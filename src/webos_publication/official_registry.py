"""Operator-controlled registry for official channel policies.

This registry stores metadata only. It is not a history replica, HTTP endpoint,
validator, or permission to store arbitrary user-created channel content.
Callers must protect the operator interface and the database directory.
"""
import base64
import hashlib
import json
import sqlite3
from .protocol import verify_listing
from .official_content import validate_scratch_node, reconstruct_scratch_history
from .official_chat_replay import ExperimentalChatReplay
from .official_certificates import inspect_certificate
from .protocol import _proof

def replay_for(wire,channel,genesis):
    policy=_proof(wire,channel)
    if isinstance(policy,dict) and policy.get('stream')=='chess':
        from .official_chess_replay import OfficialChessReplay
        return OfficialChessReplay(wire,channel=channel,genesis=genesis)
    return ExperimentalChatReplay(wire,channel=channel,genesis=genesis)

def public_chat_policy(wire, channel):
    policy = _proof(wire, channel)
    return int(isinstance(policy, dict) and policy.get('stream') == 'chat'
               and policy.get('publicRead') is True
               and type(policy.get('publicWrite')) is bool)


class OfficialChannelRegistry:
    def __init__(self, path, *, scratch_bytes=64*1024*1024, check_same_thread=True):
        if type(scratch_bytes) is not int or not 16384 <= scratch_bytes <= 1024*1024*1024:
            raise ValueError('Invalid official scratch allowance')
        self._scratch_bytes = scratch_bytes
        self._db = sqlite3.connect(path, isolation_level=None, timeout=10, check_same_thread=check_same_thread)
        self._db.create_function('codi_casefold',1,lambda value: value.casefold(),deterministic=True)
        self._db.create_function('codi_public_chat_policy',2,public_chat_policy,deterministic=True)
        self._db.execute('PRAGMA foreign_keys=ON')
        self._db.execute('PRAGMA journal_mode=WAL')
        self._db.execute('''CREATE TABLE IF NOT EXISTS official_channels (
            channel TEXT PRIMARY KEY, genesis_hash TEXT NOT NULL,
            policy_wire TEXT NOT NULL, label TEXT NOT NULL,
            description TEXT NOT NULL, enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
            enrolled_at INTEGER NOT NULL
        )''')
        self._db.execute('''CREATE TABLE IF NOT EXISTS official_roles (
            role TEXT PRIMARY KEY CHECK(role='system'),
            channel TEXT NOT NULL REFERENCES official_channels(channel)
        )''')
        self._db.execute('''CREATE TABLE IF NOT EXISTS official_staged_nodes (
            channel TEXT NOT NULL REFERENCES official_channels(channel),
            cid TEXT NOT NULL, wire TEXT NOT NULL,
            PRIMARY KEY(channel,cid)
        )''')
        self._db.execute('''CREATE TABLE IF NOT EXISTS official_replayed_blocks (
            channel TEXT NOT NULL REFERENCES official_channels(channel),
            height INTEGER NOT NULL, wire TEXT NOT NULL,
            PRIMARY KEY(channel,height)
        )''')
        self._db.execute('''CREATE TABLE IF NOT EXISTS official_replayed_locators (
            channel TEXT NOT NULL, height INTEGER NOT NULL, cid TEXT NOT NULL,
            PRIMARY KEY(channel,height),
            FOREIGN KEY(channel,height) REFERENCES official_replayed_blocks(channel,height)
        )''')

    def enroll(self, signed_listing, *, now):
        """Enroll a valid public listing; only the protected operator may call this."""
        listing = verify_listing(signed_listing, now)
        channel, genesis = listing['channel'], listing['genesisHash']
        self._db.execute('BEGIN IMMEDIATE')
        try:
            old = self._db.execute('SELECT genesis_hash, policy_wire FROM official_channels WHERE channel=?', (channel,)).fetchone()
            if old and old[0] != genesis:
                raise ValueError('Official channel policy pin cannot be changed')
            self._db.execute('''INSERT INTO official_channels
                (channel,genesis_hash,policy_wire,label,description,enabled,enrolled_at)
                VALUES (?,?,?,?,?,1,?) ON CONFLICT(channel) DO UPDATE SET
                label=excluded.label, description=excluded.description, enabled=1''',
                (channel, genesis, listing['policyWire'], listing['label'], listing['description'], now))
            self._db.execute('COMMIT')
        except BaseException:
            self._db.execute('ROLLBACK')
            raise
        return self.get(channel)

    def set_enabled(self, channel, enabled):
        if type(enabled) is not bool:
            raise ValueError('Enabled must be a boolean')
        cursor = self._db.execute('UPDATE official_channels SET enabled=? WHERE channel=?', (int(enabled),channel))
        if cursor.rowcount != 1:
            raise KeyError('Unknown official channel')

    def get(self, channel):
        row = self._db.execute('SELECT channel,genesis_hash,policy_wire,label,description,enabled,enrolled_at FROM official_channels WHERE channel=?', (channel,)).fetchone()
        if row is None:
            return None
        return dict(zip(('channel','genesisHash','policyWire','label','description','enabled','enrolledAt'), (*row[:5],bool(row[5]),row[6])))

    def public_directory(self,*,after='',limit=16,query=''):
        """Bounded operator-enrolled public chat descriptors, not peer listings."""
        if after:
            from .official_content import _id
            _id(after)
        if type(limit) is not int or not 1<=limit<=32 or not isinstance(query,str) or len(query)>64 or len(query.encode('utf-8'))>256:raise ValueError('Invalid directory page')
        query=query.strip().casefold()
        self._db.execute('BEGIN')
        try:
            rows=self._db.execute("SELECT channel,genesis_hash,policy_wire,label,description FROM official_channels WHERE enabled=1 AND channel>? AND instr(codi_casefold(label || ' ' || description),?)>0 AND codi_public_chat_policy(policy_wire,channel)=1 ORDER BY channel LIMIT ?", (after,query,limit+1)).fetchall()
            chosen=rows[:limit];items=[]
            for channel,genesis,wire,label,description in chosen:
                policy=_proof(wire,channel)
                if not isinstance(policy,dict):raise ValueError('Invalid official policy')
                if policy.get('stream')!='chat' or policy.get('publicRead') is not True or type(policy.get('publicWrite')) is not bool:continue
                ExperimentalChatReplay(wire,channel=channel,genesis=genesis)
                items.append({'category':'official','channel':channel,'genesisHash':genesis,'policyWire':wire,'label':label,'description':description})
            result={'items':items,'next':chosen[-1][0] if len(rows)>limit else None};self._db.execute('COMMIT');return result
        except BaseException:
            self._db.execute('ROLLBACK');raise

    def public_channel(self,channel):
        from .official_content import _id
        _id(channel);entry=self.get(channel)
        if not entry or not entry['enabled']:return None
        policy=_proof(entry['policyWire'],channel)
        if not isinstance(policy,dict):raise ValueError('Invalid official policy')
        if policy.get('stream') not in ('chat','chess') or policy.get('publicRead') is not True or type(policy.get('publicWrite')) is not bool:return None
        replay_for(entry['policyWire'],channel,entry['genesisHash'])
        return {'category':'official','channel':channel,'genesisHash':entry['genesisHash'],'policyWire':entry['policyWire'],'label':entry['label'],'description':entry['description']}

    def set_system_channel(self,channel):
        """Only an operator may designate a public, owner-write-only channel."""
        entry=self.public_channel(channel)
        if not entry or entry['label']!='SYSTEM':raise ValueError('SYSTEM must be an enabled official channel named SYSTEM')
        policy=_proof(entry['policyWire'],channel)
        if policy.get('publicWrite') is not False or policy.get('validators')!=[channel]:raise ValueError('SYSTEM requires one owner validator and no public writes')
        self._db.execute("INSERT INTO official_roles(role,channel) VALUES('system',?) ON CONFLICT(role) DO UPDATE SET channel=excluded.channel",(channel,))

    def public_system_channel(self):
        row=self._db.execute("SELECT channel FROM official_roles WHERE role='system'").fetchone()
        if not row:return None
        entry=self.public_channel(row[0])
        if not entry or entry['label']!='SYSTEM':return None
        policy=_proof(entry['policyWire'],row[0])
        if policy.get('publicWrite') is not False or policy.get('validators')!=[row[0]]:raise ValueError('Invalid SYSTEM channel policy')
        return entry

    def stage_node(self, channel, cid, wire):
        """Retain hash-matching scratch bytes, never an accepted history claim.

        Full DAG, signature and accepted-state verification must happen before
        any staged data can be published or treated as a server replica.
        """
        if not isinstance(wire, str) or not isinstance(cid, str):
            raise ValueError('Invalid staged node')
        raw = wire.encode('utf-8')
        if not 1 <= len(raw) <= 16384:
            raise ValueError('Staged node exceeds size limit')
        digest = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b'=').decode('ascii')
        if cid != digest:
            raise ValueError('Staged node hash mismatch')
        self._db.execute('BEGIN IMMEDIATE')
        try:
            row = self._db.execute('SELECT enabled, genesis_hash FROM official_channels WHERE channel=?', (channel,)).fetchone()
            if row is None or not row[0]:
                raise ValueError('Channel is not enabled for official storage')
            validate_scratch_node(wire, channel, row[1])
            existing = self._db.execute('SELECT wire FROM official_staged_nodes WHERE channel=? AND cid=?', (channel,cid)).fetchone()
            if existing is not None and existing[0] != wire:
                raise ValueError('Staged node conflicts with existing data')
            if existing is None:
                used = self._db.execute('SELECT COALESCE(SUM(length(CAST(wire AS BLOB))),0) FROM official_staged_nodes WHERE channel=?', (channel,)).fetchone()[0]
                if used + len(raw) > self._scratch_bytes:
                    raise ValueError('Official scratch allowance exceeded')
                self._db.execute('INSERT INTO official_staged_nodes(channel,cid,wire) VALUES (?,?,?)', (channel,cid,wire))
            self._db.execute('COMMIT')
        except BaseException:
            self._db.execute('ROLLBACK')
            raise

    def staged_node(self, channel, cid):
        """Internal scratch retrieval; this is not a public serving endpoint."""
        row = self._db.execute('''SELECT n.wire FROM official_staged_nodes n
            JOIN official_channels c ON c.channel=n.channel
            WHERE n.channel=? AND n.cid=? AND c.enabled=1''', (channel,cid)).fetchone()
        return row[0] if row else None

    def replayed_head(self, channel):
        """Reverify stored experimental blocks from genesis; never trust stored state."""
        self._db.execute('BEGIN')
        try:
            replay = self._load_replay(channel)
            result = replay.snapshot()
            self._db.execute('COMMIT')
            return result
        except BaseException:
            self._db.execute('ROLLBACK')
            raise

    def _load_replay(self, channel):
        row = self._db.execute('SELECT genesis_hash,policy_wire,enabled FROM official_channels WHERE channel=?', (channel,)).fetchone()
        if row is None or not row[2]:raise ValueError('Channel is not enabled for official storage')
        replay = replay_for(row[1],channel,row[0])
        cursor = self._db.execute('SELECT height,wire FROM official_replayed_blocks WHERE channel=? ORDER BY height', (channel,))
        expected=1
        while batch:=cursor.fetchmany(64):
            if any(height!=expected+i for i,(height,_) in enumerate(batch)):raise ValueError('Stored history contains a gap')
            replay.append([json.loads(wire) for _,wire in batch]);expected+=len(batch)
        return replay

    def append_replayed(self, channel, *, expected_head, blocks):
        """Experimental verified append; requires protected operator/service caller.

        The implementation is not yet audited and is not a public fallback.
        Persist only after a full replay and atomic compare-and-append.
        """
        if not isinstance(blocks,list) or not 1<=len(blocks)<=64:raise ValueError('Invalid bounded batch')
        wires=[json.dumps(b,separators=(',',':'),ensure_ascii=False,allow_nan=False) for b in blocks]
        if any(len(w.encode())>2*1048576 for w in wires) or sum(len(w.encode()) for w in wires)>8*1048576:raise ValueError('Batch exceeds byte allowance')
        self._db.execute('BEGIN IMMEDIATE')
        try:
            replay=self._load_replay(channel);before=replay.snapshot()
            if before['head']!=expected_head:raise ValueError('Stale official history head')
            result=replay.append(blocks)
            for index,wire in enumerate(wires,1):
                self._db.execute('INSERT INTO official_replayed_blocks(channel,height,wire) VALUES (?,?,?)', (channel,before['height']+index,wire))
            self._db.execute('COMMIT')
            return result
        except BaseException:
            self._db.execute('ROLLBACK')
            raise

    def append_staged_history(self, channel, *, expected_head, history, height, head, uploader=None):
        """Experimental compare-and-replay from staged DAG; not public serving."""
        self._db.execute('BEGIN IMMEDIATE')
        try:
            if uploader is not None:
                from .official_upload_policy import permits
                if not permits(self._db,uploader,channel):raise ValueError('Official upload denied at commit')
            replay=self._load_replay(channel);before=replay.snapshot()
            if before['head']!=expected_head:raise ValueError('Stale official history head')
            if type(height) is not int or not 1<=height-before['height']<=64:raise ValueError('Invalid offered history gap')
            current=self._db.execute('SELECT cid FROM official_replayed_locators WHERE channel=? AND height=?', (channel,before['height'])).fetchone() if before['height'] else None
            if before['height'] and current is None:raise ValueError('Prior history locator unavailable')
            genesis=self._db.execute('SELECT genesis_hash FROM official_channels WHERE channel=?', (channel,)).fetchone()[0]
            segment=reconstruct_scratch_history(lambda cid:self.staged_node(channel,cid),channel=channel,genesis=genesis,history=history,height=height,head=head,max_blocks=height-before['height'])
            if segment['previousHeight']!=before['height'] or segment['previousHead']!=before['head'] or segment['previousHistory']!=(current[0] if current else None):raise ValueError('Staged history does not extend retained floor')
            for row in segment['blocks']:
                result=replay.append([row['block']])
                if result['head']!=row['head']:raise ValueError('Staged locator differs from replayed head')
                wire=json.dumps(row['block'],separators=(',',':'),ensure_ascii=False,allow_nan=False)
                self._db.execute('INSERT INTO official_replayed_blocks(channel,height,wire) VALUES (?,?,?)',(channel,result['height'],wire))
                self._db.execute('INSERT INTO official_replayed_locators(channel,height,cid) VALUES (?,?,?)',(channel,result['height'],row['history']))
            self._db.execute('COMMIT')
            return result
        except BaseException:
            self._db.execute('ROLLBACK')
            raise

    def read_replayed_segment(self, channel, *, after_height, after_head, limit=32, byte_limit=8*1048576):
        """Read bounded experimental block wires after a matching floor.

        Callers must provide a protected authorization boundary. This method
        is local only and is not a public or production-ready fallback.
        """
        if type(after_height) is not int or after_height<0 or type(limit) is not int or not 1<=limit<=64 or type(byte_limit) is not int or not 1<=byte_limit<=8*1048576:raise ValueError('Invalid read bounds')
        self._db.execute('BEGIN')
        try:
            replay=self._load_replay(channel);tip=replay.snapshot()
            result=self._page_from_verified_tip(channel,after_height=after_height,after_head=after_head,limit=limit,byte_limit=byte_limit,tip=tip)
            self._db.execute('COMMIT');return result
        except BaseException:
            self._db.execute('ROLLBACK')
            raise

    def _page_from_verified_tip(self,channel,*,after_height,after_head,limit,byte_limit,tip):
            """Caller owns a read transaction and a freshly replay-verified tip."""
            if after_height>tip['height']:raise ValueError('Floor is ahead of stored history')
            row=self._db.execute('SELECT genesis_hash,policy_wire,enabled FROM official_channels WHERE channel=?',(channel,)).fetchone()
            if not row or not row[2]:raise ValueError('Channel is not enabled for official storage')
            genesis,wire=row[:2]
            if genesis!=tip.get('genesisHash',genesis):raise ValueError('Official policy pin changed')
            if after_height==0:floor=replay_for(wire,channel,genesis).snapshot()['head']
            else:
                row=self._db.execute('SELECT wire FROM official_replayed_blocks WHERE channel=? AND height=?',(channel,after_height)).fetchone()
                if row is None:raise ValueError('Stored floor is missing')
                floor=inspect_certificate(json.loads(row[0]),channel=channel,genesis=genesis,validators=_proof(wire,channel)['validators'])['head']
            if floor!=after_head:raise ValueError('Requested floor differs from stored history')
            rows=self._db.execute('SELECT height,wire FROM official_replayed_blocks WHERE channel=? AND height>? ORDER BY height LIMIT ?', (channel,after_height,limit)).fetchall()
            result=[];used=0
            for height,block_wire in rows:
                size=len(block_wire.encode('utf-8'))
                if used+size>byte_limit:
                    if not result:raise ValueError('One block exceeds read allowance')
                    break
                result.append({'height':height,'wire':block_wire});used+=size
            return {'status':'experimental-replayed-segment','head':tip['head'],'height':tip['height'],'afterHeight':after_height,'blocks':result,'complete':after_height+len(result)==tip['height']}

    def close(self):
        self._db.close()
