"""Experimental loopback-only reader for replayed public official chat.

This is a development fixture, not a production service or an ingest API.
The browser must independently verify every block it receives.
"""
import copy
import hashlib
import json
import sys
import threading
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from .official_content import _id
from .official_registry import OfficialChannelRegistry
from .protocol import _proof


class OfficialReadServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, database, *, allowed_origin=None):
        self.database = database
        self.allowed_origin = allowed_origin
        self.slots = threading.BoundedSemaphore(4)
        self.connections=threading.BoundedSemaphore(16)
        self.head_lock=threading.RLock()
        self.head_registry=OfficialChannelRegistry(database,check_same_thread=False)
        self.head_cache=OrderedDict()
        try:super().__init__(("127.0.0.1", 0), OfficialReadHandler)
        except BaseException:self.head_registry.close();raise

    def process_request(self,request,client_address):
        if not self.connections.acquire(blocking=False):
            try:request.sendall(b'HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
            except OSError:pass
            self.shutdown_request(request);return
        try:super().process_request(request,client_address)
        except BaseException:self.connections.release();raise

    def get_request(self):
        request,address=super().get_request();request.settimeout(10);return request,address

    def handle_error(self,request,client_address):
        if isinstance(sys.exc_info()[1],(ConnectionError,TimeoutError)):return
        super().handle_error(request,client_address)

    def process_request_thread(self,request,client_address):
        try:super().process_request_thread(request,client_address)
        finally:self.connections.release()

    def verified_head(self,channel):
        # One persistent connection makes data_version comparable across calls.
        # Any other-connection commit invalidates all cached in-process replays.
        with self.head_lock:
            db=self.head_registry._db
            for _ in range(3):
                before=db.execute('PRAGMA data_version').fetchone()[0]
                cached=self.head_cache.get(channel)
                if cached and cached[0]==before:
                    entry,tip,fingerprint,replay_obj=cached[1:]
                else:
                    entry=self.head_registry.get(channel)
                    if not entry or not entry['enabled']:return None
                    policy=_proof(entry['policyWire'],channel)
                    if not isinstance(policy,dict):raise ValueError('Invalid official policy')
                    if policy.get('stream') not in ('chat','chess') or policy.get('publicRead') is not True:return None
                    # SQLite's data_version changes for *any* channel or table,
                    # including unrelated chess moves. Hash this channel's exact
                    # stored bytes before reusing a previously verified replay.
                    # Any altered, removed, inserted, or reordered block changes
                    # the pin and forces a complete cryptographic replay.
                    digest=hashlib.sha256();expected=1;appended=[];prefix=digest.digest() if cached and cached[2]['height']==0 else None
                    cursor=db.execute('SELECT height,wire FROM official_replayed_blocks WHERE channel=? ORDER BY height',(channel,))
                    while batch:=cursor.fetchmany(64):
                        for height,wire in batch:
                            if height!=expected or not isinstance(wire,str):raise ValueError('Stored history contains a gap')
                            raw=wire.encode('utf-8');digest.update(height.to_bytes(8,'big'));digest.update(len(raw).to_bytes(8,'big'));digest.update(raw)
                            if cached and height==cached[2]['height']:prefix=digest.digest()
                            if cached and height>cached[2]['height'] and len(appended)<65:appended.append(wire)
                            expected+=1
                    fingerprint=digest.digest()
                    same_policy=cached and all(cached[1][key]==entry[key] for key in ('genesisHash','policyWire','enabled'))
                    if same_policy and cached[3]==fingerprint:
                        tip,replay_obj=cached[2],cached[4]
                    elif same_policy and prefix==cached[3] and 1<=len(appended)<=64:
                        # The old verified prefix is byte-identical. Validate
                        # every appended block on a copy before publishing the
                        # new in-memory floor; invalid suffixes change nothing.
                        replay_obj=copy.deepcopy(cached[4]);replay=replay_obj.append([json.loads(wire) for wire in appended]);tip={'channel':channel,'genesisHash':entry['genesisHash'],'height':replay['height'],'head':replay['head']}
                    else:
                        db.execute('BEGIN')
                        try:replay_obj=self.head_registry._load_replay(channel);replay=replay_obj.snapshot();db.execute('COMMIT')
                        except BaseException:db.execute('ROLLBACK');raise
                        tip={'channel':channel,'genesisHash':entry['genesisHash'],'height':replay['height'],'head':replay['head']}
                after=db.execute('PRAGMA data_version').fetchone()[0]
                if before!=after:
                    continue
                self.head_cache[channel]=(after,entry,tip,fingerprint,replay_obj);self.head_cache.move_to_end(channel)
                while len(self.head_cache)>128:self.head_cache.popitem(last=False)
                return dict(tip)
            raise ValueError('Official history changed during verification')

    def verified_page(self,channel,*,after_height,after_head,limit):
        with self.head_lock:
            db=self.head_registry._db
            for _ in range(3):
                before=db.execute('PRAGMA data_version').fetchone()[0]
                tip=self.verified_head(channel)
                if tip is None:return None
                db.execute('BEGIN')
                try:
                    page=self.head_registry._page_from_verified_tip(channel,after_height=after_height,after_head=after_head,limit=limit,byte_limit=8*1048576,tip=tip)
                    db.execute('COMMIT')
                except BaseException:
                    db.execute('ROLLBACK');raise
                after=db.execute('PRAGMA data_version').fetchone()[0]
                if before==after:return page
            raise ValueError('Official history changed during page read')

    def directory_page(self,*,after,limit,query=''):
        with self.head_lock:return self.head_registry.public_directory(after=after,limit=limit,query=query)

    def directory_channel(self,channel):
        with self.head_lock:return self.head_registry.public_channel(channel)

    def directory_system_channel(self):
        with self.head_lock:return self.head_registry.public_system_channel()

    def author_names(self,channel,actors):
        with self.head_lock:
            entry=self.head_registry.public_channel(channel)
            if not entry:return None
            policy=_proof(entry['policyWire'],channel)
            if policy.get('stream')!='chat' or policy.get('publicRead') is not True:return None
            db=self.head_registry._db
            if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='official_chat_names'").fetchone():return {'version':'codi-official-author-names/1','authors':{}}
            rows=db.execute('SELECT actor,name FROM official_chat_names WHERE channel=? AND actor IN ('+','.join('?' for _ in actors)+')',(channel,*actors)).fetchall()
            return {'version':'codi-official-author-names/1','authors':dict(rows)}

    def featured_game(self,previous_of=None):
        from .official_chess_custody import verify_invitation
        with self.head_lock:
            db=self.head_registry._db
            if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='official_featured_game'").fetchone():return None
            if previous_of is None:
                row=db.execute('SELECT invitation FROM official_featured_game WHERE version=1').fetchone();expected=None
            else:
                _id(previous_of)
                if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='official_featured_game_history'").fetchone():return None
                link=db.execute('SELECT predecessor FROM official_featured_game_history WHERE channel=?',(previous_of,)).fetchone()
                if not link or link[0] is None:return None
                expected=link[0];_id(expected)
                if expected==previous_of:raise ValueError('Featured game history contains a cycle')
                row=db.execute('SELECT invitation FROM official_featured_game_history WHERE channel=?',(expected,)).fetchone()
            if not row:return None
            if not isinstance(row[0],str) or len(row[0].encode())>80000:raise ValueError('Invalid featured match')
            invitation=verify_invitation(json.loads(row[0]))
            if expected is not None and invitation['game']['config']['channel']!=expected:raise ValueError('Featured history link differs from its signed match')
            for name in ('game','chat'):
                config=invitation[name]['config'];item=self.head_registry.public_channel(config['channel'])
                if not item or item['genesisHash']!=config['genesisHash'] or item['policyWire']!=config['policyWire']:raise ValueError('Featured channel is unavailable')
            return invitation

    def server_close(self):
        super().server_close()
        with self.head_lock:self.head_registry.close();self.head_cache.clear()


class OfficialReadHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, body):
        data = json.dumps(body, separators=(',', ':'), ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        origin = self.headers.get('Origin')
        if origin and origin == self.server.allowed_origin:
            self.send_header('Access-Control-Allow-Origin', origin)
            self.send_header('Vary', 'Origin')
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        origin = self.headers.get('Origin')
        if origin and origin != self.server.allowed_origin:
            return self.reply(403, {'error': 'origin refused'})
        try:
            url = urlsplit(self.path)
            if url.path not in ('/official-history','/official-head','/official-directory','/official-channel') or len(url.query) > (2048 if url.path=='/official-channel' else 512):
                raise ValueError('invalid request')
            query = parse_qs(url.query, keep_blank_values=True, strict_parsing=True)
            if url.path=='/official-directory':
                if set(query) not in ({'after','limit'},{'after','limit','query'}) or any(len(v)!=1 for v in query.values()):raise ValueError('invalid query')
                search=query.get('query',[''])[0]
                if len(search)>64 or len(search.encode('utf-8'))>256:raise ValueError('invalid search')
                after=query['after'][0];limit_text=query['limit'][0]
                if after:_id(after)
                if not limit_text.isascii() or not limit_text.isdecimal() or len(limit_text)>2 or str(int(limit_text))!=limit_text or not 1<=int(limit_text)<=32:raise ValueError('invalid bounds')
                limit=int(limit_text);channel=None
            elif url.path in ('/official-head','/official-channel'):
                if set(query)!={'channel'} and not (url.path=='/official-channel' and set(query) in ({'channel','authors'},{'channel','before'})):raise ValueError('invalid query')
                if any(len(v)!=1 for v in query.values()):raise ValueError('invalid query')
                channel=query['channel'][0]
                if 'before' in query and channel!='featured-previous':raise ValueError('invalid query')
                if channel=='featured-previous' and 'before' not in query:raise ValueError('invalid query')
                if url.path!='/official-channel' or channel not in ('system','featured-game','featured-previous'):_id(channel)
                if 'before' in query:_id(query['before'][0])
                if 'authors' in query:
                    _id(channel);actors=query['authors'][0].split(',')
                    if not 1<=len(actors)<=32 or len(set(actors))!=len(actors):raise ValueError('invalid authors')
                    for actor in actors:_id(actor)
            else:
                channel=None
            if url.path=='/official-history' and (set(query) != {'channel', 'afterHeight', 'afterHead', 'limit'} or any(len(v) != 1 for v in query.values())):
                raise ValueError('invalid query')
            if url.path=='/official-history':
                channel, after_head = query['channel'][0], query['afterHead'][0]
                _id(channel); _id(after_head)
                height_text, limit_text = query['afterHeight'][0], query['limit'][0]
                if not height_text.isascii() or not height_text.isdecimal() or len(height_text) > 15 or not limit_text.isascii() or not limit_text.isdecimal() or len(limit_text) > 2:raise ValueError('invalid bounds')
                height, limit = int(height_text), int(limit_text)
                if str(height) != height_text or str(limit) != limit_text or not 1 <= limit <= 64:raise ValueError('invalid bounds')
        except ValueError:
            return self.reply(400, {'error': 'invalid request'})
        if not self.server.slots.acquire(timeout=2):
            return self.reply(503, {'error': 'reader busy'})
        try:
            if url.path=='/official-directory':return self.reply(200,self.server.directory_page(after=after,limit=limit,query=search))
            if url.path=='/official-channel':
                if 'authors' in query:
                    item=self.server.author_names(channel,actors);return self.reply(200,item) if item is not None else self.reply(404,{'error':'unavailable'})
                if channel=='featured-game':
                    item=self.server.featured_game();return self.reply(200,{'version':'codi-featured-game/1','invitation':item}) if item else self.reply(404,{'error':'unavailable'})
                if channel=='featured-previous':
                    item=self.server.featured_game(previous_of=query['before'][0]);return self.reply(200,{'version':'codi-featured-game/1','invitation':item}) if item else self.reply(404,{'error':'unavailable'})
                item=self.server.directory_system_channel() if channel=='system' else self.server.directory_channel(channel)
                return self.reply(200,{'items':[item],'next':None}) if item else self.reply(404,{'error':'unavailable'})
            if url.path=='/official-head':
                tip=self.server.verified_head(channel)
                return self.reply(200,tip) if tip else self.reply(404,{'error':'unavailable'})
            page=self.server.verified_page(channel,after_height=height,after_head=after_head,limit=limit)
            return self.reply(200,page) if page else self.reply(404,{'error':'unavailable'})
        except ValueError:
            return self.reply(409, {'error': 'history unavailable or floor mismatch'})
        finally:
            self.server.slots.release()
