"""Server-held sole validator for operator-offered public chat channels.

The author signs both the original and its channel authorization. The server
checks a second actor-to-account proof, current bans and the complete replayed
channel state before signing and atomically appending a block. This does not
create accounts, channels, or keys during a request.
"""
import copy,hashlib,json,time,unicodedata
from collections import OrderedDict
from .protocol import CHANNEL_PROFILE,KEY_VERSION,TYPE,jose
from .official_authors import inspect_author_record
from .official_chat_replay import _digest
from .official_upload_policy import permits
from .official_errors import OfficialWriteDenied
from .system_publisher import _proof,_witness,identity

BINDING_PROFILE='codi-official-account-binding/1'
ACTORS_SQL='CREATE TABLE official_chat_actors (channel TEXT NOT NULL, actor TEXT NOT NULL, subject TEXT NOT NULL, PRIMARY KEY(channel,actor))'
BAN_EPOCHS_SQL='CREATE TABLE official_chat_ban_epochs (scope TEXT NOT NULL, subject TEXT NOT NULL, epoch INTEGER NOT NULL, PRIMARY KEY(scope,subject))'
REVIEW_SQL='CREATE TABLE official_chat_actor_reviews (channel TEXT NOT NULL, actor TEXT NOT NULL, subject TEXT NOT NULL, denied_operation TEXT NOT NULL, PRIMARY KEY(channel,actor))'
NAMES_SQL='CREATE TABLE official_chat_names (channel TEXT NOT NULL, actor TEXT NOT NULL, name TEXT NOT NULL, PRIMARY KEY(channel,actor))'

class VerifiedWriterCache:
    """Bounded verified floors, reused only after checking exact database bytes.

    Callers serialize access and hold an SQLite write transaction while loading
    and committing. Cache entries are published only after a successful commit.
    """
    def __init__(self):self._entries=OrderedDict();self._trees=OrderedDict()
    @staticmethod
    def _add(digest,height,wire):
        if not isinstance(wire,str):raise ValueError('Invalid stored history')
        raw=wire.encode('utf-8');digest.update(height.to_bytes(8,'big'));digest.update(len(raw).to_bytes(8,'big'));digest.update(raw)
    def load(self,registry,channel,policy):
        cached=self._entries.get(channel);digest=hashlib.sha256();expected=1;prefix=digest.digest() if cached and cached[2]==0 else None;appended=[]
        cursor=registry._db.execute('SELECT height,wire FROM official_replayed_blocks WHERE channel=? ORDER BY height',(channel,))
        while batch:=cursor.fetchmany(64):
            for height,wire in batch:
                if height!=expected:raise ValueError('Stored history contains a gap')
                self._add(digest,height,wire)
                if cached and height==cached[2]:prefix=digest.digest()
                if cached and height>cached[2] and len(appended)<65:appended.append(wire)
                expected+=1
        same=cached and cached[0]==policy
        if same and digest.digest()==cached[1]:
            replay=copy.deepcopy(cached[3]);existing=list(cached[4])
        elif same and prefix==cached[1] and 1<=len(appended)<=64:
            replay=copy.deepcopy(cached[3]);blocks=[json.loads(wire) for wire in appended];replay.append(blocks);existing=list(cached[4])
            for block in blocks:
                for record in block['operations']:existing.append(inspect_author_record(record,channel=channel)['operation'])
        else:
            replay=registry._load_replay(channel);existing=[]
            for (wire,) in registry._db.execute('SELECT wire FROM official_replayed_blocks WHERE channel=? ORDER BY height',(channel,)):
                for record in json.loads(wire)['operations']:existing.append(inspect_author_record(record,channel=channel)['operation'])
        return replay,existing,digest
    def publish(self,channel,policy,digest,replay,existing):
        if len(existing)>32768:self._entries.pop(channel,None);self._trees.pop(channel,None);return
        self._entries[channel]=(policy,digest.digest(),replay.snapshot()['height'],copy.deepcopy(replay),tuple(existing));self._entries.move_to_end(channel)
        while len(self._entries)>8:self._entries.popitem(last=False)

    def witness(self,channel,existing,target,expected_root):
        """Reuse only a tree bound to the freshly verified history and root."""
        from .official_sparse_cache import SparseWitnessTree
        if len(existing)>=32768:return None
        ids=tuple(existing);entry=self._trees.get(channel)
        tree=entry[1] if entry and entry[0]==ids else SparseWitnessTree(ids)
        if tree.root()!=expected_root:raise ValueError('Cached operation index differs from verified replay')
        return tree.witness(target),tree.added(target)

    def publish_tree(self,channel,existing,tree,expected_root):
        """Publish a new immutable tree only after the database commits."""
        if len(existing)>32768:self._trees.pop(channel,None);return
        if tree.root()!=expected_root or tree.count!=len(existing):raise ValueError('Committed operation index differs')
        self._trees[channel]=(tuple(existing),tree);self._trees.move_to_end(channel)
        while len(self._trees)>2:self._trees.popitem(last=False)

def initialize(db):
    for name,sql in [('official_chat_actors',ACTORS_SQL),('official_chat_ban_epochs',BAN_EPOCHS_SQL),('official_chat_actor_reviews',REVIEW_SQL),('official_chat_names',NAMES_SQL)]:
        row=db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(name,)).fetchone()
        if row is None:db.execute(sql)
        elif row[0]!=sql:raise ValueError('Official actor binding schema unavailable')

def check_schema(db):
    for name,sql in [('official_chat_actors',ACTORS_SQL),('official_chat_ban_epochs',BAN_EPOCHS_SQL),('official_chat_actor_reviews',REVIEW_SQL),('official_chat_names',NAMES_SQL)]:
        if db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(name,)).fetchone()!=(sql,):raise ValueError('Official actor binding schema unavailable')

def binding(wire,identity_value,channel,genesis,now):
    if identity_value.get('kind')!='registered':raise ValueError('Registered identity required')
    header,payload,_,_=jose.inspect(wire,TYPE,16384)
    if set(header)!={'alg','typ'} or set(payload)!={'version','channel','key','purpose','body'} or payload['version']!=KEY_VERSION or payload['purpose']!='member.grant':raise ValueError('Invalid account binding proof')
    actor=payload['channel'];key=payload['key']
    if jose.digest(jose.dumps([KEY_VERSION,jose.thumbprint(key)]))!=actor:raise ValueError('Invalid actor key')
    value=jose.verify(wire,key,TYPE,16384)['body']
    if not isinstance(value,dict) or set(value)!={'profile','channel','genesisHash','subject','sid','issued','expires'} or value['profile']!=BINDING_PROFILE or value['channel']!=channel or value['genesisHash']!=genesis or value['subject']!=identity_value.get('sub') or value['sid']!=identity_value.get('sid') or type(value['issued']) is not int or type(value['expires']) is not int or not value['issued']<=now+30 or not now<value['expires']<=value['issued']+120:raise ValueError('Wrong account binding')
    return actor

class OfficialChatWriter:
    def __init__(self,registry,key,*,clock=time.time,cache=None):
        self.registry=registry;self.key=key;self.clock=clock;self.cache=cache
    def note_denial(self,channel,genesis,record,actor_binding,principal):
        now=int(self.clock());identity_value=principal.identity;actor=binding(actor_binding,identity_value,channel,genesis,now);op=inspect_author_record(record,channel=channel)
        if op['actor']!=actor or op['kind']!='chat' or identity(self.key)[0]!=channel:raise ValueError('Invalid denied original')
        db=self.registry._db;db.execute('BEGIN IMMEDIATE')
        try:
            check_schema(db);entry=db.execute('SELECT genesis_hash,enabled FROM official_channels WHERE channel=?',(channel,)).fetchone()
            if not entry or entry!=(genesis,1):raise ValueError('Denied channel is unavailable')
            previous=db.execute('SELECT subject FROM official_chat_actors WHERE channel=? AND actor=?',(channel,actor)).fetchone();review=db.execute('SELECT subject FROM official_chat_actor_reviews WHERE channel=? AND actor=?',(channel,actor)).fetchone()
            if previous and previous[0]!=identity_value['sub'] or review and review[0]!=identity_value['sub']:raise ValueError('Actor belongs to another account')
            if not previous and not review:db.execute('INSERT INTO official_chat_actor_reviews(channel,actor,subject,denied_operation) VALUES(?,?,?,?)',(channel,actor,identity_value['sub'],op['operation']))
            db.execute('COMMIT')
        except BaseException:
            if db.in_transaction:db.execute('ROLLBACK')
            raise
    def append(self,channel,genesis,record,actor_binding,principal):
        db=self.registry._db;now=int(self.clock());identity_value=principal.identity
        name=identity_value.get('name')
        if not isinstance(name,str) or not 1<=len(name)<=64 or any(unicodedata.category(c).startswith('C') for c in name):raise ValueError('Valid registered author name required')
        if not isinstance(record,dict) or set(record)!={'proposal','authorization','absence'}:raise ValueError('Invalid signed message record')
        actor=binding(actor_binding,identity_value,channel,genesis,now)
        op=inspect_author_record(record,channel=channel)
        if op['actor']!=actor or op['kind']!='chat':raise ValueError('Binding does not match chat author')
        validator,_=identity(self.key)
        db.execute('BEGIN IMMEDIATE')
        try:
            check_schema(db)
            if not permits(db,{'kind':identity_value.get('kind'),'sub':identity_value.get('sub')},channel):raise OfficialWriteDenied('Account is not allowed in this channel')
            row=db.execute('SELECT genesis_hash,policy_wire,enabled FROM official_channels WHERE channel=?',(channel,)).fetchone()
            if not row or row[0]!=genesis or not row[2] or validator!=channel:raise ValueError('Wrong official validator')
            previous=db.execute('SELECT subject FROM official_chat_actors WHERE channel=? AND actor=?',(channel,actor)).fetchone()
            if previous and previous[0]!=identity_value['sub']:raise ValueError('Actor already belongs to another account')
            review=db.execute('SELECT subject,denied_operation FROM official_chat_actor_reviews WHERE channel=? AND actor=?',(channel,actor)).fetchone() if not previous else None
            if not previous and (review or db.execute('SELECT 1 FROM official_chat_ban_epochs WHERE subject=? AND scope IN (?,?) AND epoch>0',(identity_value['sub'],'*',channel)).fetchone()):
                if review and review[0]!=identity_value['sub']:raise ValueError('Actor review belongs to another account')
                if not review:
                    db.execute('INSERT INTO official_chat_actor_reviews(channel,actor,subject,denied_operation) VALUES(?,?,?,?)',(channel,actor,identity_value['sub'],op['operation']));db.execute('COMMIT');raise OfficialWriteDenied('Review messages after an account restriction')
                if review[1]==op['operation']:raise OfficialWriteDenied('Review messages after an account restriction')
            if self.cache:replay,existing,fingerprint=self.cache.load(self.registry,channel,row)
            else:
                replay=self.registry._load_replay(channel);existing=[]
                for (wire,) in db.execute('SELECT wire FROM official_replayed_blocks WHERE channel=? ORDER BY height',(channel,)):
                    for old in json.loads(wire)['operations']:existing.append(inspect_author_record(old,channel=channel)['operation'])
            before=replay.snapshot();state=copy.deepcopy(before['state'])
            if op['operation'] in existing:
                db.execute('ROLLBACK');return {'status':'already-accepted','height':before['height'],'head':before['head']}
            cached=self.cache.witness(channel,existing,op['operation'],state['acceptedRoot']) if self.cache else None
            if cached:witness,new_tree=cached;root=state['acceptedRoot']
            else:witness,root=_witness(existing,op['operation']);new_tree=None
            if root!=state['acceptedRoot']:raise ValueError('Official accepted set changed')
            record={**record,'absence':witness}
            from .official_witness import apply_witness
            state['acceptedRoot']=apply_witness(state['acceptedRoot'],op['operation'],witness)
            if new_tree is not None and new_tree.root()!=state['acceptedRoot']:raise ValueError('Cached operation index differs from verified insertion')
            prior=next((a for a in state['authors'] if a['actor']==actor),None)
            if prior:prior.update(sequence=op['sequence'],last=op['operation'])
            else:state['authors'].append({'actor':actor,'sequence':op['sequence'],'last':op['operation']})
            state['authors'].sort(key=lambda a:a['actor']);state['count']+=1;state['height']+=1
            state['messages'].append({'id':op['operation'],'actor':actor,'text':op['data']['text'],'index':state['count']});state['messages']=state['messages'][-64:]
            records=[record];header={'profile':CHANNEL_PROFILE,'channel':channel,'genesisHash':genesis,'height':state['height'],'parent':before['head'],'count':state['count'],'operationsRoot':_digest(records),'stateHash':_digest(state),'round':0}
            def vote(phase):return _proof(self.key,'checkpoint',{'profile':CHANNEL_PROFILE,'type':'vote','channel':channel,'genesisHash':genesis,'phase':phase,'header':_digest(header)})
            block={'header':header,'operations':records,'prepare':[vote('prepare')],'commit':[vote('commit')]}
            after=replay.append([block]);wire=json.dumps(block,separators=(',',':'),ensure_ascii=False,allow_nan=False)
            db.execute('INSERT OR IGNORE INTO official_chat_actors(channel,actor,subject) VALUES (?,?,?)',(channel,actor,identity_value['sub']))
            db.execute('INSERT INTO official_chat_names(channel,actor,name) VALUES (?,?,?) ON CONFLICT(channel,actor) DO UPDATE SET name=excluded.name',(channel,actor,name))
            db.execute('INSERT INTO official_replayed_blocks(channel,height,wire) VALUES (?,?,?)',(channel,state['height'],wire));db.execute('COMMIT')
            if self.cache:
                updated=[*existing,op['operation']];self.cache._add(fingerprint,state['height'],wire);self.cache.publish(channel,row,fingerprint,replay,updated)
                if new_tree is not None:self.cache.publish_tree(channel,updated,new_tree,state['acceptedRoot'])
            return {'status':'accepted','height':after['height'],'head':after['head']}
        except BaseException:
            if db.in_transaction:db.execute('ROLLBACK')
            raise
