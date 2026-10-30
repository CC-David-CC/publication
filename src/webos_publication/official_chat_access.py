"""Atomically restrict an account and advance its signed author epochs."""
import copy,json,secrets
from urllib.parse import urlsplit
from .official_authors import inspect_author_record
from .official_chat_replay import _digest
from .official_chat_writer import check_schema
from .official_upload_policy import check_schema as check_policy,subject as validate_subject
from .official_witness import apply_witness
from .protocol import CHANNEL_PROFILE,_proof,jose
from .system_publisher import _proof as sign_proof,_witness,identity

def _set_actor(registry,key,actor,account,allowed):
    db=registry._db;channel=identity(key)[0];row=db.execute('SELECT genesis_hash,policy_wire,enabled FROM official_channels WHERE channel=?',(channel,)).fetchone()
    if not row or not row[2]:raise ValueError('Official channel is not enabled')
    genesis,wire=row[:2];policy=_proof(wire,channel)
    if policy.get('stream')!='chat' or policy.get('validators')!=[channel] or policy.get('authorAuthorization')!='actor-epoch/2':raise ValueError('Epoch-aware sole-validator chat required')
    replay=registry._load_replay(channel);before=replay.snapshot();state=copy.deepcopy(before['state']);bound=next((v for v in state.get('accountBindings',[]) if v['actor']==actor),None);old=next((v for v in state['permissions'] if v['actor']==actor),None)
    if bound and bound['account']!=account:raise ValueError('Actor belongs to another account')
    if bound and old and old['read'] is True and old['write'] is allowed:return
    data={'subject':actor,'read':True,'write':allowed,'expectedHead':before['head'],'account':account};proposal=sign_proof(key,'operation',{'profile':CHANNEL_PROFILE,'type':'proposal','target':channel,'nonce':secrets.token_urlsafe(18),'kind':'permission','data':data});parts=proposal.split('.');op=jose.digest(jose.dumps([CHANNEL_PROFILE,'signed-content',parts[0],parts[1]]));prior=next((a for a in state['authors'] if a['actor']==channel),None);sequence=(prior['sequence'] if prior else 0)+1
    authorization=sign_proof(key,'operation',{'profile':CHANNEL_PROFILE,'type':'authorize','target':channel,'proposal':op,'sequence':sequence,'previous':prior['last'] if prior else None,'permissionRevision':state['permissionRevision']});existing=[]
    for (raw,) in db.execute('SELECT wire FROM official_replayed_blocks WHERE channel=? ORDER BY height',(channel,)):
        for record in json.loads(raw)['operations']:existing.append(inspect_author_record(record,channel=channel)['operation'])
    witness,root=_witness(existing,op)
    if root!=state['acceptedRoot']:raise ValueError('Stored chat history changed')
    record={'proposal':proposal,'authorization':authorization,'absence':witness};state['acceptedRoot']=apply_witness(state['acceptedRoot'],op,witness);state['count']+=1;state['height']+=1;state['permissionRevision']+=1
    if prior:prior.update(sequence=sequence,last=op)
    else:state['authors'].append({'actor':channel,'sequence':sequence,'last':op});state['authors'].sort(key=lambda value:value['actor'])
    bindings=state.setdefault('accountBindings',[])
    if not bound:bindings.append({'actor':actor,'account':account});bindings.sort(key=lambda value:value['actor'])
    if old:old.update(read=True,write=allowed)
    else:state['permissions'].append({'actor':actor,'read':True,'write':allowed});state['permissions'].sort(key=lambda value:value['actor'])
    epochs=state['authorEpochs'];epoch=next((v for v in epochs if v['actor']==actor),None)
    if epoch:epoch['epoch']=op
    else:epochs.append({'actor':actor,'epoch':op});epochs.sort(key=lambda value:value['actor'])
    records=[record];header={'profile':CHANNEL_PROFILE,'channel':channel,'genesisHash':genesis,'height':state['height'],'parent':before['head'],'count':state['count'],'operationsRoot':_digest(records),'stateHash':_digest(state),'round':0}
    def vote(phase):return sign_proof(key,'checkpoint',{'profile':CHANNEL_PROFILE,'type':'vote','channel':channel,'genesisHash':genesis,'phase':phase,'header':_digest(header)})
    block={'header':header,'operations':records,'prepare':[vote('prepare')],'commit':[vote('commit')]};replay.append([block]);db.execute('INSERT INTO official_replayed_blocks(channel,height,wire) VALUES(?,?,?)',(channel,state['height'],json.dumps(block,separators=(',',':'),ensure_ascii=False,allow_nan=False)))

def set_banned(registry,key,*,issuer,subject,banned):
    validate_subject(subject)
    if not isinstance(issuer,str) or not issuer or len(issuer)>256 or type(banned) is not bool:raise ValueError('Explicit account and restriction required')
    url=urlsplit(issuer)
    if not url.netloc or url.username or url.password or url.path or url.query or url.fragment or not (url.scheme=='https' or url.scheme=='http' and url.hostname=='127.0.0.1') or url.geturl()!=issuer:raise ValueError('Exact issuer origin required')
    channel=identity(key)[0];db=registry._db;db.execute('BEGIN IMMEDIATE')
    try:
        check_schema(db);check_policy(db)
        if not db.execute('SELECT 1 FROM official_channels WHERE channel=? AND enabled=1',(channel,)).fetchone():raise ValueError('Official channel unavailable')
        current=bool(db.execute('SELECT 1 FROM official_upload_bans WHERE scope=? AND subject=?',(channel,subject)).fetchone());actors=[row[0] for row in db.execute('SELECT actor FROM official_chat_actors WHERE channel=? AND subject=? ORDER BY actor',(channel,subject))]
        if not banned and not current:db.execute('COMMIT');return {'status':'unbanned','channel':channel,'knownDevices':len(actors)}
        if banned and not current:
            db.execute('INSERT INTO official_upload_bans(scope,subject) VALUES(?,?)',(channel,subject));db.execute('INSERT INTO official_chat_ban_epochs(scope,subject,epoch) VALUES(?,?,1) ON CONFLICT(scope,subject) DO UPDATE SET epoch=epoch+1',(channel,subject))
        account={'issuer':issuer,'subject':subject}
        for actor in actors:_set_actor(registry,key,actor,account,not banned)
        if not banned and current:db.execute('DELETE FROM official_upload_bans WHERE scope=? AND subject=?',(channel,subject))
        db.execute('COMMIT');return {'status':'banned' if banned else 'unbanned','channel':channel,'knownDevices':len(actors)}
    except BaseException:
        db.execute('ROLLBACK');raise
