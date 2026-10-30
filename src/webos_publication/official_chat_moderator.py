"""Publish operator-signed spam markers without deleting original messages."""
import copy,json,secrets
from .official_authors import inspect_author_record
from .official_chat_replay import _digest
from .official_content import _id
from .official_witness import apply_witness
from .protocol import CHANNEL_PROFILE,_proof,jose
from .system_publisher import _proof as sign_proof,_witness,identity

def mark_spam(registry,key,*,message=None,author=None):
    if (message is None)==(author is None):raise ValueError('Choose exactly one message or author')
    subject=message if message is not None else author;_id(subject);channel=identity(key)[0];db=registry._db;db.execute('BEGIN IMMEDIATE')
    try:
        row=db.execute('SELECT genesis_hash,policy_wire,enabled FROM official_channels WHERE channel=?',(channel,)).fetchone()
        if not row or not row[2]:raise ValueError('Official channel is not enabled')
        genesis,wire=row[:2];policy=_proof(wire,channel)
        if policy.get('stream')!='chat' or policy.get('validators')!=[channel]:raise ValueError('Sole operator chat validator required')
        replay=registry._load_replay(channel);before=replay.snapshot();state=copy.deepcopy(before['state']);field='message' if message is not None else 'author';collection='moderation' if message is not None else 'moderationAuthors';items=state.setdefault(collection,[])
        if len(items)>=16384 or any(row[field]==subject for row in items):raise ValueError('Spam marker already exists or capacity reached')
        data={field:subject,'action':'spam'};proposal=sign_proof(key,'operation',{'profile':CHANNEL_PROFILE,'type':'proposal','target':channel,'nonce':secrets.token_urlsafe(18),'kind':'moderation','data':data});parts=proposal.split('.');op=jose.digest(jose.dumps([CHANNEL_PROFILE,'signed-content',parts[0],parts[1]]));prior=next((a for a in state['authors'] if a['actor']==channel),None);sequence=(prior['sequence'] if prior else 0)+1
        authorization=sign_proof(key,'operation',{'profile':CHANNEL_PROFILE,'type':'authorize','target':channel,'proposal':op,'sequence':sequence,'previous':prior['last'] if prior else None,'permissionRevision':state['permissionRevision']});existing=[]
        for (old,) in db.execute('SELECT wire FROM official_replayed_blocks WHERE channel=? ORDER BY height',(channel,)):
            for record in json.loads(old)['operations']:existing.append(inspect_author_record(record,channel=channel)['operation'])
        witness,root=_witness(existing,op)
        if root!=state['acceptedRoot']:raise ValueError('Stored chat history changed')
        record={'proposal':proposal,'authorization':authorization,'absence':witness};state['acceptedRoot']=apply_witness(state['acceptedRoot'],op,witness);state['count']+=1;state['height']+=1;items.append({field:subject,'by':channel,'index':state['count']})
        if prior:prior.update(sequence=sequence,last=op)
        else:state['authors'].append({'actor':channel,'sequence':sequence,'last':op});state['authors'].sort(key=lambda a:a['actor'])
        records=[record];header={'profile':CHANNEL_PROFILE,'channel':channel,'genesisHash':genesis,'height':state['height'],'parent':before['head'],'count':state['count'],'operationsRoot':_digest(records),'stateHash':_digest(state),'round':0}
        def vote(phase):return sign_proof(key,'checkpoint',{'profile':CHANNEL_PROFILE,'type':'vote','channel':channel,'genesisHash':genesis,'phase':phase,'header':_digest(header)})
        block={'header':header,'operations':records,'prepare':[vote('prepare')],'commit':[vote('commit')]};after=replay.append([block]);db.execute('INSERT INTO official_replayed_blocks(channel,height,wire) VALUES(?,?,?)',(channel,state['height'],json.dumps(block,separators=(',',':'),ensure_ascii=False,allow_nan=False)));db.execute('COMMIT');return after
    except BaseException:
        db.execute('ROLLBACK');raise
