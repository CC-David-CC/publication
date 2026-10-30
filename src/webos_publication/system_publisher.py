"""Owner-only SYSTEM announcements using the ordinary signed chat protocol.

The caller owns private-key custody and serialization. All blocks are verified
again by the official registry before the atomic append; no browser trusts this
helper's computed state without replaying the signed history itself.
"""
import base64,copy,json,secrets,time
from .protocol import jose,CHANNEL_PROFILE,KEY_VERSION,TYPE
from .official_chat_replay import _digest
from .official_witness import ZEROS,_hash,_node,apply_witness
from .official_authors import inspect_author_record


def identity(key):
    public=jose.public_jwk(key);channel=jose.digest(jose.dumps([KEY_VERSION,jose.thumbprint(public)]))
    return channel,public

def _proof(key,purpose,body):
    channel,public=identity(key)
    return jose.sign({'version':KEY_VERSION,'channel':channel,'key':public,'purpose':purpose,'body':body},key,TYPE)

def create_policy(key):
    channel,_=identity(key)
    body={'profile':CHANNEL_PROFILE,'type':'policy','channel':channel,'stream':'chat','validators':[channel],'publicWrite':False,'players':None,'publicRead':True}
    wire=_proof(key,'checkpoint',body);parts=wire.split('.')
    return {'channel':channel,'genesisHash':jose.digest(jose.dumps([CHANNEL_PROFILE,'signed-content',parts[0],parts[1]])),'policyWire':wire}

def listing(key,config,now=None):
    now=int(time.time()) if now is None else now
    if type(now) is not int or now<0 or config['channel']!=identity(key)[0]:raise ValueError('Wrong SYSTEM owner or time')
    body={'profile':'codi-channel-listing/1','category':'user','channel':config['channel'],'genesisHash':config['genesisHash'],'policyWire':config['policyWire'],'label':'SYSTEM','description':'Announcements from the system','issued':now,'expires':now+180}
    return _proof(key,'checkpoint',body)

def _witness(existing,target):
    target_int=int.from_bytes(jose.unb64(target),'big');nodes={int.from_bytes(jose.unb64(item),'big'):_hash(['codi-operation-set/1','leaf',item]) for item in existing}
    if len(nodes)!=len(existing) or target_int in nodes:raise ValueError('Repeated SYSTEM operation')
    siblings=[]
    for level in range(256):
        other=nodes.get((target_int>>level)^1,ZEROS[level])
        if other!=ZEROS[level]:siblings.append({'level':level,'hash':other})
        next_nodes={}
        for parent in {n>>1 for n in nodes}:
            next_nodes[parent]=_node(nodes.get(parent*2,ZEROS[level]),nodes.get(parent*2+1,ZEROS[level]))
        nodes=next_nodes
    return {'siblings':siblings},nodes.get(0,ZEROS[256])

def post(registry,key,text):
    if not isinstance(text,str) or not 1<=len(text.encode('utf-8'))<=4096:raise ValueError('SYSTEM text must contain 1–4096 UTF-8 bytes')
    entry=registry.public_system_channel();channel,_=identity(key)
    if not entry or entry['channel']!=channel:raise ValueError('Key is not the designated SYSTEM owner')
    before=registry.replayed_head(channel);state=copy.deepcopy(before['state']);genesis=entry['genesisHash']
    existing=[]
    for (wire,) in registry._db.execute('SELECT wire FROM official_replayed_blocks WHERE channel=? ORDER BY height',(channel,)):
        for record in json.loads(wire)['operations']:existing.append(inspect_author_record(record,channel=channel)['operation'])
    body={'profile':CHANNEL_PROFILE,'type':'proposal','target':channel,'nonce':secrets.token_urlsafe(18),'kind':'chat','data':{'text':text}}
    proposal=_proof(key,'operation',body);parts=proposal.split('.');op=jose.digest(jose.dumps([CHANNEL_PROFILE,'signed-content',parts[0],parts[1]]))
    witness,root=_witness(existing,op)
    if root!=state['acceptedRoot']:raise ValueError('Stored SYSTEM operation set differs from verified head')
    author=next((a for a in state['authors'] if a['actor']==channel),None);sequence=(author['sequence'] if author else 0)+1;previous=author['last'] if author else None
    authorization=_proof(key,'operation',{'profile':CHANNEL_PROFILE,'type':'authorize','target':channel,'proposal':op,'sequence':sequence,'previous':previous,'permissionRevision':state['permissionRevision']})
    records=[{'proposal':proposal,'authorization':authorization,'absence':witness}]
    state['acceptedRoot']=apply_witness(state['acceptedRoot'],op,witness)
    if author:author.update(sequence=sequence,last=op)
    else:state['authors'].append({'actor':channel,'sequence':sequence,'last':op});state['authors'].sort(key=lambda row:row['actor'])
    state['count']+=1;state['height']+=1;state['messages'].append({'id':op,'actor':channel,'text':text,'index':state['count']});state['messages']=state['messages'][-64:]
    header={'profile':CHANNEL_PROFILE,'channel':channel,'genesisHash':genesis,'height':state['height'],'parent':before['head'],'count':state['count'],'operationsRoot':_digest(records),'stateHash':_digest(state),'round':0}
    def vote(phase):return _proof(key,'checkpoint',{'profile':CHANNEL_PROFILE,'type':'vote','channel':channel,'genesisHash':genesis,'phase':phase,'header':_digest(header)})
    block={'header':header,'operations':records,'prepare':[vote('prepare')],'commit':[vote('commit')]}
    return registry.append_replayed(channel,expected_head=before['head'],blocks=[block])
