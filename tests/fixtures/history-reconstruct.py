#!/usr/bin/env python3
import base64,hashlib,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'src'))
from webos_publication.official_content import reconstruct_scratch_history

def ident(v):return base64.urlsafe_b64encode(hashlib.sha256(v).digest()).rstrip(b'=').decode()
def j(v):return json.dumps(v,separators=(',',':'))
channel,genesis,parent,head=map(lambda x:ident(x.encode()),['channel','genesis','initial','head'])
nodes={}
def save(value):
 wire=j(value);cid=ident(wire.encode());nodes[cid]=wire;return cid
block={'header':{'channel':channel,'genesisHash':genesis,'height':1,'parent':parent},'operations':[],'prepare':[],'commit':[]}
raw=j(block).encode();chunk=save({'profile':'codi-channel-content/1','kind':'chunk','data':base64.urlsafe_b64encode(raw).rstrip(b'=').decode()});blob=save({'profile':'codi-channel-content/1','kind':'blob','bytes':len(raw),'tree':{'cid':chunk,'bytes':len(raw),'height':0}});tip=save({'profile':'codi-channel-content/1','kind':'head','channel':channel,'genesisHash':genesis,'height':1,'head':head,'parent':None,'block':blob})
def run(d=nodes,**opts):return reconstruct_scratch_history(d.get,channel=channel,genesis=genesis,history=tip,height=1,head=head,**opts)
def reject(fn):
 try:fn()
 except ValueError:return True
 return False
x=run();assert x['status']=='untrusted-reconstructed-segment' and x['blocks'][0]['block']==block and x['previousHead']==parent and x['previousHeight']==0
assert reject(lambda:run({k:v for k,v in nodes.items() if k!=chunk}))
assert reject(lambda:run({**nodes,chunk:nodes[chunk]+' '}))
assert reject(lambda:run(max_nodes=2))
assert reject(lambda:run(max_bytes=10))
assert reject(lambda:reconstruct_scratch_history(nodes.get,channel=channel,genesis=genesis,history=tip,height=2,head=head))
assert reject(lambda:reconstruct_scratch_history(nodes.get,channel=channel,genesis=genesis,history=tip,height=1,head=parent))
# Replace the blob with a two-piece tree, retaining the same block bytes.
left,right=raw[:len(raw)//2],raw[len(raw)//2:]
def part(data):return save({'profile':'codi-channel-content/1','kind':'chunk','data':base64.urlsafe_b64encode(data).rstrip(b'=').decode()})
a,b=part(left),part(right);parts=save({'profile':'codi-channel-content/1','kind':'parts','links':[{'cid':a,'bytes':len(left),'height':0},{'cid':b,'bytes':len(right),'height':0}]});multi=save({'profile':'codi-channel-content/1','kind':'blob','bytes':len(raw),'tree':{'cid':parts,'bytes':len(raw),'height':1}});multi_tip=save({'profile':'codi-channel-content/1','kind':'head','channel':channel,'genesisHash':genesis,'height':1,'head':head,'parent':None,'block':multi})
def multi_run(store=nodes):return reconstruct_scratch_history(store.get,channel=channel,genesis=genesis,history=multi_tip,height=1,head=head)
assert multi_run()['blocks'][0]['block']==block
assert reject(lambda:multi_run({k:v for k,v in nodes.items() if k!=b}))
wrong_parts=save({'profile':'codi-channel-content/1','kind':'parts','links':[{'cid':a,'bytes':len(left)+1,'height':0},{'cid':b,'bytes':len(right),'height':0}]});wrong_blob=save({'profile':'codi-channel-content/1','kind':'blob','bytes':len(raw),'tree':{'cid':wrong_parts,'bytes':len(raw),'height':1}});wrong_tip=save({'profile':'codi-channel-content/1','kind':'head','channel':channel,'genesisHash':genesis,'height':1,'head':head,'parent':None,'block':wrong_blob})
assert reject(lambda:reconstruct_scratch_history(nodes.get,channel=channel,genesis=genesis,history=wrong_tip,height=1,head=head))
print(json.dumps({'status':'PASS','checks':['reconstruct untrusted block','missing content rejected','tampering rejected','node and byte bounds enforced','height and head mismatch rejected','multipart reconstructs and missing or mismatched pieces rejected'],'note':'Synthetic unsigned blocks; no acceptance verification asserted'}))
