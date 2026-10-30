#!/usr/bin/env python3
"""Certificate-only quorum tests. These do not validate channel transitions."""
import copy,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from cryptography.hazmat.primitives.asymmetric import ec
from steward.protocol import jose,TYPE,KEY_VERSION,CHANNEL_PROFILE
from steward.official_certificates import inspect_certificate,_canonical

def key():
    k=ec.generate_private_key(ec.SECP256R1());j=jose.public_jwk(k);return k,j,jose.digest(jose.dumps([KEY_VERSION,jose.thumbprint(j)]))
keys=[key() for _ in range(5)];validators=sorted(k[2] for k in keys[:4]);channel=validators[0];genesis=jose.digest('genesis');parent=jose.digest('parent')
h={'profile':CHANNEL_PROFILE,'channel':channel,'genesisHash':genesis,'height':1,'parent':parent,'count':1,'operationsRoot':jose.digest('operations'),'stateHash':jose.digest('state'),'round':0}
def vote(k,phase,header=h):
    private,public,actor=k;body={'profile':CHANNEL_PROFILE,'type':'vote','channel':channel,'genesisHash':genesis,'phase':phase,'header':jose.digest(_canonical(header))}
    return jose.sign({'version':KEY_VERSION,'channel':actor,'key':public,'purpose':'checkpoint','body':body},private,TYPE)
block={'header':h,'operations':[],'prepare':[vote(k,'prepare') for k in keys[:3]],'commit':[vote(k,'commit') for k in keys[:3]]}
def inspect(v):return inspect_certificate(v,channel=channel,genesis=genesis,validators=validators)
def reject(v):
    try:inspect(v)
    except (ValueError,TypeError):return True
    return False
assert inspect(block)['status']=='certificate-only'
x=copy.deepcopy(block);x['commit']=x['commit'][:2];assert reject(x)
x=copy.deepcopy(block);x['prepare'][1]=x['prepare'][0];assert reject(x)
x=copy.deepcopy(block);x['commit'][0]=vote(keys[4],'commit');assert reject(x)
x=copy.deepcopy(block);x['prepare'][0]=vote(keys[0],'commit');assert reject(x)
x=copy.deepcopy(block);x['header']['round']=1;assert reject(x)
x=copy.deepcopy(block);x['header']['parent']=genesis;assert reject(x)
x=copy.deepcopy(block);x['commit'][0]=x['commit'][0][:-1]+'!';assert reject(x)
x=copy.deepcopy(block);parts=x['commit'][0].split('.');signature=bytearray(jose.unb64(parts[2]));signature[0]^=1;parts[2]=jose.b64(signature);x['commit'][0]='.'.join(parts);assert reject(x)
x=copy.deepcopy(block);x['commit'].append(vote(keys[3],'commit'));assert inspect(x)['height']==1
print(json.dumps({'status':'PASS','checks':['four validators require three votes','duplicate signer rejected','unlisted signer rejected','wrong phase rejected','changed header rejected','forged signature rejected','extra valid vote accepted'],'scope':'certificate only; operations intentionally not verified'}))
