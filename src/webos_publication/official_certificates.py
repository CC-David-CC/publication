"""Bounded certificate-only checks; not full channel replay or acceptance."""
import json
from .protocol import CHANNEL_PROFILE, TYPE, KEY_VERSION, _proof, identifier, jose

def _canonical(value):
    # Used only for fixed-schema ASCII header fields and safe integers.
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)

def inspect_certificate(block, *, channel, genesis, validators):
    """Check certificate signatures only; validators must come from a verified pinned policy.

    The returned value does not certify operation content or authorization.
    Never use this result alone to promote or serve a history head.
    """
    identifier(channel);identifier(genesis)
    if not isinstance(validators,(list,tuple)) or not 1<=len(validators)<=31 or list(validators)!=sorted(set(validators)):raise ValueError('Invalid validator set')
    for v in validators:identifier(v)
    if not isinstance(block,dict) or set(block)!={'header','operations','prepare','commit'}:raise ValueError('Invalid block')
    h=block['header']; fields={'profile','channel','genesisHash','height','parent','count','operationsRoot','stateHash','round'}
    if not isinstance(h,dict) or set(h)!=fields or h['profile']!=CHANNEL_PROFILE or h['channel']!=channel or h['genesisHash']!=genesis:raise ValueError('Invalid header scope')
    for k in ['parent','operationsRoot','stateHash']:identifier(h[k])
    for k in ['height','count','round']:
        if type(h[k]) is not int or not 0<=h[k]<=9007199254740991:raise ValueError('Invalid header number')
    if h['height']<1 or h['count']<h['height']:raise ValueError('Invalid header height')
    header_hash=jose.digest(_canonical(h)); quorum=len(validators)-(len(validators)-1)//3
    for phase in ['prepare','commit']:
        votes=block[phase]
        if not isinstance(votes,list) or not quorum<=len(votes)<=len(validators):raise ValueError('Missing quorum')
        signers=set()
        for wire in votes:
            if not isinstance(wire,str) or len(wire)>2048:raise ValueError('Invalid vote size')
            _,payload,_,_=jose.inspect(wire,TYPE,2048);signer=payload.get('channel');identifier(signer)
            if signer not in validators or signer in signers:raise ValueError('Invalid vote signer')
            body=_proof(wire,signer);expected={'profile':CHANNEL_PROFILE,'type':'vote','channel':channel,'genesisHash':genesis,'phase':phase,'header':header_hash}
            if body!=expected:raise ValueError('Vote differs from header')
            signers.add(signer)
    without_round={k:v for k,v in h.items() if k!='round'}
    return {'status':'certificate-only','head':jose.digest(_canonical(without_round)),'height':h['height'],'parent':h['parent']}
