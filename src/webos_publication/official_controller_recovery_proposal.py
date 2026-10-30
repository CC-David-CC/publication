"""Experimental proposal verification only; this grants no channel authority.

The caller must obtain trusted context from a separately authenticated durable
policy and state. There is no transaction, consensus or validator rotation here.
"""
from .protocol import jose, identifier

PROPOSAL='codi-official-controller-recovery-proposal/1'
ACCEPT='codi-official-controller-recovery-possession/1'
MAX_COUNTER=9007199254740991

def _fields(value,keys):
    if not isinstance(value,dict) or set(value)!=set(keys):raise ValueError('Invalid recovery object fields')

def _key(value):
    _fields(value,('kty','crv','x','y'));jose.load_public(value);return value

def _counter(value,minimum=0):
    if type(value) is not int or not minimum<=value<MAX_COUNTER:raise ValueError('Invalid recovery generation')

def _header(token,typ):
    h,p,_,_=jose.inspect(token,typ,8192);_fields(h,('alg','typ'));return p

def verify_official_recovery_proposal(wire,acceptance,trusted):
    _fields(trusted,('channel','genesisHash','head','generation','controller','recoveryKey','oldCommitteeHash','newCommitteeHash'))
    for name in ('channel','genesisHash','head','controller','oldCommitteeHash','newCommitteeHash'):identifier(trusted[name])
    _counter(trusted['generation']);_key(trusted['recoveryKey'])
    _header(wire,PROPOSAL);p=jose.verify(wire,trusted['recoveryKey'],PROPOSAL,8192)
    _fields(p,('version','channel','genesisHash','head','generation','controller','replacement','replacementKey','oldCommitteeHash','newCommitteeHash'))
    if p['version']!=PROPOSAL:raise ValueError('Wrong recovery proposal version')
    for name in ('channel','genesisHash','head','controller','replacement','oldCommitteeHash','newCommitteeHash'):identifier(p[name])
    _counter(p['generation'],1);_key(p['replacementKey'])
    if p['replacement']==p['controller']:raise ValueError('Controller must change')
    if any(p[name]!=trusted[name] for name in ('channel','genesisHash','head','controller','oldCommitteeHash','newCommitteeHash')) or p['generation']!=trusted['generation']+1:raise ValueError('Recovery proposal differs from trusted state')
    if jose.digest(jose.dumps(['codi-device-channel-key/1',jose.thumbprint(p['replacementKey'])]))!=p['replacement']:raise ValueError('Replacement key differs from identity')
    _header(acceptance,ACCEPT);a=jose.verify(acceptance,p['replacementKey'],ACCEPT,8192);_fields(a,('version','proposalHash'))
    if a['version']!=ACCEPT or a['proposalHash']!=jose.digest(wire):raise ValueError('Acceptance does not bind this proposal')
    return {name:p[name] for name in ('channel','genesisHash','head','generation','controller','replacement','oldCommitteeHash','newCommitteeHash')}
