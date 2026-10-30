"""Verify signed author-record bindings; this is not permission or state replay."""
import re
from .protocol import TYPE, KEY_VERSION, CHANNEL_PROFILE, identifier, jose

def _operation_proof(wire):
    header,payload,_,_=jose.inspect(wire,TYPE,65536)
    if set(header)!={'alg','typ'} or set(payload)!={'version','channel','key','purpose','body'} or payload['version']!=KEY_VERSION or payload['purpose']!='operation':raise ValueError('Invalid author proof')
    actor=payload['channel'];identifier(actor);key=payload['key']
    if not isinstance(key,dict) or set(key)!={'kty','crv','x','y'} or jose.digest(jose.dumps([KEY_VERSION,jose.thumbprint(key)]))!=actor:raise ValueError('Wrong author key')
    verified=jose.verify(wire,key,TYPE,65536)
    if not isinstance(verified['body'],dict):raise ValueError('Invalid proof body')
    return actor,verified['body']

def inspect_author_record(record, *, channel):
    """Check signed proposal/authorization binding; caller must replay policy."""
    identifier(channel)
    if not isinstance(record,dict) or set(record)!={'proposal','authorization','absence'}:raise ValueError('Invalid author record')
    actor,proposal=_operation_proof(record['proposal'])
    if set(proposal)!={'profile','type','target','nonce','kind','data'} or proposal['profile']!=CHANNEL_PROFILE or proposal['type']!='proposal' or proposal['target']!=channel or not isinstance(proposal['nonce'],str) or not re.fullmatch(r'[A-Za-z0-9_-]{16,128}',proposal['nonce']) or proposal['kind'] not in ('chat','permission','move','moderation','account-control') or not isinstance(proposal['data'],dict):raise ValueError('Invalid proposal')
    parts=record['proposal'].split('.');operation=jose.digest(jose.dumps([CHANNEL_PROFILE,'signed-content',parts[0],parts[1]]))
    signer,authorization=_operation_proof(record['authorization'])
    common={'profile','type','target','proposal','sequence','previous'};fields=set(authorization);version='permissionRevision' if fields==common|{'permissionRevision'} else 'authorEpoch' if fields==common|{'authorEpoch'} else None
    if signer!=actor or version is None or authorization['profile']!=CHANNEL_PROFILE or authorization['type']!='authorize' or authorization['target']!=channel or authorization['proposal']!=operation:raise ValueError('Invalid authorization binding')
    if type(authorization['sequence']) is not int or not 1<=authorization['sequence']<=9007199254740991:raise ValueError('Invalid authorization counter')
    if version=='permissionRevision' and (type(authorization[version]) is not int or not 1<=authorization[version]<=9007199254740991):raise ValueError('Invalid authorization counter')
    if version=='authorEpoch' and authorization[version] is not None:identifier(authorization[version])
    if authorization['previous'] is not None:identifier(authorization['previous'])
    return {'status':'signed-binding-only','actor':actor,'operation':operation,'kind':proposal['kind'],'data':proposal['data'],'sequence':authorization['sequence'],'previous':authorization['previous'],version:authorization[version]}
