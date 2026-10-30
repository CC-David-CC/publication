"""Isolated experimental verifier for recovery-enabled public-chat genesis.

This does not enroll channels, authenticate directory pins, replay blocks,
implement transition, or enable the live official service.
"""
from .protocol import jose, identifier, _proof, CHANNEL_PROFILE

PROFILE='codi-official-genesis-recovery/1'

def verify_recovery_genesis(wire,*,channel,genesis_hash):
    identifier(channel);identifier(genesis_hash)
    if not isinstance(wire,str) or len(wire)>16384:raise ValueError('Invalid genesis wire')
    body=_proof(wire,channel)
    if not isinstance(body,dict) or set(body)!={'profile','type','channel','stream','validators','publicWrite','players','publicRead','recovery'}:raise ValueError('Invalid recovery genesis fields')
    if body['profile']!=CHANNEL_PROFILE or body['type']!='policy' or body['channel']!=channel or body['stream']!='chat' or body['publicRead'] is not True or body['publicWrite'] is not True or body['players'] is not None:raise ValueError('Unsupported recovery genesis policy')
    validators=body['validators']
    if not isinstance(validators,list) or not 1<=len(validators)<=31 or any(not isinstance(x,str) for x in validators) or validators!=sorted(set(validators)):raise ValueError('Invalid validators')
    for actor in validators:identifier(actor)
    recovery=body['recovery']
    if not isinstance(recovery,dict) or set(recovery)!={'profile','key'} or recovery['profile']!=PROFILE or not isinstance(recovery['key'],dict) or set(recovery['key'])!={'kty','crv','x','y'}:raise ValueError('Invalid recovery key')
    jose.load_public(recovery['key'])
    parts=wire.split('.');identity=jose.digest(jose.dumps([CHANNEL_PROFILE,'signed-content',parts[0],parts[1]]))
    if identity!=genesis_hash:raise ValueError('Genesis pin mismatch')
    return {'channel':channel,'genesisHash':identity,'head':jose.digest(jose.dumps([CHANNEL_PROFILE,'genesis',identity])),'validators':validators,'recoveryKey':recovery['key']}
