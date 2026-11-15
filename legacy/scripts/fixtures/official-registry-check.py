#!/usr/bin/env python3
import base64, hashlib, json, tempfile, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from cryptography.hazmat.primitives.asymmetric import ec
from steward.protocol import jose, TYPE, KEY_VERSION, CHANNEL_PROFILE, PROFILE
from steward.official_registry import OfficialChannelRegistry

now=1800000000
key=ec.generate_private_key(ec.SECP256R1()); public=jose.public_jwk(key)
channel=jose.digest(jose.dumps([KEY_VERSION,jose.thumbprint(public)]))
def sign(body): return jose.sign({'version':KEY_VERSION,'channel':channel,'key':public,'purpose':'checkpoint','body':body},key,TYPE)
def listing(public_write=True, label='Official test', issued=now):
    policy=sign({'profile':CHANNEL_PROFILE,'type':'policy','channel':channel,'stream':'chat','validators':[channel],'publicWrite':public_write,'players':None,'publicRead':True})
    parts=policy.split('.'); genesis=jose.digest(jose.dumps([CHANNEL_PROFILE,'signed-content',parts[0],parts[1]]))
    return sign({'profile':PROFILE,'category':'user','channel':channel,'genesisHash':genesis,'policyWire':policy,'label':label,'description':'','issued':issued,'expires':issued+180})
def rejected(fn):
    try: fn()
    except (ValueError,KeyError): return True
    return False
with tempfile.TemporaryDirectory() as tmp:
    db=Path(tmp)/'official.sqlite'; a=OfficialChannelRegistry(db,scratch_bytes=16384)
    assert a.get(channel) is None
    assert a.enroll(listing(),now=now)['enabled']
    first=a.get(channel); assert first['enrolledAt']==now
    wire=json.dumps({'profile':'codi-channel-content/1','kind':'chunk','data':'dGVzdA'},separators=(',',':'));cid=base64.urlsafe_b64encode(hashlib.sha256(wire.encode()).digest()).rstrip(b'=').decode()
    assert rejected(lambda:a.stage_node('user-channel',cid,wire))
    assert rejected(lambda:a.stage_node(channel,cid,wire+'tamper'))
    a.stage_node(channel,cid,wire);a.stage_node(channel,cid,wire);assert a.staged_node(channel,cid)==wire
    def node(data):
        wire=json.dumps({'profile':'codi-channel-content/1','kind':'chunk','data':base64.urlsafe_b64encode(data).rstrip(b'=').decode()},separators=(',',':'))
        return wire,base64.urlsafe_b64encode(hashlib.sha256(wire.encode()).digest()).rstrip(b'=').decode()
    large,large_id=node(b'x'*8192);a.stage_node(channel,large_id,large)
    larger,larger_id=node(b'y'*8192);assert rejected(lambda:a.stage_node(channel,larger_id,larger));assert a.staged_node(channel,larger_id) is None
    wrong=json.dumps({'profile':'codi-channel-content/1','kind':'head','channel':channel,'genesisHash':'A'*43,'height':1,'head':cid,'parent':None,'block':cid},separators=(',',':'))
    wrong_id=base64.urlsafe_b64encode(hashlib.sha256(wrong.encode()).digest()).rstrip(b'=').decode();assert rejected(lambda:a.stage_node(channel,wrong_id,wrong))
    malformed='{}';bad_id=base64.urlsafe_b64encode(hashlib.sha256(malformed.encode()).digest()).rstrip(b'=').decode();assert rejected(lambda:a.stage_node(channel,bad_id,malformed))
    assert rejected(lambda:a.enroll(listing(False),now=now))
    assert a.get(channel)==first
    assert rejected(lambda:a.enroll(listing(issued=now-300),now=now))
    assert rejected(lambda:a.enroll(listing()[:-1]+'!',now=now))
    a.set_enabled(channel,False); assert not a.get(channel)['enabled']; assert a.staged_node(channel,cid) is None; assert rejected(lambda:a.stage_node(channel,cid,wire)); a.close()
    b=OfficialChannelRegistry(db); assert not b.get(channel)['enabled']
    b.enroll(listing(label='Renamed'),now=now); assert b.get(channel)['label']=='Renamed'; assert b.staged_node(channel,cid)==wire
    def another_listing():
        k=ec.generate_private_key(ec.SECP256R1());p=jose.public_jwk(k);c=jose.digest(jose.dumps([KEY_VERSION,jose.thumbprint(p)]))
        def signed(body):return jose.sign({'version':KEY_VERSION,'channel':c,'key':p,'purpose':'checkpoint','body':body},k,TYPE)
        policy=signed({'profile':CHANNEL_PROFILE,'type':'policy','channel':c,'stream':'chat','validators':[c],'publicWrite':True,'players':None,'publicRead':True});parts=policy.split('.');g=jose.digest(jose.dumps([CHANNEL_PROFILE,'signed-content',parts[0],parts[1]]))
        return signed({'profile':PROFILE,'category':'user','channel':c,'genesisHash':g,'policyWire':policy,'label':'Another','description':'','issued':now,'expires':now+180})
    second=b.enroll(another_listing(),now=now)['channel'];first_page=b.public_directory(limit=1);assert len(first_page['items'])==1 and first_page['next'];second_page=b.public_directory(after=first_page['next'],limit=1);assert {first_page['items'][0]['channel'],second_page['items'][0]['channel']}=={channel,second} and second_page['next'] is None
    assert [item['channel'] for item in b.public_directory(query=' aNOTHER ')['items']]==[second]
    assert not b.public_directory(query='missing')['items']
    b.set_enabled(second,False);assert [item['channel'] for item in b.public_directory(limit=2)['items']]==[channel]
    assert b.get(channel)['genesisHash']==first['genesisHash'] and b.get(channel)['enrolledAt']==now
    assert rejected(lambda:b.set_enabled(channel,1)); assert rejected(lambda:b.set_enabled('missing',True));b.close()
print(json.dumps({'status':'PASS','checks':['signed policy enrollment','pin conflict rolls back','invalid and expired signatures refused','disable survives restart','same policy can be re-enabled','unknown and non-boolean updates refused','scratch rejects unapproved channels and mismatched hashes','scratch survives restart and is inaccessible while disabled','per-channel scratch allowance is enforced transactionally','malformed and wrong-channel nodes rejected']}))
