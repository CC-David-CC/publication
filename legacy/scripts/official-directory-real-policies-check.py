#!/usr/bin/env python3
"""Real signed policies: many games must not hide official chat pages."""
import sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from cryptography.hazmat.primitives.asymmetric import ec
from steward.protocol import jose,TYPE,KEY_VERSION,CHANNEL_PROFILE
from steward.official_registry import OfficialChannelRegistry
keys=[]
for _ in range(88):
 k=ec.generate_private_key(ec.SECP256R1());pub=jose.public_jwk(k);channel=jose.digest(jose.dumps([KEY_VERSION,jose.thumbprint(pub)]));keys.append((channel,k,pub))
keys.sort()
with tempfile.TemporaryDirectory() as folder:
 r=OfficialChannelRegistry(str(Path(folder)/'state.sqlite'))
 for i,(channel,key,pub) in enumerate(keys):
  stream='chess' if i<85 else 'chat';body={'profile':CHANNEL_PROFILE,'type':'policy','channel':channel,'stream':stream,'validators':[channel],'publicWrite':stream=='chat','players':None if stream=='chat' else {'white':channel,'black':channel},'publicRead':True}
  wire=jose.sign({'version':KEY_VERSION,'channel':channel,'key':pub,'purpose':'checkpoint','body':body},key,TYPE);parts=wire.split('.');genesis=jose.digest(jose.dumps([CHANNEL_PROFILE,'signed-content',parts[0],parts[1]]));label='game' if i<85 else ['General chess chat','SYSTEM','Third'][i-85]
  r._db.execute('INSERT INTO official_channels VALUES (?,?,?,?,?,?,?)',(channel,genesis,wire,label,'',1,0))
 page=r.public_directory(limit=2);assert [x['label'] for x in page['items']]==['General chess chat','SYSTEM'] and page['next'];page2=r.public_directory(limit=2,after=page['next']);assert [x['label'] for x in page2['items']]==['Third'] and page2['next'] is None;r.close()
print('PASS 85 real signed chess policies do not hide signed chat listings')
