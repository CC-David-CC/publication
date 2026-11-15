#!/usr/bin/env python3
"""Ten accounts concurrently use the same cached official authority."""
import concurrent.futures,importlib.util,sys,types,uuid
from pathlib import Path
R=Path(__file__).resolve().parents[1];sys.path.insert(0,str(R));spec=importlib.util.spec_from_file_location('fixture',R/'scripts/official-chat-writer-check.py');fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from steward.official_chat_authority import OfficialChatAuthority
case=fixture.Checks();case.setUp()
try:
 keys=Path(case.tmp.name)/'keys';keys.mkdir(mode=0o700);path=keys/(case.channel+'.pem');path.write_bytes(case.key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));path.chmod(0o600);authority=OfficialChatAuthority(case.path,keys);jobs=[]
 for i in range(10):
  case.actorKey=ec.generate_private_key(ec.SECP256R1());principal=types.SimpleNamespace(identity={'kind':'registered','name':'tester'+str(i),'sub':'user:'+str(uuid.uuid4()),'sid':str(uuid.uuid4())});jobs.append((case.record('parallel '+str(i)),case.bind(principal),principal))
 with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
  results=list(pool.map(lambda j:authority(case.channel,case.genesis,*j),jobs))
 assert all(x['status']=='accepted' for x in results);tip=case.registry.replayed_head(case.channel);assert tip['height']==10 and {x['text'] for x in tip['state']['messages']}=={'parallel '+str(i) for i in range(10)}
 print('PASS ten concurrent distinct registered authors, signed replay, shared writer cache and complete history')
finally:case.tearDown()
