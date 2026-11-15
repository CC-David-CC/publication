#!/usr/bin/env python3
"""Verify registered, signed, atomic official chat admission and idempotency."""
import json,secrets,sys,tempfile,threading,time,types,unittest,urllib.error,urllib.request,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from cryptography.hazmat.primitives.asymmetric import ec
from steward.official_registry import OfficialChannelRegistry
from steward.official_read_http import OfficialReadServer
from steward.official_upload_policy import initialize as init_policy,OfficialUploadPolicy
from steward.official_chat_writer import OfficialChatWriter,initialize,BINDING_PROFILE
from steward.official_chat_moderator import mark_spam
from steward.official_chat_access import set_banned
from steward.official_errors import OfficialWriteDenied
from steward.system_publisher import _proof,identity,listing
from steward.protocol import CHANNEL_PROFILE,jose
class Checks(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();path=Path(self.tmp.name)/'official.sqlite';self.path=path;self.registry=OfficialChannelRegistry(path);init_policy(path);initialize(self.registry._db);self.registry._db.commit()
  self.key=ec.generate_private_key(ec.SECP256R1());self.actorKey=ec.generate_private_key(ec.SECP256R1());self.channel,_=identity(self.key);self.actor,_=identity(self.actorKey);self.now=int(time.time())
  body={'profile':CHANNEL_PROFILE,'type':'policy','channel':self.channel,'stream':'chat','validators':[self.channel],'publicWrite':True,'players':None,'publicRead':True,'authorAuthorization':'actor-epoch/2'}
  wire=_proof(self.key,'checkpoint',body);parts=wire.split('.');self.genesis=jose.digest(jose.dumps([CHANNEL_PROFILE,'signed-content',parts[0],parts[1]]));config={'channel':self.channel,'genesisHash':self.genesis,'policyWire':wire};self.registry.enroll(listing(self.key,config,now=self.now),now=self.now)
  self.subject='user:'+str(uuid.uuid4());self.principal=types.SimpleNamespace(identity={'kind':'registered','name':'alice','sub':self.subject,'sid':str(uuid.uuid4())});self.writer=OfficialChatWriter(self.registry,self.key,clock=lambda:self.now)
 def tearDown(self):self.registry.close();self.tmp.cleanup()
 def bind(self,principal=None):
  i=(principal or self.principal).identity;return _proof(self.actorKey,'member.grant',{'profile':BINDING_PROFILE,'channel':self.channel,'genesisHash':self.genesis,'subject':i['sub'],'sid':i['sid'],'issued':self.now,'expires':self.now+60})
 def record(self,text='hello',sequence=1,previous=None,epoch=None):
  proposal=_proof(self.actorKey,'operation',{'profile':CHANNEL_PROFILE,'type':'proposal','target':self.channel,'nonce':secrets.token_urlsafe(18),'kind':'chat','data':{'text':text,'authorEpoch':epoch}});parts=proposal.split('.');op=jose.digest(jose.dumps([CHANNEL_PROFILE,'signed-content',parts[0],parts[1]]));auth=_proof(self.actorKey,'operation',{'profile':CHANNEL_PROFILE,'type':'authorize','target':self.channel,'proposal':op,'sequence':sequence,'previous':previous,'authorEpoch':epoch});return {'proposal':proposal,'authorization':auth,'absence':{'siblings':[]}}
 def test_signed_message_and_duplicate(self):
  rec=self.record();a=self.writer.append(self.channel,self.genesis,rec,self.bind(),self.principal);self.assertEqual(a['status'],'accepted');self.assertEqual(self.registry.replayed_head(self.channel)['state']['messages'][0]['text'],'hello');self.assertEqual(self.registry._db.execute('SELECT name FROM official_chat_names WHERE channel=? AND actor=?',(self.channel,self.actor)).fetchone(),('alice',));b=self.writer.append(self.channel,self.genesis,rec,self.bind(),self.principal);self.assertEqual(b['status'],'already-accepted');self.assertEqual(b['height'],1)
 def test_names_are_channel_scoped_and_only_after_accepted_message(self):
  server=OfficialReadServer(self.path);thread=threading.Thread(target=server.serve_forever);thread.start();base='http://127.0.0.1:'+str(server.server_port)+'/official-channel?channel='+self.channel+'&authors='
  try:
   with urllib.request.urlopen(base+self.actor) as response:self.assertEqual(json.load(response)['authors'],{})
   self.writer.append(self.channel,self.genesis,self.record(),self.bind(),self.principal)
   with urllib.request.urlopen(base+self.actor) as response:self.assertEqual(json.load(response)['authors'],{self.actor:'alice'})
   with self.assertRaises(urllib.error.HTTPError) as duplicate:urllib.request.urlopen(base+self.actor+','+self.actor)
   self.assertEqual(duplicate.exception.code,400)
   with self.assertRaises(urllib.error.HTTPError) as invalid:urllib.request.urlopen(base+'invalid')
   self.assertEqual(invalid.exception.code,400)
   actors=[jose.digest(str(n)) for n in range(33)]
   with urllib.request.urlopen(base+','.join([self.actor,*actors[:31]])) as response:self.assertEqual(json.load(response)['authors'],{self.actor:'alice'})
   with self.assertRaises(urllib.error.HTTPError) as over:urllib.request.urlopen(base+','.join(actors))
   self.assertEqual(over.exception.code,400)
   other=types.SimpleNamespace(identity={'kind':'registered','name':'mallory','sub':'user:'+str(uuid.uuid4()),'sid':str(uuid.uuid4())})
   with self.assertRaises(ValueError):self.writer.append(self.channel,self.genesis,self.record(),self.bind(other),other)
   with urllib.request.urlopen(base+self.actor) as response:self.assertEqual(json.load(response)['authors'],{self.actor:'alice'})
  finally:server.shutdown();server.server_close();thread.join()
 def test_verified_cache_survives_unrelated_writes_but_rejects_changed_history(self):
  self.writer.append(self.channel,self.genesis,self.record(),self.bind(),self.principal);server=OfficialReadServer(self.path);original=server.head_registry._load_replay;calls=[]
  def counted(channel):calls.append(channel);return original(channel)
  server.head_registry._load_replay=counted
  try:
   first=server.verified_head(self.channel);self.assertEqual(len(calls),1)
   self.registry._db.execute('CREATE TABLE unrelated_test (value INTEGER)');self.registry._db.execute('INSERT INTO unrelated_test VALUES (1)')
   self.assertEqual(server.verified_head(self.channel),first);self.assertEqual(len(calls),1,'unrelated writes must not trigger a full replay')
   previous=self.registry.replayed_head(self.channel)['state']['authors'][0]['last'];self.writer.append(self.channel,self.genesis,self.record('second',sequence=2,previous=previous),self.bind(),self.principal)
   second=server.verified_head(self.channel);self.assertEqual(second['height'],2);self.assertEqual(len(calls),1,'a valid appended block should be verified incrementally')
   self.registry._db.execute('INSERT INTO official_replayed_blocks(channel,height,wire) VALUES(?,?,?)',(self.channel,3,'{}'))
   with self.assertRaises((ValueError,KeyError)):server.verified_head(self.channel)
   self.registry._db.execute('DELETE FROM official_replayed_blocks WHERE channel=? AND height=3',(self.channel,));self.assertEqual(server.verified_head(self.channel),second)
   wire=self.registry._db.execute('SELECT wire FROM official_replayed_blocks WHERE channel=? AND height=1',(self.channel,)).fetchone()[0]
   self.registry._db.execute('UPDATE official_replayed_blocks SET wire=? WHERE channel=? AND height=1',('{}',self.channel))
   with self.assertRaises((ValueError,KeyError)):server.verified_head(self.channel)
   self.assertEqual(len(calls),2,'changed stored bytes must be reverified')
   self.registry._db.execute('UPDATE official_replayed_blocks SET wire=? WHERE channel=? AND height=1',(wire,self.channel))
   self.assertEqual(server.verified_head(self.channel),second)
  finally:server.server_close()
 def test_wrong_actor_account_and_ban_are_refused(self):
  rec=self.record();other=types.SimpleNamespace(identity={'kind':'registered','name':'bob','sub':'user:'+str(uuid.uuid4()),'sid':str(uuid.uuid4())})
  with self.assertRaises(ValueError):self.writer.append(self.channel,self.genesis,rec,self.bind(),other)
  self.writer.append(self.channel,self.genesis,rec,self.bind(),self.principal)
  with self.assertRaises(ValueError):self.writer.append(self.channel,self.genesis,self.record(),self.bind(other),other)
  OfficialUploadPolicy(self.path).set_ban(self.channel,self.subject,True)
  with self.assertRaises(ValueError):self.writer.append(self.channel,self.genesis,self.record(),self.bind(),self.principal)
  self.assertEqual(self.registry.replayed_head(self.channel)['height'],1)
 def test_anonymous_invalid_signature_and_stale_author_are_refused(self):
  anon=types.SimpleNamespace(identity={'kind':'anonymous','name':'anon','sub':'anon:'+str(uuid.uuid4()),'sid':str(uuid.uuid4())})
  with self.assertRaises(ValueError):self.writer.append(self.channel,self.genesis,self.record(),self.bind(anon),anon)
  rec=self.record();bad={**rec,'proposal':rec['proposal'][:-2]+'AA'}
  with self.assertRaises(ValueError):self.writer.append(self.channel,self.genesis,bad,self.bind(),self.principal)
  self.assertEqual(self.registry.replayed_head(self.channel)['height'],0)
  self.writer.append(self.channel,self.genesis,rec,self.bind(),self.principal)
  with self.assertRaises(ValueError):self.writer.append(self.channel,self.genesis,self.record('stale'),self.bind(),self.principal)
  self.assertEqual(self.registry.replayed_head(self.channel)['height'],1)
 def test_signed_spam_marker_preserves_original(self):
  self.writer.append(self.channel,self.genesis,self.record('original text'),self.bind(),self.principal);before=self.registry.replayed_head(self.channel);message=before['state']['messages'][0]
  result=mark_spam(self.registry,self.key,message=message['id']);self.assertEqual(result['state']['moderation'][0]['message'],message['id']);self.assertEqual(result['state']['messages'][0]['text'],'original text')
  with self.assertRaises(ValueError):mark_spam(self.registry,self.key,message=message['id'])
  self.assertEqual(self.registry.replayed_head(self.channel)['height'],2)
 def test_offline_original_stays_stale_after_ban_and_unban(self):
  self.writer.append(self.channel,self.genesis,self.record('first'),self.bind(),self.principal);before=self.registry.replayed_head(self.channel);last=before['state']['authors'][0]['last'];offline=self.record('offline',sequence=2,previous=last)
  set_banned(self.registry,self.key,issuer='https://ksu.codes',subject=self.subject,banned=True);set_banned(self.registry,self.key,issuer='https://ksu.codes',subject=self.subject,banned=False)
  with self.assertRaises(ValueError):self.writer.append(self.channel,self.genesis,offline,self.bind(),self.principal)
  state=self.registry.replayed_head(self.channel)['state'];epoch=next(a['epoch'] for a in state['authorEpochs'] if a['actor']==self.actor);self.writer.append(self.channel,self.genesis,self.record('offline',sequence=2,previous=last,epoch=epoch),self.bind(),self.principal)
  self.assertEqual([x['text'] for x in self.registry.replayed_head(self.channel)['state']['messages']],['first','offline'])
 def test_unseen_device_after_unban_requires_a_new_original(self):
  offline=self.record('unsent');set_banned(self.registry,self.key,issuer='https://ksu.codes',subject=self.subject,banned=True);set_banned(self.registry,self.key,issuer='https://ksu.codes',subject=self.subject,banned=False)
  with self.assertRaises(OfficialWriteDenied):self.writer.append(self.channel,self.genesis,offline,self.bind(),self.principal)
  with self.assertRaises(OfficialWriteDenied):self.writer.append(self.channel,self.genesis,offline,self.bind(),self.principal)
  self.writer.append(self.channel,self.genesis,self.record('unsent'),self.bind(),self.principal);self.assertEqual(self.registry.replayed_head(self.channel)['state']['messages'][0]['text'],'unsent')
 def test_denial_remembers_unseen_original_before_unban(self):
  offline=self.record('blocked');set_banned(self.registry,self.key,issuer='https://ksu.codes',subject=self.subject,banned=True);self.writer.note_denial(self.channel,self.genesis,offline,self.bind(),self.principal);set_banned(self.registry,self.key,issuer='https://ksu.codes',subject=self.subject,banned=False)
  with self.assertRaises(OfficialWriteDenied):self.writer.append(self.channel,self.genesis,offline,self.bind(),self.principal)
  self.writer.append(self.channel,self.genesis,self.record('blocked'),self.bind(),self.principal);self.assertEqual(self.registry.replayed_head(self.channel)['state']['messages'][0]['text'],'blocked')
 def test_unblock_race_still_remembers_denied_original(self):
  original=self.record('racing');set_banned(self.registry,self.key,issuer='https://ksu.codes',subject=self.subject,banned=True);set_banned(self.registry,self.key,issuer='https://ksu.codes',subject=self.subject,banned=False);self.writer.note_denial(self.channel,self.genesis,original,self.bind(),self.principal)
  with self.assertRaises(OfficialWriteDenied):self.writer.append(self.channel,self.genesis,original,self.bind(),self.principal)
  self.writer.append(self.channel,self.genesis,self.record('racing'),self.bind(),self.principal)
if __name__=='__main__':unittest.main(verbosity=2)
