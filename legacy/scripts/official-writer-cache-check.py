#!/usr/bin/env python3
"""Exercise cached chat authority against signed moderation and storage changes."""
import importlib.util,json,sys,unittest
from pathlib import Path
R=Path(__file__).resolve().parents[1];sys.path.insert(0,str(R));spec=importlib.util.spec_from_file_location('fixture',R/'scripts/official-chat-writer-check.py');fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
from steward.official_chat_writer import VerifiedWriterCache
from steward.official_authors import inspect_author_record
from steward.official_chat_moderator import mark_spam
class CachedChecks(fixture.Checks):
 def setUp(self):super().setUp();self.writer.cache=VerifiedWriterCache()
 def test_cache_rechecks_exact_bytes_and_incremental_moderation(self):
  original=self.registry._load_replay;calls=[]
  def counted(channel):calls.append(channel);return original(channel)
  self.registry._load_replay=counted
  one=self.record('one');self.writer.append(self.channel,self.genesis,one,self.bind(),self.principal);self.assertEqual(len(calls),1)
  self.registry._db.execute('CREATE TABLE unrelated_cache_work (value INTEGER)');self.registry._db.execute('INSERT INTO unrelated_cache_work VALUES (1)')
  last=inspect_author_record(one,channel=self.channel)['operation'];two=self.record('two',sequence=2,previous=last);self.writer.append(self.channel,self.genesis,two,self.bind(),self.principal);self.assertEqual(len(calls),1)
  mark_spam(self.registry,self.key,message=last);base=len(calls);last=inspect_author_record(two,channel=self.channel)['operation'];three=self.record('three',sequence=3,previous=last)
  self.writer.append(self.channel,self.genesis,three,self.bind(),self.principal);self.assertEqual(len(calls),base,'valid external moderation must replay only its suffix')
  last=inspect_author_record(three,channel=self.channel)['operation'];four=self.record('four',sequence=4,previous=last)
  self.registry._db.execute('INSERT INTO official_replayed_blocks(channel,height,wire) VALUES(?,?,?)',(self.channel,5,'{}'))
  with self.assertRaises((ValueError,KeyError)):self.writer.append(self.channel,self.genesis,four,self.bind(),self.principal)
  self.registry._db.execute('DELETE FROM official_replayed_blocks WHERE channel=? AND height=5',(self.channel,))
  wire=self.registry._db.execute('SELECT wire FROM official_replayed_blocks WHERE channel=? AND height=1',(self.channel,)).fetchone()[0];self.registry._db.execute('UPDATE official_replayed_blocks SET wire=? WHERE channel=? AND height=1',('{}',self.channel))
  with self.assertRaises((ValueError,KeyError)):self.writer.append(self.channel,self.genesis,four,self.bind(),self.principal)
  self.assertEqual(len(calls),base+1,'changed prefix must force full cryptographic replay');self.registry._db.execute('UPDATE official_replayed_blocks SET wire=? WHERE channel=? AND height=1',(wire,self.channel))
  self.writer.append(self.channel,self.genesis,four,self.bind(),self.principal);result=original(self.channel).snapshot();self.assertEqual(result['height'],5);self.assertEqual([m['text'] for m in result['state']['messages']],['one','two','three','four']);self.assertEqual(len(result['state']['moderation']),1)
if __name__=='__main__':unittest.main(verbosity=2)
