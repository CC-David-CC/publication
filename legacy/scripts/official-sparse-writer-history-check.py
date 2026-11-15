#!/usr/bin/env python3
"""Replay a substantial signed history through the cached writer."""
import importlib.util,sys,time,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
spec=importlib.util.spec_from_file_location('writer_fixture',ROOT/'scripts/official-chat-writer-check.py');fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
from steward.official_chat_writer import VerifiedWriterCache
from steward.official_authors import inspect_author_record

class History(fixture.Checks):
 def test_400_signed_messages_match_full_replay(self):
  self.writer.cache=VerifiedWriterCache();previous=None;start=time.monotonic()
  for i in range(1,401):
   record=self.record('cache history '+str(i),sequence=i,previous=previous)
   result=self.writer.append(self.channel,self.genesis,record,self.bind(),self.principal)
   self.assertEqual(result['status'],'accepted');previous=inspect_author_record(record,channel=self.channel)['operation']
  snapshot=self.registry._load_replay(self.channel).snapshot();self.assertEqual(snapshot['height'],400);self.assertEqual(snapshot['state']['messages'][-1]['text'],'cache history 400')
  self.assertEqual(self.writer.cache._trees[self.channel][1].root(),snapshot['state']['acceptedRoot'])
  print('400 signed messages and fresh complete replay:',round(time.monotonic()-start,2),'seconds',flush=True)

if __name__=='__main__':unittest.main(defaultTest='History.test_400_signed_messages_match_full_replay')
