#!/usr/bin/env python3
"""Time isolated signed chat writer and distinguish replay/author scan/witness work."""
import importlib.util,json,os,sys,time
from pathlib import Path
R=Path(__file__).resolve().parents[1];sys.path.insert(0,str(R));spec=importlib.util.spec_from_file_location('fixture',R/'scripts/official-chat-writer-check.py');fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
from steward.official_authors import inspect_author_record
from steward.official_chat_writer import VerifiedWriterCache
case=fixture.Checks();case.setUp();cached=os.environ.get("CODI_WRITER_CACHE")=="1"
if cached:case.writer.cache=VerifiedWriterCache()
try:
 previous=None;timings=[]
 for i in range(1,166):
  record=case.record('profile message '+str(i),sequence=i,previous=previous);start=time.monotonic();case.writer.append(case.channel,case.genesis,record,case.bind(),case.principal);elapsed=time.monotonic()-start
  previous=inspect_author_record(record,channel=case.channel)['operation']
  if i in (1,32,64,128,160,165):
   start=time.monotonic();case.registry.replayed_head(case.channel);replay=time.monotonic()-start;timings.append({'height':i,'appendMs':round(elapsed*1000),'readFullReplayMs':round(replay*1000)})
 print(json.dumps({'status':'PASS','samples':timings,'cache':cached,'scope':'isolated local signed channel and SQLite; not public server or network'},indent=2))
finally:case.tearDown()
