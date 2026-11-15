#!/usr/bin/env python3
"""Measure verified reader reuse with a longer signed chat and unrelated writes."""
import importlib.util,json,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from steward.official_read_http import OfficialReadServer
spec=importlib.util.spec_from_file_location('writer_fixture',ROOT/'scripts/official-chat-writer-check.py');fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
case=fixture.Checks();case.setUp();server=None
try:
 previous=None
 for number in range(1,31):
  case.writer.append(case.channel,case.genesis,case.record('message '+str(number),sequence=number,previous=previous),case.bind(),case.principal)
  previous=case.registry.replayed_head(case.channel)['state']['authors'][0]['last']
 server=OfficialReadServer(case.path);original=server.head_registry._load_replay;replays=[]
 def counted(channel):replays.append(channel);return original(channel)
 server.head_registry._load_replay=counted;initial=server.verified_head(case.channel);case.registry._db.execute('CREATE TABLE unrelated_work (value INTEGER)')
 start=time.monotonic()
 for number in range(10):
  case.registry._db.execute('INSERT INTO unrelated_work VALUES (?)',(number,));assert server.verified_head(case.channel)==initial
 cached=time.monotonic()-start;assert len(replays)==1
 incremental=0.0
 for number in range(31,36):
  case.writer.append(case.channel,case.genesis,case.record('message '+str(number),sequence=number,previous=previous),case.bind(),case.principal)
  previous=case.registry.replayed_head(case.channel)['state']['authors'][0]['last'];start=time.monotonic();tip=server.verified_head(case.channel);incremental+=time.monotonic()-start;assert tip['height']==number and len(replays)==1
 start=time.monotonic()
 for _ in range(10):original(case.channel)
 full=time.monotonic()-start
 print(json.dumps({'status':'PASS','signedBlocks':35,'unrelatedUpdates':10,'incrementalAppends':5,'fullReplaysAfterFirst':len(replays)-1,'cachedSeconds':round(cached,3),'incrementalSeconds':round(incremental,3),'replayingSeconds':round(full,3),'scope':'isolated local SQLite; browser/network and live performance not measured'}))
finally:
 if server:server.server_close()
 case.tearDown()
