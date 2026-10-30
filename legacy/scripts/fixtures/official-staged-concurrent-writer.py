#!/usr/bin/env python3
"""Disposable staged writer used by the multiprocess fixture."""
import json,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from steward.official_registry import OfficialChannelRegistry
args=json.load(sys.stdin);store=OfficialChannelRegistry(args['db'])
try:
 deadline=time.monotonic()+20
 while not Path(args['start']).exists():
  if time.monotonic()>deadline:raise TimeoutError('fixture barrier timed out')
  time.sleep(.01)
 try:
  result=store.append_staged_history(args['channel'],expected_head=args['head'],history=args['history'],height=args['height'],head=args['targetHead'])
  print(json.dumps({'status':'committed','head':result['head']}))
 except ValueError as error:print(json.dumps({'status':'rejected','error':str(error)}))
finally:store.close()
