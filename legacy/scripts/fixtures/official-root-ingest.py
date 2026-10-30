#!/usr/bin/env python3
"""Root-only disposable fixture connecting enrollment to staged replay."""
import json,os,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from steward.official_registry import OfficialChannelRegistry
if os.geteuid()!=0:raise PermissionError('Fixture requires root')
a=json.load(sys.stdin);store=OfficialChannelRegistry(a['db'])
try:
 before=store.replayed_head(a['channel']);assert before['height']==0
 for cid,wire in a['nodes'].items():store.stage_node(a['channel'],cid,wire)
 result=store.append_staged_history(a['channel'],expected_head=before['head'],history=a['history'],height=a['height'],head=a['head'])
 print(json.dumps({'head':result['head'],'height':result['height'],'state':result['state']}))
finally:store.close()
