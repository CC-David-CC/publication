#!/usr/bin/env python3
"""Disposable staged writer paused after locator insertion before commit."""
import json,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from steward.official_registry import OfficialChannelRegistry
args=json.load(sys.stdin);store=OfficialChannelRegistry(args['db'])
def pause():
 Path(args['marker']).write_text('locator inserted')
 while True:time.sleep(1)
store._db.create_function('fixture_pause',0,pause)
store._db.execute('CREATE TEMP TRIGGER crash_fixture AFTER INSERT ON official_replayed_locators BEGIN SELECT fixture_pause(); END')
store.append_staged_history(args['channel'],expected_head=args['head'],history=args['history'],height=args['height'],head=args['targetHead'])
