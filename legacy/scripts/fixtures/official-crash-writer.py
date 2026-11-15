#!/usr/bin/env python3
"""Disposable writer paused by a temporary SQLite trigger inside a transaction."""
import json,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from steward.official_registry import OfficialChannelRegistry
args=json.load(sys.stdin);store=OfficialChannelRegistry(args['db'])
def pause():
 Path(args['marker']).write_text('insert reached')
 while True:time.sleep(1)
store._db.create_function('fixture_pause',0,pause)
store._db.execute('CREATE TEMP TRIGGER crash_fixture AFTER INSERT ON official_replayed_blocks BEGIN SELECT fixture_pause(); END')
store.append_replayed(args['channel'],expected_head=args['head'],blocks=args['blocks'])
