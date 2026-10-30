#!/usr/bin/env python3
"""Owned temporary runtime subprocess for crash-recovery tests only."""
import asyncio,json,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'codiserver-server-v0.3.0'))
from steward.official_runtime import OfficialRuntime

async def main():
    config=json.loads(sys.stdin.readline())
    if config.get('pause_before_commit'):
        from steward.official_registry import OfficialChannelRegistry
        original=OfficialChannelRegistry.append_staged_history
        def hold(self,*args,**kwargs):
            def pause():
                Path(config['pause_before_commit']).write_text('inserted')
                while True:time.sleep(1)
            self._db.create_function('fixture_pause',0,pause);self._db.execute('CREATE TEMP TRIGGER fixture_hold AFTER INSERT ON official_replayed_locators BEGIN SELECT fixture_pause(); END')
            return original(self,*args,**kwargs)
        OfficialChannelRegistry.append_staged_history=hold
    runtime=await OfficialRuntime(database=config['database'],ledger=config['ledger'],issuer_policy=config['policy']).start()
    print(json.dumps({'port':runtime.port}),flush=True)
    try:await asyncio.Event().wait()
    finally:await runtime.close()

if __name__=='__main__':asyncio.run(main())
