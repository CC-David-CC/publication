#!/usr/bin/env python3
"""Run the experimental official-channel runtime on a fixed loopback port.

Databases and issuer policy must already be provisioned; this does not expose
or install a public service and is not a production provisioning tool.
"""
import argparse
import asyncio
import json
import signal
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'codiserver-server-v0.3.0'))
from steward.official_runtime import OfficialRuntime
from steward.official_state_paths import validate_state


async def run(args):
    database = args.database.absolute()
    ledger = args.ledger.absolute()
    if database.name != 'official.sqlite' or ledger.name != 'access.sqlite' or database.parent != ledger.parent:
        raise ValueError('Official database and ledger must share the designated state directory')
    validate_state(database.parent)
    policy_path = args.issuer_discovery or args.issuer_policy
    policy_bytes = policy_path.read_bytes()
    parsed = json.loads(policy_bytes)
    policy = parsed['identity'] if args.issuer_discovery else parsed
    runtime = OfficialRuntime(database=args.database, ledger=args.ledger,
                              issuer_policy=policy, base_path=args.base_path,
                              port=args.port,validator_key_dir=getattr(args,'validator_key_dir',None),receipts=getattr(args,'receipts',False))
    stopped = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stopped.set)
    try:
        await runtime.start()
        print(json.dumps({'status': 'ready', 'address': '127.0.0.1', 'port': runtime.port}), flush=True)
        if args.issuer_discovery:
            while not stopped.is_set():
                try:
                    await asyncio.wait_for(stopped.wait(), timeout=2)
                except asyncio.TimeoutError:
                    if policy_path.read_bytes() != policy_bytes:
                        raise RuntimeError('Issuer discovery changed; restart to load current signing policy')
        else:
            await stopped.wait()
    finally:
        await runtime.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', type=Path, required=True)
    parser.add_argument('--ledger', type=Path, required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--issuer-policy', type=Path)
    source.add_argument('--issuer-discovery', type=Path)
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--validator-key-dir', type=Path, help='Private operator-provisioned official chat validator keys')
    parser.add_argument('--receipts', action='store_true', help='Enable account delivery checkpoints after explicit schema migration')
    parser.add_argument('--base-path', default='')
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error('--port must be between 1 and 65535')
    asyncio.run(run(args))
