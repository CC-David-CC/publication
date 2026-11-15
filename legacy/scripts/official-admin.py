#!/usr/bin/env python3
"""Local operator commands for the experimental official-channel service.

Run as the account owning the private state directory. This tool does not
install services, publish routes, or change peer-to-peer moderation.
"""
import argparse
import json
import os
import stat
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'codiserver-server-v0.3.0'))
from steward.official_state_paths import validate_state
from steward.official_access import initialize as initialize_access
from steward.official_registry import OfficialChannelRegistry
from steward.official_upload_policy import OfficialUploadPolicy, initialize as initialize_policy



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, required=True)
    actions = parser.add_subparsers(dest='action', required=True)
    actions.add_parser('init')
    enroll = actions.add_parser('enroll');enroll.add_argument('signed_listing', type=Path)
    system = actions.add_parser('set-system');system.add_argument('channel')
    actions.add_parser('system-init')
    actions.add_parser('system-post',help='Read one announcement from standard input')
    for name in ('enable', 'disable'):
        command = actions.add_parser(name);command.add_argument('channel')
    for name in ('ban', 'unban'):
        command = actions.add_parser(name);command.add_argument('channel');command.add_argument('account')
    anonymous = actions.add_parser('anonymous');anonymous.add_argument('setting', choices=('allow', 'block'))
    listing=actions.add_parser('list');listing.add_argument('--after',default='')
    args = parser.parse_args()
    state = args.state
    db, ledger = state / 'official.sqlite', state / 'access.sqlite'
    if args.action == 'init':
        state = state.absolute()
        parent = state.parent
        if parent.resolve() != parent:
            raise ValueError('State parent must not traverse symlinks')
        info = parent.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid()) or stat.S_IMODE(info.st_mode) & 0o022:
            raise ValueError('State parent must be trusted and not writable by other users')
        db, ledger = state / 'official.sqlite', state / 'access.sqlite'
        state.mkdir(mode=0o700, parents=False, exist_ok=False)
        old = os.umask(0o077)
        try:
            registry = OfficialChannelRegistry(db);registry.close()
            initialize_policy(db);initialize_access(ledger)
        finally:
            os.umask(old)
        print(json.dumps({'status':'initialized','directory':str(state)}));return
    state = validate_state(state)
    db, ledger = state / 'official.sqlite', state / 'access.sqlite'
    if args.action in ('ban','unban','anonymous'):
        policy = OfficialUploadPolicy(db)
        if args.action == 'anonymous':policy.set_anonymous(args.setting == 'allow')
        else:policy.set_ban(args.channel,args.account,args.action == 'ban')
        print(json.dumps({'status':'updated','action':args.action}));return
    registry = OfficialChannelRegistry(db)
    try:
        if args.action=='system-init':
            from steward.system_custody import initialize
            print(json.dumps({'status':'updated',**initialize(registry,state)}));return
        if args.action=='system-post':
            from steward.system_custody import publish
            text=sys.stdin.read(4097)
            if len(text.encode('utf-8'))>4096:raise ValueError('SYSTEM announcement exceeds 4096 bytes')
            print(json.dumps({'status':'posted',**publish(registry,state,text)}));return
        if args.action=='set-system':
            registry.set_system_channel(args.channel);print(json.dumps({'status':'updated','action':args.action,'channel':args.channel}));return
        if args.action == 'enroll':
            wire=args.signed_listing.read_text(encoding='utf-8')
            result=registry.enroll(wire.strip(),now=int(time.time()))
        elif args.action in ('enable','disable'):
            registry.set_enabled(args.channel,args.action == 'enable');result=registry.get(args.channel)
        else:
            result=registry.public_directory(limit=32,after=args.after)
        print(json.dumps(result))
    finally:
        registry.close()


if __name__ == '__main__':
    main()
