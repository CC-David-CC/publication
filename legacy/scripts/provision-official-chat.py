#!/usr/bin/env python3
"""Provision the operator-offered General chess chat as the service owner."""
import argparse,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'codiserver-server-v0.3.0')]
from steward.official_chat_custody import provision
from steward.official_state_paths import validate_state

if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--database',type=Path,required=True);parser.add_argument('--validator-key-dir',type=Path,required=True);args=parser.parse_args()
 database=args.database.absolute()
 if database.name!='official.sqlite':raise ValueError('Designated official database required')
 validate_state(database.parent)
 print(json.dumps(provision(database,args.validator_key_dir.absolute()),indent=2))
