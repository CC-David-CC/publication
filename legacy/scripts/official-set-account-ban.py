#!/usr/bin/env python3
"""Set an official account restriction and sign affected device epochs."""
import argparse,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'codiserver-server-v0.3.0')]
from steward.official_chat_access import set_banned
from steward.official_chess_custody import load_key
from steward.official_registry import OfficialChannelRegistry
from steward.official_state_paths import validate_state
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--database',type=Path,required=True);p.add_argument('--validator-key-dir',type=Path,required=True);p.add_argument('--channel',required=True);p.add_argument('--issuer',required=True);p.add_argument('--subject',required=True);p.add_argument('action',choices=('ban','unban'));a=p.parse_args();db=a.database.absolute()
 if db.name!='official.sqlite':raise ValueError('Designated official database required')
 validate_state(db.parent);key=load_key(a.validator_key_dir,a.channel);registry=OfficialChannelRegistry(db)
 try:print(json.dumps(set_banned(registry,key,issuer=a.issuer,subject=a.subject,banned=a.action=='ban')))
 finally:registry.close()
