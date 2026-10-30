#!/usr/bin/env python3
"""Mark one official message or author as spam using the operator key."""
import argparse,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'codiserver-server-v0.3.0')]
from steward.official_chat_moderator import mark_spam
from steward.official_chess_custody import load_key
from steward.official_registry import OfficialChannelRegistry
from steward.official_state_paths import validate_state
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--database',type=Path,required=True);p.add_argument('--validator-key-dir',type=Path,required=True);p.add_argument('--channel',required=True);which=p.add_mutually_exclusive_group(required=True);which.add_argument('--message');which.add_argument('--author');which.add_argument('--list',action='store_true',help='Show recent message IDs and text');a=p.parse_args();database=a.database.absolute()
 if database.name!='official.sqlite':raise ValueError('Designated official database required')
 validate_state(database.parent);key=load_key(a.validator_key_dir,a.channel);registry=OfficialChannelRegistry(database)
 try:
  if a.list:
   state=registry.replayed_head(a.channel)['state'];print(json.dumps({'channel':a.channel,'messages':state['messages'],'moderation':state.get('moderation',[]),'moderationAuthors':state.get('moderationAuthors',[])},ensure_ascii=False))
  else:
   result=mark_spam(registry,key,message=a.message,author=a.author);print(json.dumps({'status':'marked','channel':a.channel,'height':result['height']}))
 finally:registry.close()
