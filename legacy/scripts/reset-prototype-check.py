#!/usr/bin/env python3
"""Check coordinated prototype reset and rollback with real signed fixtures."""
import json,pathlib,subprocess,sys,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'codiserver-server-v0.3.0')]
from steward.official_chat_custody import provision
from steward.official_chess_custody import provision as provision_game
from steward.official_registry import OfficialChannelRegistry
from steward.official_receipts import initialize as receipts
from steward.official_upload_policy import initialize as upload
with tempfile.TemporaryDirectory(prefix='prototype-reset-check-') as directory:
 root=pathlib.Path(directory);keys=root/'keys';keys.mkdir(mode=0o700);db=root/'official.sqlite'
 old=provision(db,keys);game=provision_game(db,keys,old['channel']);upload(db);receipts(db);registry=OfficialChannelRegistry(db)
 registry._db.execute('INSERT INTO official_staged_nodes(channel,cid,wire) VALUES(?,?,?)',(old['channel'],'test','test'))
 registry._db.execute('INSERT INTO official_upload_bans(scope,subject) VALUES(?,?)',(old['channel'],'testsubject'))
 registry._db.execute('INSERT INTO official_channels VALUES(?,?,?,?,?,?,?)',('other','genesis','policy','Keep other','desc',1,1));registry._db.execute('INSERT INTO official_roles VALUES(?,?)',('system','other'));registry.close()
 original=(keys/'general-chess.json').read_bytes();before={p.name for p in keys.glob('*.pem')}
 source=(ROOT/'scripts/reset-prototype-chat-chess.py').read_text().replace(" assert new_chat['channel']!=old_chat", " raise RuntimeError('injected failure')\n assert new_chat['channel']!=old_chat")
 fault=root/'fault.py';fault.write_text(source);args=[str(db),str(keys),str(ROOT)]
 failed=subprocess.run([sys.executable,str(fault),*args],capture_output=True,text=True)
 assert failed.returncode and 'injected failure' in failed.stderr and (keys/'general-chess.json').read_bytes()==original and {p.name for p in keys.glob('*.pem')}==before
 registry=OfficialChannelRegistry(db);assert registry.get(old['channel']) and registry.get(game['game']['config']['channel']);registry.close()
 result=subprocess.run([sys.executable,str(ROOT/'scripts/reset-prototype-chat-chess.py'),*args],capture_output=True,text=True,check=True);value=json.loads(result.stdout)
 registry=OfficialChannelRegistry(db)
 assert registry.get(old['channel']) is None and registry.get(game['game']['config']['channel']) is None
 assert registry.get(value['newChat'])['label']=='General chess chat' and registry.get(value['newGame']) and registry.get('other')
 assert registry._db.execute('SELECT channel FROM official_roles WHERE role=?',('system',)).fetchone()==('other',)
 assert registry._db.execute('SELECT count(*) FROM official_staged_nodes WHERE channel=?',(old['channel'],)).fetchone()[0]==0
 assert registry._db.execute('SELECT count(*) FROM official_upload_bans WHERE scope=?',(value['newChat'],)).fetchone()[0]==1
 registry.close();print('PASS prototype reset preserves other channels and bans; late failure restores signed chat, game and keys')
