#!/usr/bin/env python3
"""Exercise local operator initialization without touching a live service."""
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from cryptography.hazmat.primitives.asymmetric import ec
from steward.protocol import jose, TYPE, KEY_VERSION, CHANNEL_PROFILE, PROFILE
from steward.official_access import connection
from steward.official_upload_policy import permits
with tempfile.TemporaryDirectory(prefix='official-admin-check-') as tmp:
    state=Path(tmp)/'state'
    def run(*args):
        return subprocess.run([sys.executable,str(ROOT/'scripts/official-admin.py'),'--state',str(state),*args],capture_output=True,text=True)
    first=run('init');assert first.returncode==0,first.stderr
    assert json.loads(first.stdout)['status']=='initialized'
    assert state.stat().st_mode & 0o777 == 0o700
    for file in ('official.sqlite','access.sqlite'):
        assert (state/file).is_file() and (state/file).stat().st_mode & 0o077 == 0
    assert run('init').returncode!=0
    assert json.loads(run('list').stdout)=={'items':[],'next':None}
    assert run('anonymous','block').returncode==0
    assert run('anonymous','allow').returncode==0
    assert run('ban','*','invalid').returncode!=0
    assert run('enable','invalid').returncode!=0
    key=ec.generate_private_key(ec.SECP256R1());public=jose.public_jwk(key)
    channel=jose.digest(jose.dumps([KEY_VERSION,jose.thumbprint(public)]))
    def sign(body):return jose.sign({'version':KEY_VERSION,'channel':channel,'key':public,'purpose':'checkpoint','body':body},key,TYPE)
    policy=sign({'profile':CHANNEL_PROFILE,'type':'policy','channel':channel,'stream':'chat','validators':[channel],'publicWrite':True,'players':None,'publicRead':True})
    parts=policy.split('.');genesis=jose.digest(jose.dumps([CHANNEL_PROFILE,'signed-content',parts[0],parts[1]]));now=int(time.time())
    listing=sign({'profile':PROFILE,'category':'user','channel':channel,'genesisHash':genesis,'policyWire':policy,'label':'Operator fixture','description':'','issued':now,'expires':now+180})
    path=Path(tmp)/'listing';path.write_text(listing)
    enrolled=run('enroll',str(path));assert enrolled.returncode==0,enrolled.stderr
    assert json.loads(enrolled.stdout)['channel']==channel
    assert json.loads(run('list').stdout)['items'][0]['channel']==channel
    account='user:'+str(uuid.uuid4());identity={'kind':'registered','sub':account}
    def allowed():
        with connection(state/'official.sqlite') as db:return permits(db,identity,channel)
    assert allowed();assert run('ban',channel,account).returncode==0;assert not allowed()
    assert run('unban',channel,account).returncode==0;assert allowed()
    assert run('disable',channel).returncode==0;assert not allowed() and not json.loads(run('list').stdout)['items']
    assert run('enable',channel).returncode==0;assert allowed()
print('PASS: private initialization, signed enrollment, listing, scoped ban/unban and channel disable/enable')
