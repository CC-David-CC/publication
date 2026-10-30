"""Experimental identity admission and persistent one-use official challenges.

Identity admission does not authorize storage. A separate policy must decide
whether this principal may submit the named official channel.
"""
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from origin_service.official_authority import CONFIRMATION_TYPE
from room_service.contract import (jose,require,exact,identifier,integer,window,
                                   issuer_proof,verify_identity,Principal)

USE_TYPE='codi-official-ingest-use+jws'
SCHEMA={
 'official_access_metadata':'CREATE TABLE official_access_metadata (version INTEGER PRIMARY KEY CHECK(version=1))',
 'official_access_challenges':'CREATE TABLE official_access_challenges (nonce TEXT PRIMARY KEY, key_thumb TEXT NOT NULL, request_sha TEXT NOT NULL, expires INTEGER NOT NULL)',
 'official_access_spent':'CREATE TABLE official_access_spent (id TEXT PRIMARY KEY, expires INTEGER NOT NULL)',
}

@contextmanager
def connection(path,*,create=False):
    uri=Path(path).resolve().as_uri()+'?mode='+('rwc' if create else 'rw')
    db=sqlite3.connect(uri,timeout=10,uri=True)
    try:
        with db:yield db
    finally:db.close()


def initialize(path):
    """Explicit initialization; normal service startup never repairs a ledger."""
    with connection(path,create=True) as db:
        db.execute('BEGIN IMMEDIATE')
        present={row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")} & SCHEMA.keys()
        if not present:
            for statement in SCHEMA.values():db.execute(statement)
            db.execute('INSERT INTO official_access_metadata VALUES(1)')
        check_schema(db)


def check_schema(db):
    for name,statement in SCHEMA.items():
        if db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(name,)).fetchone()!=(statement,):raise ValueError('Official access ledger schema unavailable')
    if db.execute('SELECT version FROM official_access_metadata').fetchall()!=[(1,)]:raise ValueError('Official access ledger version unavailable')


class OfficialAccess:
    def __init__(self,path,policy,*,base_path='',clock=time.time,capacity=128):
        from room_service.contract import context,trusted_keys
        context(policy['issuer'],base_path);trusted_keys(policy)
        if type(capacity) is not int or not 1<=capacity<=1024:raise ValueError('Invalid challenge capacity')
        self.path=path;self.policy=policy;self.clock=clock;self.capacity=capacity
        self.audience=policy['issuer']+base_path+'/official-ingest';self.use_path=base_path+'/official-ingest/use'
        with connection(path) as db:check_schema(db)

    def challenge(self,key,request_sha):
        identifier(request_sha);thumb=jose.thumbprint(key);now=int(self.clock())
        with connection(self.path) as db:
            db.execute('BEGIN IMMEDIATE');check_schema(db)
            db.execute('DELETE FROM official_access_challenges WHERE expires<=?',(now,));db.execute('DELETE FROM official_access_spent WHERE expires<=?',(now,))
            require(db.execute('SELECT count(*) FROM official_access_challenges').fetchone()[0]<self.capacity and db.execute('SELECT count(*) FROM official_access_challenges WHERE key_thumb=?',(thumb,)).fetchone()[0]<8,'Official challenge capacity reached')
            nonce=secrets.token_urlsafe(32);db.execute('INSERT INTO official_access_challenges VALUES(?,?,?,?)',(nonce,thumb,request_sha,now+60))
        return {'nonce':nonce,'request_sha256':request_sha,'expires_at':now+60}

    def consume(self,raw,confirmation,proof):
        require(isinstance(raw,str) and len(raw.encode('utf-8'))<=8*1048576,'Bounded official offer required');now=int(self.clock())
        c=issuer_proof(confirmation,CONFIRMATION_TYPE,self.policy)
        exact(c,['v','iss','aud','identity','iat','exp','jti','nonce','request_sha256','session_deadline'])
        require(type(c['v']) is int and c['v']==1 and c['iss']==self.policy['issuer'] and c['aud']==self.audience,'Wrong official confirmation context')
        window(c,now,30);identifier(c['jti']);identifier(c['nonce']);identifier(c['request_sha256'])
        _,identity_exp=verify_identity(c['identity'],self.policy,now);integer(c['session_deadline'],c['exp'],9007199254740991)
        require(c['exp']<=identity_exp and c['request_sha256']==jose.digest(raw),'Official confirmation body or lifetime mismatch')
        identity=c['identity'];p=jose.verify(proof,identity['key'],USE_TYPE,8192)
        exact(p,['v','iss','aud','nonce','grant_sha256','request_sha256','method','path','iat','exp']);window(p,now,30)
        require(type(p['v']) is int and p['v']==1 and p['iss']==identity['sid'] and p['aud']==self.audience and p['nonce']==c['nonce'] and p['grant_sha256']==jose.digest(confirmation) and p['request_sha256']==c['request_sha256'] and p['method']=='POST' and p['path']==self.use_path and p['exp']<=c['exp'],'Official client proof context changed')
        with connection(self.path) as db:
            db.execute('BEGIN IMMEDIATE');check_schema(db)
            row=db.execute('SELECT key_thumb,request_sha,expires FROM official_access_challenges WHERE nonce=?',(c['nonce'],)).fetchone()
            require(row is not None and row[:2]==(jose.thumbprint(identity['key']),c['request_sha256']) and row[2]>now,'Missing, spent or changed official challenge')
            db.execute('DELETE FROM official_access_spent WHERE expires<=?',(now,))
            require(db.execute('SELECT count(*) FROM official_access_spent').fetchone()[0]<4096 and not db.execute('SELECT 1 FROM official_access_spent WHERE id=?',(c['jti'],)).fetchone(),'Official confirmation used or capacity reached')
            db.execute('INSERT INTO official_access_spent VALUES(?,?)',(c['jti'],c['exp']));db.execute('DELETE FROM official_access_challenges WHERE nonce=?',(c['nonce'],))
        return Principal(identity,min(c['exp'],p['exp']))
