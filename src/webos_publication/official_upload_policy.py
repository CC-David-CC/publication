"""Experimental operator-owned policy for official-history uploads only.

This does not ban users from P2P chat or disable anonymous introductions.
"""
import uuid
from .official_access import connection
from .official_content import _id

SCHEMA={
 'official_upload_settings':'CREATE TABLE official_upload_settings (version INTEGER PRIMARY KEY CHECK(version=1), anonymous_allowed INTEGER NOT NULL CHECK(anonymous_allowed IN (0,1)))',
 'official_upload_bans':'CREATE TABLE official_upload_bans (scope TEXT NOT NULL, subject TEXT NOT NULL, PRIMARY KEY(scope,subject))',
}

def check_schema(db):
    for name,sql in SCHEMA.items():
        if db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(name,)).fetchone()!=(sql,):raise ValueError('Official upload policy schema unavailable')
    if len(db.execute('SELECT version,anonymous_allowed FROM official_upload_settings').fetchall())!=1:raise ValueError('Official upload settings unavailable')

def initialize(path):
    with connection(path,create=True) as db:
        db.execute('BEGIN IMMEDIATE');present={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")} & SCHEMA.keys()
        if not present:
            for sql in SCHEMA.values():db.execute(sql)
            db.execute('INSERT INTO official_upload_settings VALUES(1,1)')
        check_schema(db)

def subject(value):
    if not isinstance(value,str) or not value.startswith('user:'):raise ValueError('Registered account subject required')
    try:canonical='user:'+str(uuid.UUID(value[5:]))
    except (ValueError,AttributeError) as error:raise ValueError('Invalid account subject') from error
    if canonical!=value:raise ValueError('Canonical account subject required')
    return value

def scope(value):
    if value!='*':_id(value)
    return value

def permits(db,identity,channel):
    _id(channel);check_schema(db)
    if not isinstance(identity,dict) or set(identity)!={'kind','sub'}:return False
    kind=identity['kind'];account=identity['sub'];entry=db.execute('SELECT enabled FROM official_channels WHERE channel=?',(channel,)).fetchone()
    if not entry or entry[0]!=1:return False
    if kind=='anonymous':
        try:valid=isinstance(account,str) and account.startswith('anon:') and 'anon:'+str(uuid.UUID(account[5:]))==account
        except (ValueError,AttributeError):valid=False
        return valid and db.execute('SELECT anonymous_allowed FROM official_upload_settings WHERE version=1').fetchone()[0]==1
    if kind!='registered':return False
    subject(account)
    return not bool(db.execute('SELECT 1 FROM official_upload_bans WHERE subject=? AND scope IN (?,?)',(account,'*',channel)).fetchone())

class OfficialUploadPolicy:
    def __init__(self,path):
        self.path=path
        with connection(path) as db:check_schema(db)

    def set_anonymous(self,allowed):
        if type(allowed) is not bool:raise ValueError('Explicit boolean required')
        with connection(self.path) as db:
            db.execute('BEGIN IMMEDIATE');check_schema(db);db.execute('UPDATE official_upload_settings SET anonymous_allowed=? WHERE version=1',(int(allowed),))

    def set_ban(self,channel,account,banned):
        scope(channel);subject(account)
        if type(banned) is not bool:raise ValueError('Explicit boolean required')
        with connection(self.path) as db:
            db.execute('BEGIN IMMEDIATE');check_schema(db)
            if channel!='*' and not db.execute('SELECT 1 FROM official_channels WHERE channel=?',(channel,)).fetchone():raise ValueError('Unknown official channel')
            if banned:db.execute('INSERT OR IGNORE INTO official_upload_bans(scope,subject) VALUES(?,?)',(channel,account))
            else:db.execute('DELETE FROM official_upload_bans WHERE scope=? AND subject=?',(channel,account))

    def __call__(self,principal,channel):
        identity=principal.identity
        with connection(self.path) as db:
            db.execute('BEGIN');return permits(db,{'kind':identity.get('kind'),'sub':identity.get('sub')},channel)
