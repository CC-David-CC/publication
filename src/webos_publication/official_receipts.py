"""Account-scoped checkpoints for verified official chat history.

The caller must authenticate the principal and bind the entire request to its
proof. A checkpoint is a statement by that account, not proof of human reading.
"""
import json
from .official_access import connection
from .official_chat_replay import _digest
from .official_content import _id
from .official_upload_policy import permits
from .protocol import _proof

SCHEMA = 'CREATE TABLE official_chat_receipts (channel TEXT NOT NULL, subject TEXT NOT NULL, height INTEGER NOT NULL, head TEXT NOT NULL, PRIMARY KEY(channel,subject))'

def check_schema(db):
    if db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='official_chat_receipts'").fetchone() != (SCHEMA,):
        raise ValueError('Official receipt schema unavailable')

def initialize(path):
    """Explicit migration, separate from request handling and service startup."""
    with connection(path) as db:
        db.execute('BEGIN IMMEDIATE')
        row = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='official_chat_receipts'").fetchone()
        if row is None:
            db.execute(SCHEMA)
        elif row[0] != SCHEMA:
            raise ValueError('Official receipt schema differs')

def _validate(db, channel, genesis, height, head, identity):
    check_schema(db)
    if not permits(db, {'kind': identity.get('kind'), 'sub': identity.get('sub')}, channel):
        raise ValueError('Official channel access denied')
    entry = db.execute('SELECT genesis_hash,policy_wire FROM official_channels WHERE channel=? AND enabled=1', (channel,)).fetchone()
    if not entry or entry[0] != genesis:
        raise ValueError('Official channel pin differs')
    policy = _proof(entry[1], channel)
    if not isinstance(policy, dict) or policy.get('stream') != 'chat' or policy.get('publicRead') is not True:
        raise ValueError('Public official chat required')
    row = db.execute('SELECT wire FROM official_replayed_blocks WHERE channel=? AND height=?', (channel, height)).fetchone()
    if not row:
        raise ValueError('Receipt head is not in official history')
    block = json.loads(row[0]); header = block['header']
    if header.get('channel') != channel or header.get('genesisHash') != genesis or header.get('height') != height or _digest({k:v for k,v in header.items() if k != 'round'}) != head:
        raise ValueError('Receipt head differs from official history')

def _other(db, channel, subject):
    row = db.execute('SELECT height,head FROM official_chat_receipts WHERE channel=? AND subject<>? ORDER BY height DESC LIMIT 1', (channel, subject)).fetchone()
    return {'other': {'height': row[0], 'head': row[1]} if row else None}

def checkpoint(path, *, channel, genesis, height, head, principal):
    """Record a confirmed stored head and return the furthest other account.

    The result is only a checkpoint; callers must establish message ancestry
    before assigning a delivery label. All authorization and head checks happen
    in the same transaction as the monotonic update.
    """
    _id(channel); _id(genesis); _id(head)
    if type(height) is not int or not 1 <= height <= 9007199254740991:
        raise ValueError('Invalid receipt height')
    identity = principal.identity
    if identity.get('kind') != 'registered':
        raise ValueError('Registered identity required')
    # Most polls confirm the same already stored head. They can read a
    # consistent WAL snapshot without contending with chat's writer lock.
    with connection(path) as db:
        db.execute('BEGIN')
        _validate(db,channel,genesis,height,head,identity)
        previous=db.execute('SELECT height FROM official_chat_receipts WHERE channel=? AND subject=?',(channel,identity['sub'])).fetchone()
        if previous and previous[0]>=height:
            return _other(db,channel,identity['sub'])
    # A new head needs a write lock; recheck everything inside that transaction
    # because the account, channel or history can change after the first read.
    with connection(path) as db:
        db.execute('BEGIN IMMEDIATE')
        _validate(db,channel,genesis,height,head,identity)
        db.execute('INSERT INTO official_chat_receipts(channel,subject,height,head) VALUES(?,?,?,?) ON CONFLICT(channel,subject) DO UPDATE SET height=excluded.height,head=excluded.head WHERE excluded.height>official_chat_receipts.height', (channel, identity['sub'], height, head))
        return _other(db,channel,identity['sub'])
