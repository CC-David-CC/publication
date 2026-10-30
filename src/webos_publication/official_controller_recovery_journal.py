"""Isolated experimental local selection journal, not channel authority.

No production service imports this module. Initialization accepts a caller's
trust anchor and does not authenticate it. A SQLite selection cannot prevent
another server or an old channel validator from accepting a conflicting head.
"""
import json, sqlite3
from .official_controller_recovery_proposal import verify_official_recovery_proposal, _fields, _key, _counter
from .protocol import identifier

class RecoveryJournal:
    def __init__(self,path):
        self.db=sqlite3.connect(path,isolation_level=None,timeout=10)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS recovery_state (channel TEXT PRIMARY KEY, context TEXT NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS recovery_selections (channel TEXT NOT NULL, generation INTEGER NOT NULL, proposal TEXT NOT NULL, acceptance TEXT NOT NULL, result TEXT NOT NULL, PRIMARY KEY(channel,generation))')
    def close(self):self.db.close()
    def initialize(self,context):
        _fields(context,('channel','genesisHash','head','generation','controller','recoveryKey','oldCommitteeHash','newCommitteeHash'))
        for key in ('channel','genesisHash','head','controller','oldCommitteeHash','newCommitteeHash'):identifier(context[key])
        _counter(context['generation']);_key(context['recoveryKey'])
        self.db.execute('INSERT INTO recovery_state(channel,context) VALUES (?,?)',(context['channel'],json.dumps(context,separators=(',',':'))))
    def context(self,channel):
        row=self.db.execute('SELECT context FROM recovery_state WHERE channel=?',(channel,)).fetchone()
        if not row:raise ValueError('Unknown experimental recovery channel')
        return json.loads(row[0])
    def select(self,channel,wire,acceptance,*,before_commit=None):
        identifier(channel);self.db.execute('BEGIN IMMEDIATE')
        try:
            current=self.context(channel)
            # Repeating the exact selected proposal is an idempotent receipt;
            # a different signature or proposal must pass against current state.
            prior=self.db.execute('SELECT proposal,acceptance,result FROM recovery_selections WHERE channel=? AND generation=?',(channel,current['generation'])).fetchone()
            if prior and prior[0]==wire and prior[1]==acceptance:
                result=json.loads(prior[2]);self.db.execute('COMMIT');return result
            result=verify_official_recovery_proposal(wire,acceptance,current)
            updated={**current,'generation':result['generation'],'controller':result['replacement']}
            encoded=json.dumps(result,separators=(',',':'))
            self.db.execute('INSERT INTO recovery_selections VALUES (?,?,?,?,?)',(channel,result['generation'],wire,acceptance,encoded))
            self.db.execute('UPDATE recovery_state SET context=? WHERE channel=?',(json.dumps(updated,separators=(',',':')),channel))
            if before_commit:before_commit()
            self.db.execute('COMMIT');return result
        except BaseException:
            self.db.execute('ROLLBACK');raise
