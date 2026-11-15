#!/usr/bin/env python3
"""Exercise receipt checkpoint authorization and monotonicity in SQLite."""
import concurrent.futures, json, pathlib, sqlite3, sys, tempfile, unittest
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from steward.official_registry import OfficialChannelRegistry
from steward.official_upload_policy import initialize as policy_initialize, OfficialUploadPolicy
from steward.official_receipts import initialize, checkpoint
from steward.official_chat_replay import _digest

class Receipts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path = str(pathlib.Path(self.temp.name) / 'official.sqlite')
        registry = OfficialChannelRegistry(self.path); self.addCleanup(registry.close)
        self.channel = _digest('channel'); self.genesis = _digest('genesis')
        registry._db.execute('INSERT INTO official_channels VALUES(?,?,?,?,?,?,?)', (self.channel,self.genesis,'policy','Chat','',1,0))
        self.heads = []
        for height in (1,2):
            header = {'channel':self.channel,'genesisHash':self.genesis,'height':height,'round':0}
            self.heads.append(_digest({k:v for k,v in header.items() if k != 'round'}))
            registry._db.execute('INSERT INTO official_replayed_blocks VALUES(?,?,?)',(self.channel,height,json.dumps({'header':header})))
        policy_initialize(self.path); initialize(self.path)
        self.proof_patch = patch('steward.official_receipts._proof', return_value={'stream':'chat','publicRead':True}); self.proof = self.proof_patch.start(); self.addCleanup(self.proof_patch.stop)
        self.alice = SimpleNamespace(identity={'kind':'registered','sub':'user:00000000-0000-0000-0000-000000000001'})
        self.bob = SimpleNamespace(identity={'kind':'registered','sub':'user:00000000-0000-0000-0000-000000000002'})
    def save(self, who, n, head=None):
        return checkpoint(self.path,channel=self.channel,genesis=self.genesis,height=n,head=head or self.heads[n-1],principal=who)
    def test_other_account_and_monotonic(self):
        self.assertIsNone(self.save(self.alice,2)['other'])
        self.assertIsNone(self.save(self.alice,1)['other'])
        self.assertEqual(self.save(self.bob,1)['other'],{'height':2,'head':self.heads[1]})
        self.assertEqual(self.save(self.alice,1)['other'],{'height':1,'head':self.heads[0]})
    def test_invalid_and_banned(self):
        with self.assertRaises(ValueError): self.save(self.bob,1,_digest('wrong head'))
        with self.assertRaises(ValueError): self.save(SimpleNamespace(identity={'kind':'anonymous','sub':'x'}),1)
        OfficialUploadPolicy(self.path).set_ban(self.channel,self.bob.identity['sub'],True)
        with self.assertRaises(ValueError): self.save(self.bob,1)
        self.assertIsNone(self.save(self.alice,1)['other'])
    def test_unavailable_or_wrong_channel(self):
        with self.assertRaises(ValueError): checkpoint(self.path,channel=self.channel,genesis=_digest('wrong genesis'),height=1,head=self.heads[0],principal=self.alice)
        with self.assertRaises(ValueError): checkpoint(self.path,channel=self.channel,genesis=self.genesis,height=3,head=_digest('missing'),principal=self.alice)
        self.proof.return_value={'stream':'chess','publicRead':True}
        with self.assertRaises(ValueError): self.save(self.alice,1)
    def test_unchanged_receipt_does_not_wait_for_unrelated_writer(self):
        self.save(self.alice,1)
        db=sqlite3.connect(self.path,timeout=5);db.execute('BEGIN IMMEDIATE')
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future=pool.submit(self.save,self.alice,1)
                try:self.assertEqual(future.result(timeout=1),{'other':None})
                finally:db.rollback()
        finally:db.close()
    def test_new_receipt_rechecks_ban_after_read_phase(self):
        from steward.official_receipts import _validate
        calls=[]
        def validate_and_ban(*args):
            result=_validate(*args);calls.append(1)
            if len(calls)==1:OfficialUploadPolicy(self.path).set_ban(self.channel,self.bob.identity['sub'],True)
            return result
        with patch('steward.official_receipts._validate',side_effect=validate_and_ban):
            with self.assertRaises(ValueError):self.save(self.bob,1)
        self.assertIsNone(self.save(self.alice,1)['other'])

if __name__ == '__main__': unittest.main()
