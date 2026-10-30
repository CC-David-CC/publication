#!/usr/bin/env python3
"""Compare compressed-tree witnesses with the existing full-tree oracle."""
import hashlib,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'codiserver-server-v0.3.0')]
from steward.protocol import jose
from steward.official_sparse_cache import SparseWitnessTree
from steward.official_witness import apply_witness,ZEROS
from steward.system_publisher import _witness

def operation(n):return jose.b64(hashlib.sha256(str(n).encode()).digest())

class SparseCache(unittest.TestCase):
    def test_incremental_witness_matches_existing_oracle(self):
        values=[operation(i) for i in range(25)];tree=SparseWitnessTree();old=[]
        for op in values:
            witness,root=_witness(old,op);self.assertEqual(tree.root(),root);self.assertEqual(tree.witness(op),witness)
            next_tree=tree.added(op);self.assertEqual(next_tree.root(),apply_witness(root,op,witness));self.assertEqual(tree.root(),root)
            tree=next_tree;old.append(op)
        with self.assertRaises(ValueError):tree.added(values[0])
        with self.assertRaises(ValueError):tree.witness(values[0])
    def test_bulk_build_matches_incremental_and_full_oracle(self):
        values=[operation(i) for i in range(400)];target=operation(1000)
        tree=SparseWitnessTree(values);witness,root=_witness(values,target)
        self.assertEqual(tree.root(),root);self.assertEqual(tree.witness(target),witness)
        next_tree=tree.added(target);self.assertEqual(next_tree.root(),apply_witness(root,target,witness));self.assertEqual(tree.count,400)
        self.assertEqual(SparseWitnessTree(list(reversed(values))).root(),tree.root())
    def test_invalid_and_empty(self):
        self.assertEqual(SparseWitnessTree().root(),ZEROS[256])
        with self.assertRaises(ValueError):SparseWitnessTree(['bad'])
        with self.assertRaises(ValueError):SparseWitnessTree([operation(1),operation(1)])
    def test_writer_cache_binds_history_and_only_publishes_committed_tree(self):
        from steward.official_chat_writer import VerifiedWriterCache
        cache=VerifiedWriterCache();channel=operation(10000);base=[operation(i) for i in range(8)];target=operation(9);root=SparseWitnessTree(base).root()
        witness,candidate=cache.witness(channel,base,target,root)
        self.assertEqual(candidate.root(),apply_witness(root,target,witness));self.assertNotIn(channel,cache._trees)
        cache.publish_tree(channel,[*base,target],candidate,candidate.root())
        changed=base+[operation(10)];changed_root=SparseWitnessTree(changed).root()
        witness,replacement=cache.witness(channel,changed,operation(11),changed_root)
        self.assertEqual(replacement.root(),apply_witness(changed_root,operation(11),witness))
        self.assertEqual(cache._trees[channel][0],tuple([*base,target]))
        with self.assertRaises(ValueError):cache.witness(channel,changed,operation(11),root)
        with self.assertRaises(ValueError):cache.publish_tree(channel,changed,replacement,root)

if __name__=='__main__':unittest.main()
