"""Immutable compressed sparse-set tree for bounded official writer caching.

The tree produces the existing protocol witnesses. It is a performance cache,
never an authority: callers must compare its root with a verified replay and
publish a new tree only after the corresponding database transaction commits.
"""
import base64
from .official_content import _id
from .official_witness import ZEROS, _hash, _node

LIMIT=32768

def _number(operation):
    _id(operation)
    return int.from_bytes(base64.urlsafe_b64decode(operation+'='),'big')

def _common(a,b):
    return 256-(a^b).bit_length()

def _bit(key,depth):
    return (key>>(255-depth))&1

class _Node:
    __slots__=('key','depth','digest','left','right','memo')
    def __init__(self,key,depth,digest,left=None,right=None):
        self.key=key;self.depth=depth;self.digest=digest;self.left=left;self.right=right;self.memo={}

def _promote(node,to):
    if not 0<=to<=node.depth:raise ValueError('Invalid tree promotion')
    if to in node.memo:return node.memo[to]
    value=node.digest
    for depth in range(node.depth-1,to-1,-1):
        empty=ZEROS[255-depth]
        value=_node(empty,value) if _bit(node.key,depth) else _node(value,empty)
    if len(node.memo)>=4:node.memo.pop(next(iter(node.memo)))
    node.memo[to]=value
    return value

def _leaf(operation,key):
    return _Node(key,256,_hash(['codi-operation-set/1','leaf',operation]))

def _branch(a,b,depth):
    if depth>=a.depth or depth>=b.depth or _common(a.key,b.key)!=depth:raise ValueError('Invalid sparse branch')
    left,right=(b,a) if _bit(a.key,depth) else (a,b)
    if _bit(left.key,depth) or not _bit(right.key,depth):raise ValueError('Invalid sparse ordering')
    digest=_node(_promote(left,depth+1),_promote(right,depth+1))
    return _Node(left.key,depth,digest,left,right)

def _build(entries):
    if not entries:return None
    if len(entries)==1:return _leaf(entries[0][1],entries[0][0])
    depth=_common(entries[0][0],entries[-1][0])
    if depth==256:raise ValueError('Duplicate operation')
    split=next(i for i,(key,_) in enumerate(entries) if _bit(key,depth))
    return _branch(_build(entries[:split]),_build(entries[split:]),depth)

def _insert(node,leaf):
    if node is None:return leaf
    depth=_common(node.key,leaf.key)
    if depth<node.depth:return _branch(node,leaf,depth)
    if node.depth==256:raise ValueError('Duplicate operation')
    if _bit(leaf.key,node.depth):return _branch(node.left,_insert(node.right,leaf),node.depth)
    return _branch(_insert(node.left,leaf),node.right,node.depth)

class SparseWitnessTree:
    __slots__=('_root','count')
    def __init__(self,operations=(),*,_root=None,_count=None):
        if _count is not None:
            self._root=_root;self.count=_count;return
        operations=list(operations)
        if len(operations)>LIMIT:raise ValueError('Sparse cache capacity exceeded')
        entries=sorted((_number(op),op) for op in operations)
        if len({k for k,_ in entries})!=len(entries):raise ValueError('Duplicate operation')
        self._root=_build(entries);self.count=len(entries)
    def root(self):
        return _promote(self._root,0) if self._root else ZEROS[256]
    def witness(self,operation):
        key=_number(operation);node=self._root;siblings=[]
        while node:
            depth=_common(node.key,key)
            if depth<node.depth:
                siblings.append({'level':255-depth,'hash':_promote(node,depth+1)});break
            if node.depth==256:raise ValueError('Duplicate operation')
            right=_bit(key,node.depth);sibling=node.left if right else node.right
            siblings.append({'level':255-node.depth,'hash':_promote(sibling,node.depth+1)})
            node=node.right if right else node.left
        siblings.sort(key=lambda item:item['level'])
        return {'siblings':siblings}
    def added(self,operation):
        if self.count>=LIMIT:raise ValueError('Sparse cache capacity exceeded')
        key=_number(operation);return SparseWitnessTree(_root=_insert(self._root,_leaf(operation,key)),_count=self.count+1)
