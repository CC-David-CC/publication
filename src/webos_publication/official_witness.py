"""Verify sparse operation-set witnesses with the standard SHA-256 library.

Witness validation is necessary but not sufficient for accepted history.
"""
import base64
import hashlib
import json
from .official_content import _id

PROFILE='codi-operation-set/1'
def _hash(value):
    raw=json.dumps(value,separators=(',',':'),ensure_ascii=False).encode('utf-8')
    return base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b'=').decode('ascii')
def _node(left,right):return _hash([PROFILE,'node',left,right])
def empty_roots():
    zeros=[_hash([PROFILE,'empty'])]
    for _ in range(256):zeros.append(_node(zeros[-1],zeros[-1]))
    return tuple(zeros)
ZEROS=empty_roots()

def apply_witness(root, operation, witness):
    _id(root);_id(operation)
    if not isinstance(witness,dict) or set(witness)!={'siblings'} or not isinstance(witness['siblings'],list) or len(witness['siblings'])>256:raise ValueError('Invalid operation witness')
    siblings={};previous=-1
    for row in witness['siblings']:
        if not isinstance(row,dict) or set(row)!={'level','hash'} or type(row['level']) is not int or not previous<row['level']<256:raise ValueError('Invalid witness sibling')
        _id(row['hash']);level=row['level']
        if row['hash']==ZEROS[level]:raise ValueError('Noncanonical witness sibling')
        siblings[level]=row['hash'];previous=level
    data=base64.urlsafe_b64decode(operation+'=');absent=ZEROS[0];inserted=_hash([PROFILE,'leaf',operation])
    for level in range(256):
        sibling=siblings.get(level,ZEROS[level]);right=(data[31-level//8]>>(level%8))&1
        absent=_node(sibling,absent) if right else _node(absent,sibling)
        inserted=_node(sibling,inserted) if right else _node(inserted,sibling)
    if absent!=root:raise ValueError('Operation already accepted or witness is stale')
    return inserted
