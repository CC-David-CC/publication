"""Structural screening for untrusted official-channel scratch nodes.

This does not establish ancestry, block authenticity, authorization, or
acceptance. Those require replay under the channel's signed protocol.
"""
import base64
import json
import math
import re

ID=re.compile(r'^[A-Za-z0-9_-]{43}$')
PROFILE='codi-channel-content/1'

def _integer(value, minimum, maximum):
    return type(value) in (int,float) and minimum <= value <= maximum and math.isfinite(value) and value == int(value)

def _id(v):
    if not isinstance(v,str) or not ID.fullmatch(v): raise ValueError('Invalid content identifier')
    try: raw=base64.urlsafe_b64decode(v+'=')
    except Exception as e: raise ValueError('Invalid content identifier') from e
    if len(raw)!=32 or base64.urlsafe_b64encode(raw).rstrip(b'=').decode()!=v: raise ValueError('Noncanonical identifier')

def _pairs(pairs):
    out={}
    for key,value in pairs:
        if key in out: raise ValueError('Duplicate node field')
        out[key]=value
    return out

def _link(value):
    if not isinstance(value,dict) or set(value)!={'cid','bytes','height'}: raise ValueError('Invalid content link')
    _id(value['cid'])
    if not _integer(value['bytes'],1,2*1048576) or not _integer(value['height'],0,2): raise ValueError('Invalid content link bounds')

def validate_scratch_node(wire,channel,genesis):
    _id(channel);_id(genesis)
    if not isinstance(wire,str) or not 1<=len(wire.encode())<=16384: raise ValueError('Invalid node bytes')
    try: node=json.loads(wire,object_pairs_hook=_pairs,parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid JSON number')))
    except (TypeError,ValueError,RecursionError) as e: raise ValueError('Invalid node JSON') from e
    if not isinstance(node,dict) or node.get('profile')!=PROFILE: raise ValueError('Invalid content profile')
    kind=node.get('kind')
    if kind=='head':
        if set(node)!={'profile','kind','channel','genesisHash','height','head','parent','block'} or node['channel']!=channel or node['genesisHash']!=genesis or not _integer(node['height'],1,9007199254740991): raise ValueError('Invalid scoped head')
        _id(node['head']);_id(node['block'])
        if node['parent'] is not None:_id(node['parent'])
    elif kind=='chunk':
        if set(node)!={'profile','kind','data'} or not isinstance(node['data'],str) or not re.fullmatch(r'[A-Za-z0-9_-]+',node['data']) or len(node['data'])>10923: raise ValueError('Invalid chunk')
        try: raw=base64.urlsafe_b64decode(node['data']+'='*((-len(node['data']))%4))
        except Exception as e:raise ValueError('Invalid chunk encoding') from e
        if not 1<=len(raw)<=8192 or base64.urlsafe_b64encode(raw).rstrip(b'=').decode()!=node['data']:raise ValueError('Noncanonical chunk')
    elif kind=='parts':
        if set(node)!={'profile','kind','links'} or not isinstance(node['links'],list) or not 1<=len(node['links'])<=64:raise ValueError('Invalid parts')
        for link in node['links']:_link(link)
        if len({x['height'] for x in node['links']})!=1 or sum(x['bytes'] for x in node['links'])>2*1048576:raise ValueError('Invalid parts bounds')
    elif kind=='blob':
        if set(node)!={'profile','kind','bytes','tree'} or not _integer(node['bytes'],1,2*1048576):raise ValueError('Invalid blob')
        _link(node['tree'])
        if node['tree']['bytes']!=node['bytes']:raise ValueError('Blob size differs')
    else:raise ValueError('Unknown node kind')
    return kind


def reconstruct_scratch_history(get_node, *, channel, genesis, history, height, head, max_blocks=64, max_nodes=4096, max_bytes=8*1048576):
    """Reconstruct a bounded candidate segment; never treats it as accepted.

    The caller must pin the channel and subsequently replay every returned
    block using the authoritative signature and transition verifier.
    """
    import hashlib
    _id(channel);_id(genesis);_id(history);_id(head)
    if type(height) is not int or height<1 or type(max_blocks) is not int or not 1<=max_blocks<=256 or type(max_nodes) is not int or not 1<=max_nodes<=32768 or type(max_bytes) is not int or not 1<=max_bytes<=64*1048576:raise ValueError('Invalid reconstruction bounds')
    seen=set(); consumed=0
    def node(cid):
        nonlocal consumed
        _id(cid)
        wire=get_node(cid)
        if not isinstance(wire,str):raise ValueError('Missing staged node')
        raw=wire.encode('utf-8')
        if base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b'=').decode()!=cid:raise ValueError('Stored node hash mismatch')
        if cid not in seen:
            seen.add(cid);consumed+=len(raw)
            if len(seen)>max_nodes or consumed>max_bytes:raise ValueError('Reconstruction allowance exceeded')
        validate_scratch_node(wire,channel,genesis)
        return json.loads(wire,object_pairs_hook=_pairs)
    def blob(cid):
        root=node(cid)
        if root['kind']!='blob':raise ValueError('Expected block blob')
        def walk(link):
            n=node(link['cid']); level=link['height']
            if level==0:
                if n['kind']!='chunk':raise ValueError('Expected chunk')
                data=n['data']; out=base64.urlsafe_b64decode(data+'='*((-len(data))%4))
            else:
                if n['kind']!='parts' or any(x['height']!=level-1 for x in n['links']):raise ValueError('Broken parts ancestry')
                out=b''.join(walk(child) for child in n['links'])
            if len(out)!=link['bytes']:raise ValueError('Content length mismatch')
            return out
        raw=walk(root['tree'])
        if len(raw)!=root['bytes']:raise ValueError('Blob length mismatch')
        try: block=json.loads(raw.decode('utf-8'),object_pairs_hook=_pairs,parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid number')))
        except (UnicodeError,ValueError,RecursionError) as e:raise ValueError('Invalid block JSON') from e
        if not isinstance(block,dict) or set(block)!={'header','operations','prepare','commit'} or not isinstance(block['header'],dict):raise ValueError('Invalid block envelope')
        return block
    blocks=[];cursor=history;expected_height=height;expected_head=head
    while cursor is not None and len(blocks)<max_blocks:
        n=node(cursor)
        if n['kind']!='head' or n['height']!=expected_height or n['head']!=expected_head:raise ValueError('History locator mismatch')
        block=blob(n['block']);header=block['header']
        if header.get('channel')!=channel or header.get('genesisHash')!=genesis or header.get('height')!=expected_height:raise ValueError('Block scope or height mismatch')
        _id(header.get('parent'));blocks.append({'history':cursor,'head':n['head'],'block':block})
        expected_head=header['parent'];expected_height-=1;cursor=n['parent']
        if (expected_height==0)!=(cursor is None):raise ValueError('History boundary mismatch')
    blocks.reverse()
    return {'status':'untrusted-reconstructed-segment','blocks':blocks,'previousHistory':cursor,'previousHead':expected_head,'previousHeight':expected_height,'nodes':len(seen),'bytes':consumed}
