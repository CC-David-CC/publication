#!/usr/bin/env python3
import base64,hashlib,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from steward.official_witness import apply_witness,ZEROS

def ident(s):return base64.urlsafe_b64encode(hashlib.sha256(s.encode()).digest()).rstrip(b'=').decode()
def reject(root,op,w):
 try:apply_witness(root,op,w)
 except ValueError:return True
 return False
op=ident('operation');w={'siblings':[]};root=apply_witness(ZEROS[256],op,w)
assert reject(root,op,w)
assert reject(ZEROS[256],op,{'siblings':[{'level':0,'hash':ZEROS[0]}]})
assert reject(ZEROS[256],op,{'siblings':[{'level':2,'hash':ident('x')},{'level':2,'hash':ident('y')}]})
assert reject(ZEROS[256],op,{'siblings':[{'level':256,'hash':ident('x')}]})
assert reject(ZEROS[256],op,{'siblings':[{'level':True,'hash':ident('x')}]})
assert reject(ZEROS[256],op,{'siblings':[{'level':1,'hash':ident('x')}]})
print(json.dumps({'status':'PASS','checks':['replay rejected','empty sibling rejected','duplicate level rejected','invalid level rejected','boolean level rejected','stale witness rejected']}))
