"""Journaled issuer-only official authorization switch; no store or route install."""
import http.client,json,secrets,subprocess,time
from urllib.parse import urlsplit
from pathlib import Path
from origin_service import maintenance
JOURNAL='codi-official-issuer-transition/1'

def slot(path,name):return Path(path).parent/name
def write(op,path,value):op.atomic(path,(json.dumps(value,indent=2)+'\n').encode())
def pair(current,before,after):
 stable=lambda c:{k:v for k,v in c.items() if k!='officialChannels'}
 if current not in (before,after) or stable(before)!=stable(after) or before.get('maintenance')!=1:raise ValueError('Official switch cannot change other configuration')
 for c in (before,after):
  if 'officialChannels' in c and type(c['officialChannels']) is not bool:raise ValueError('Boolean official switch required')

def check_backend(op,c,port):
 if type(port) is not int or not 1024<=port<=65535:raise ValueError('Valid unprivileged backend port required')
 expected=json.loads(op.read_owned(Path(c['stateRoot'])/'public/origin-discovery.json',0,0o444))['identity']
 if expected.get('issuer')!=c['origin']:raise ValueError('Issuer policy origin differs from managed origin')
 host=urlsplit(c['origin']).netloc
 connection=http.client.HTTPConnection('127.0.0.1',port,timeout=3)
 try:
  connection.request('GET','/internal/official-health',headers={'Host':host})
  response=connection.getresponse();raw=response.read(32769)
  if response.status!=200 or len(raw)>32768:raise ValueError('Official backend health unavailable')
  value=json.loads(raw)
  if value!={'version':'codi-official-health/1','identity':expected}:raise ValueError('Official backend issuer policy mismatch')
 finally:connection.close()
 return True

def apply(op,c,path):
 op.atomic(Path(c['unitDir'])/op.unit(c,'issuer'),op.render(c,'issuer'),0o644);write(op,path,c);op.systemctl('daemon-reload')
def start(op,c,roles,path):
 maintenance.guard_epoch(op,c,path)
 if roles:
  if op.systemctl('show',op.unit(c,'issuer'),'-p','ActiveState','--value').strip()=='failed':op.systemctl('reset-failed',op.unit(c,'issuer'))
  op.systemctl('start',op.unit(c,'issuer'));op.ready(c,['issuer'])
def clear(path):slot(path,'maintenance.json').unlink();maintenance.sync_directory(Path(path).parent)
def revert(op,path,j):
 before=j['before'];op.installed(before);j['phase']='rolling-back';write(op,slot(path,'maintenance.json'),j)
 op.stop(before,['issuer']);apply(op,before,path);start(op,before,j['activeRoles'],path);clear(path)
 return {'status':'official-switch-rolled-back','enabled':before.get('officialChannels',False),'otherRolesRestarted':False}

def configure(op,c,path,enabled,*,backend_port=None,backend_custody=None,phase=lambda _:None):
 if type(enabled) is not bool:raise ValueError('Boolean official switch required')
 from origin_service import deployment
 maintenance.guard(op,c,path);after={k:v for k,v in c.items() if k!='officialChannels'}
 if enabled:
  from origin_service.official_backend_custody import verify_listener
  if not isinstance(backend_custody,dict) or set(backend_custody)!={'unit','unit_path','unit_sha256','uid','argv'}:raise ValueError('Official backend custody pins required')
  verify_listener(systemctl=op.systemctl,port=backend_port,**backend_custody)
  check_backend(op,c,backend_port)
  after['officialChannels']=True
 pair(c,c,after);op.installed(after);deployment.syntax(op,after,path)
 if after==c:return {'status':'official-switch-already-current','enabled':enabled}
 active=['issuer'] if 'issuer' in deployment.active(op,c) else []
 j={'version':JOURNAL,'id':secrets.token_hex(16),'phase':'prepared','before':c,'after':after,'activeRoles':active,'created':int(time.time())};write(op,slot(path,'maintenance.json'),j);phase('prepared')
 try:
  op.stop(c,['issuer']);j['phase']='switching';write(op,slot(path,'maintenance.json'),j);phase('switching');apply(op,after,path)
  j['phase']='starting';write(op,slot(path,'maintenance.json'),j);phase('starting');start(op,after,active,path)
  committed={**j,'phase':'committed'};write(op,slot(path,'maintenance.json'),committed);j=committed;phase('committed');clear(path)
  return {'status':'official-switch-configured','enabled':enabled,'otherRolesRestarted':False}
 except (OSError,ValueError,KeyError,subprocess.SubprocessError) as error:
  if j['phase']=='committed':raise ValueError('Official switch committed; finish recover-operation') from error
  try:return revert(op,path,j)
  except (OSError,ValueError,subprocess.SubprocessError) as failure:raise ValueError('Official switch recovery incomplete; retain journal: '+str(failure)) from failure

def recover(op,c,path):
 j=json.loads(op.read_owned(slot(path,'maintenance.json'),0,0o600))
 if set(j)!={'version','id','phase','before','after','activeRoles','created'} or j['version']!=JOURNAL or j['phase'] not in ('prepared','switching','starting','rolling-back','committed') or j['activeRoles'] not in ([],['issuer']):raise ValueError('Invalid official switch journal')
 pair(c,j['before'],j['after'])
 if j['phase']!='committed':return revert(op,path,j)
 after=j['after'];op.installed(after);op.stop(after,['issuer']);apply(op,after,path);start(op,after,j['activeRoles'],path);clear(path)
 return {'status':'official-switch-committed-recovered','enabled':after.get('officialChannels',False),'otherRolesRestarted':False}
