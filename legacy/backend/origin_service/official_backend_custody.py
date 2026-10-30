"""Verify an expected local systemd process owns the official TCP listener.

This is one preflight, not a substitute for immutable package and policy custody.
"""
import hashlib,os,re,stat
from pathlib import Path

def verify_listener(*,systemctl,unit,unit_path,unit_sha256,uid,argv,port):
 if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,80}\.service',unit):raise ValueError('Invalid service name')
 if not re.fullmatch(r'[0-9a-f]{64}',unit_sha256) or type(uid) is not int or uid<=0 or type(port) is not int or not 1024<=port<=65535:raise ValueError('Invalid custody pins')
 path=Path(unit_path);st=path.lstat()
 if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=0o644 or path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest()!=unit_sha256:raise ValueError('Unit custody mismatch')
 status=dict(line.split('=',1) for line in systemctl('show',unit,'-p','ActiveState','-p','MainPID','-p','ControlGroup','-p','LoadState','-p','FragmentPath','-p','DropInPaths','-p','NeedDaemonReload').splitlines())
 if status.get('LoadState')!='loaded' or status.get('FragmentPath')!=str(path) or status.get('DropInPaths')!='' or status.get('NeedDaemonReload')!='no':raise ValueError('Loaded unit custody mismatch')
 if status.get('ActiveState')!='active' or not status.get('MainPID','').isdigit() or int(status['MainPID'])<=1 or not status.get('ControlGroup','').startswith('/'):raise ValueError('Official service is not active')
 pid=int(status['MainPID']);proc=Path('/proc')/str(pid);fields=dict(line.split(':',1) for line in (proc/'status').read_text().splitlines() if ':' in line)
 if int(fields['Uid'].split()[0])!=uid:raise ValueError('Official process uid mismatch')
 command=(proc/'cmdline').read_bytes().split(b'\0');command=[x.decode('utf-8') for x in command if x]
 if command!=list(argv):raise ValueError('Official process command mismatch')
 groups=(proc/'cgroup').read_text().splitlines();expected=status['ControlGroup']
 if not any(line.split(':',2)[-1]==expected for line in groups):raise ValueError('Official process cgroup mismatch')
 target=f'0100007F:{port:04X}';inodes=set()
 for row in Path('/proc/net/tcp').read_text().splitlines()[1:]:
  parts=row.split()
  if len(parts)>9 and parts[1]==target and parts[3]=='0A':inodes.add(parts[9])
 owned=set()
 for fd in (proc/'fd').iterdir():
  try:link=os.readlink(fd)
  except FileNotFoundError:continue
  match=re.fullmatch(r'socket:\[(\d+)\]',link)
  if match:owned.add(match.group(1))
 if not inodes.intersection(owned):raise ValueError('Official process does not own the loopback listener')
 return pid
