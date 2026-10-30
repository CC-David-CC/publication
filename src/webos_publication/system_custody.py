"""Private, operator-owned SYSTEM signing key and durable channel identity."""
import fcntl,json,os,stat,tempfile
from contextlib import contextmanager
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from .system_publisher import create_policy,identity,listing,post


def _private(path):
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600:raise ValueError('SYSTEM file must be private and owned by the operator')
    return path.read_bytes()

def _atomic(path,data):
    fd,name=tempfile.mkstemp(prefix='.system-',dir=path.parent)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
        os.replace(name,path);directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(directory)
        finally:os.close(directory)
    finally:
        if os.path.exists(name):os.unlink(name)

@contextmanager
def lock(state):
    path=Path(state)/'system-publisher.lock';fd=os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600:raise ValueError('SYSTEM lock must be private and owned by the operator')
        fcntl.flock(fd,fcntl.LOCK_EX);yield
    finally:os.close(fd)

def _key(state,create=False):
    path=Path(state)/'system-owner.pem'
    if not path.exists() and not path.is_symlink():
        if not create:raise ValueError('SYSTEM owner key is missing')
        key=ec.generate_private_key(ec.SECP256R1());_atomic(path,key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    key=serialization.load_pem_private_key(_private(path),password=None)
    if not isinstance(key,ec.EllipticCurvePrivateKey) or not isinstance(key.curve,ec.SECP256R1):raise ValueError('Invalid SYSTEM owner key')
    return key

def initialize(registry,state):
    with lock(state):
        current=registry.public_system_channel();keypath=Path(state)/'system-owner.pem'
        if current and not keypath.exists():raise ValueError('A SYSTEM channel already exists without this owner key')
        key=_key(state,create=True);channel,_=identity(key);path=Path(state)/'system-channel.json'
        if path.exists() or path.is_symlink():config=json.loads(_private(path))
        else:
            if current:raise ValueError('Existing SYSTEM channel metadata is missing')
            config=create_policy(key);_atomic(path,(json.dumps(config,separators=(',',':'))+'\n').encode())
        if not isinstance(config,dict) or set(config)!={'channel','genesisHash','policyWire'} or config['channel']!=channel:raise ValueError('SYSTEM identity does not match the owner key')
        if current and (current['channel']!=channel or current['genesisHash']!=config['genesisHash']):raise ValueError('A different SYSTEM channel is already designated')
        registry.enroll(listing(key,config),now=__import__('time').time_ns()//1000000000);registry.set_system_channel(channel)
        return {'channel':channel,'genesisHash':config['genesisHash']}

def publish(registry,state,text):
    with lock(state):
        key=_key(state);config=json.loads(_private(Path(state)/'system-channel.json'));current=registry.public_system_channel()
        if not current or current['channel']!=config.get('channel') or current['genesisHash']!=config.get('genesisHash'):raise ValueError('SYSTEM identity does not match the official role')
        result=post(registry,key,text);return {'channel':current['channel'],'height':result['height'],'head':result['head']}
