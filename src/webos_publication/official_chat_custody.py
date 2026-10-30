"""Provision a single operator-owned official chat channel.

This is an operator action, never a request handler. Private keys are held in
an owner-only directory and are not returned in the public descriptor.
"""
import fcntl,json,os,stat,time
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from .official_chat_writer import initialize
from .official_registry import OfficialChannelRegistry
from .official_content import _id
from .protocol import CHANNEL_PROFILE,jose
from .system_publisher import _proof,identity

def provision(database,key_dir,*,label='General chess chat',description='Discuss chess'):
    directory=Path(key_dir);info=directory.lstat()
    if directory.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('Private owned validator key directory required')
    if label!='General chess chat' or description!='Discuss chess':raise ValueError('Unexpected channel configuration')
    lock=os.open(directory/'.provision.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        st=os.fstat(lock)
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=0o600:raise ValueError('Invalid provisioning lock')
        fcntl.flock(lock,fcntl.LOCK_EX);meta=directory/'general-chess.json'
        if meta.exists():
            fd=os.open(meta,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
            try:
                st=os.fstat(fd)
                if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=0o600 or st.st_size>16384:raise ValueError('Invalid provisioning metadata')
                config=json.loads(os.read(fd,16385))
            finally:os.close(fd)
            if set(config)!={'channel','genesisHash','policyWire'}:raise ValueError('Invalid provisioning metadata')
        else:
            key=ec.generate_private_key(ec.SECP256R1());channel,_=identity(key)
            body={'profile':CHANNEL_PROFILE,'type':'policy','channel':channel,'stream':'chat','validators':[channel],'publicWrite':True,'players':None,'publicRead':True,'authorAuthorization':'actor-epoch/2'}
            wire=_proof(key,'checkpoint',body);parts=wire.split('.');config={'channel':channel,'genesisHash':jose.digest(jose.dumps([CHANNEL_PROFILE,'signed-content',parts[0],parts[1]])),'policyWire':wire}
            fd=os.open(directory/(channel+'.pem'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
            try:os.write(fd,key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));os.fsync(fd)
            finally:os.close(fd)
            fd=os.open(meta,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
            try:os.write(fd,json.dumps(config,separators=(',',':')).encode());os.fsync(fd)
            finally:os.close(fd)
            fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
            try:os.fsync(fd)
            finally:os.close(fd)
        _id(config['channel']);_id(config['genesisHash']);keyfile=directory/(config['channel']+'.pem');fd=os.open(keyfile,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            st=os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=0o600 or st.st_size>4096:raise ValueError('Invalid validator key')
            key=serialization.load_pem_private_key(os.read(fd,4097),password=None)
        finally:os.close(fd)
        if not isinstance(key,ec.EllipticCurvePrivateKey) or not isinstance(key.curve,ec.SECP256R1) or identity(key)[0]!=config['channel']:raise ValueError('Wrong validator key')
        registry=OfficialChannelRegistry(database)
        try:
            initialize(registry._db);existing=registry.get(config['channel'])
            if existing:
                if existing['genesisHash']!=config['genesisHash'] or existing['policyWire']!=config['policyWire'] or existing['label']!=label or not existing['enabled']:raise ValueError('Existing official channel differs')
                return registry.public_channel(config['channel'])
            if registry._db.execute('SELECT 1 FROM official_channels WHERE label=?',(label,)).fetchone():raise ValueError('Official channel label already used')
            now=int(time.time());listing={'profile':'codi-channel-listing/1','category':'user',**config,'label':label,'description':description,'issued':now,'expires':now+180}
            registry.enroll(_proof(key,'checkpoint',listing),now=now);return registry.public_channel(config['channel'])
        finally:registry.close()
    finally:os.close(lock)
