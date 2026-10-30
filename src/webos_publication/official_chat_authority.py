"""Read operator-provisioned official validator keys; never create on requests."""
import os,stat,threading
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from .official_content import _id
from .official_chat_writer import OfficialChatWriter,VerifiedWriterCache
from .official_registry import OfficialChannelRegistry

class OfficialChatAuthority:
    def __init__(self,database,key_dir):
        self.database=Path(database);self.key_dir=Path(key_dir);self._cache=VerifiedWriterCache();self._lock=threading.Lock()
        info=self.key_dir.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700 or self.key_dir.is_symlink():raise ValueError('Private owned validator key directory required')
    def __call__(self,channel,genesis,record,actor_binding,principal):
        return self._run('append',channel,genesis,record,actor_binding,principal)
    def note_denial(self,channel,genesis,record,actor_binding,principal):
        return self._run('note_denial',channel,genesis,record,actor_binding,principal)
    def _run(self,method,channel,genesis,record,actor_binding,principal):
        with self._lock:return self._run_locked(method,channel,genesis,record,actor_binding,principal)
    def _run_locked(self,method,channel,genesis,record,actor_binding,principal):
        _id(channel);_id(genesis);path=self.key_dir/(channel+'.pem');fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>4096:raise ValueError('Private validator key required')
            raw=os.read(fd,4097)
        finally:os.close(fd)
        key=serialization.load_pem_private_key(raw,password=None)
        if not isinstance(key,ec.EllipticCurvePrivateKey) or not isinstance(key.curve,ec.SECP256R1):raise ValueError('P-256 validator key required')
        registry=OfficialChannelRegistry(self.database)
        try:return getattr(OfficialChatWriter(registry,key,cache=self._cache),method)(channel,genesis,record,actor_binding,principal)
        finally:registry.close()
