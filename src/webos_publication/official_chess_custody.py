"""Operator-only provisioning of a featured game with two private player keys."""
import fcntl,json,os,stat,tempfile,time
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from .official_content import _id
from .official_registry import OfficialChannelRegistry
from .protocol import CHANNEL_PROFILE,KEY_VERSION,TYPE,_proof,jose
from .system_publisher import _proof as sign_proof,identity

def _read_private(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=0o600 or st.st_size>16384:raise ValueError('Private operator file required')
        return os.read(fd,16385)
    finally:os.close(fd)

def _create_private(path,data):
    # The final name must never expose a partially written key or metadata file.
    # The caller holds the directory's provisioning lock, and generated key
    # names are unique; do not replace an existing final file.
    fd,name=tempfile.mkstemp(prefix='.featured-private-',dir=path.parent)
    try:
        view=memoryview(data)
        while view:view=view[os.write(fd,view):]
        os.fsync(fd)
        os.close(fd);fd=-1
        if os.path.lexists(path):raise FileExistsError(path)
        os.rename(name,path)
        directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
        try:os.fsync(directory)
        finally:os.close(directory)
    finally:
        if fd!=-1:os.close(fd)
        if os.path.lexists(name):os.unlink(name)

def _remove_interrupted_private_files(directory):
    for item in directory.iterdir():
        if not item.name.startswith('.featured-private-'):continue
        info=item.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600:raise ValueError('Invalid interrupted provisioning file')
        item.unlink()

def load_key(directory,identifier):
    directory=Path(directory).absolute();info=directory.lstat()
    if directory.resolve()!=directory or not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('Private owned player key directory required')
    _id(identifier);key=serialization.load_pem_private_key(_read_private(directory/(identifier+'.pem')),password=None)
    if not isinstance(key,ec.EllipticCurvePrivateKey) or not isinstance(key.curve,ec.SECP256R1) or identity(key)[0]!=identifier:raise ValueError('Wrong private player key')
    return key

def verify_invitation(value):
    if not isinstance(value,dict) or set(value)!={'version','label','game','chat','proof'} or value['version']!='codi-device-chess-match/2' or not isinstance(value['label'],str) or not 1<=len(value['label'])<=48:raise ValueError('Invalid featured match')
    configs=[]
    for name in ('game','chat'):
        item=value[name]
        if not isinstance(item,dict) or set(item)!={'version','config'} or item['version']!='codi-device-member-invite/1' or not isinstance(item['config'],dict) or set(item['config'])!={'channel','genesisHash','policyWire'}:raise ValueError('Invalid match channel')
        c=item['config'];_id(c['channel']);_id(c['genesisHash']);configs.append(c)
    game,chat=configs
    if game['channel']==chat['channel']:raise ValueError('Game and chat must be separate')
    gp=_proof(game['policyWire'],game['channel']);cp=_proof(chat['policyWire'],chat['channel'])
    if not isinstance(gp,dict) or not isinstance(cp,dict) or gp.get('stream')!='chess' or gp.get('publicRead') is not True or not isinstance(gp.get('players'),dict) or set(gp['players'])!={'white','black'} or cp.get('stream')!='chat' or cp.get('publicRead') is not True or cp.get('publicWrite') is not True:raise ValueError('Invalid match policies')
    for c in configs:
        parts=c['policyWire'].split('.')
        if len(parts)!=3 or jose.digest(jose.dumps([CHANNEL_PROFILE,'signed-content',parts[0],parts[1]]))!=c['genesisHash']:raise ValueError('Match policy pin differs')
    header,outer,_,_=jose.inspect(value['proof'],TYPE,8192)
    if not isinstance(header,dict) or not isinstance(outer,dict) or set(header)!={'alg','typ'} or set(outer)!={'version','channel','key','purpose','body'} or outer['version']!=KEY_VERSION or outer['channel']!=gp['players']['white'] or outer['purpose']!='chess.match':raise ValueError('Invalid match signer')
    key=outer['key']
    if jose.digest(jose.dumps([KEY_VERSION,jose.thumbprint(key)]))!=outer['channel']:raise ValueError('Invalid match signer')
    body=jose.verify(value['proof'],key,TYPE,8192)['body'];expected={'version':value['version'],'label':value['label'],'game':game['genesisHash'],'chat':chat['genesisHash']}
    if body!=expected:raise ValueError('Match signature differs')
    return value

def provision(database,key_dir,chat_channel,*,rotate_from=None):
    directory=Path(key_dir);info=directory.lstat();_id(chat_channel)
    if directory.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('Private owned validator key directory required')
    lock=os.open(directory/'.featured-game.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        info=os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600:raise ValueError('Invalid game provisioning lock')
        fcntl.flock(lock,fcntl.LOCK_EX);_remove_interrupted_private_files(directory);registry=OfficialChannelRegistry(database)
        try:
            chat=registry.public_channel(chat_channel)
            if not chat:raise ValueError('Enabled official chat required')
            chat_policy=_proof(chat['policyWire'],chat_channel)
            if chat_policy.get('stream')!='chat' or chat_policy.get('publicWrite') is not True:raise ValueError('Writable official chat required')
            registry._db.execute('CREATE TABLE IF NOT EXISTS official_featured_game (version INTEGER PRIMARY KEY CHECK(version=1), invitation TEXT NOT NULL)')
            registry._db.execute('CREATE TABLE IF NOT EXISTS official_featured_game_history (channel TEXT PRIMARY KEY, invitation TEXT NOT NULL, predecessor TEXT UNIQUE)')
            old=registry._db.execute('SELECT invitation FROM official_featured_game WHERE version=1').fetchone()
            previous=verify_invitation(json.loads(old[0])) if old else None
            if rotate_from is not None:
                _id(rotate_from)
                if not previous:raise ValueError('No featured game to rotate')
                if previous['game']['config']['channel']!=rotate_from:
                    successor=registry._db.execute('SELECT channel FROM official_featured_game_history WHERE predecessor=?',(rotate_from,)).fetchone()
                    if successor and successor[0]==previous['game']['config']['channel'] and previous['chat']['config']['channel']==chat_channel:return previous
                    raise ValueError('Featured game changed before rotation')
                replay=registry._load_replay(rotate_from)
                if not replay.board.is_game_over(claim_draw=False) and len(replay.state['moves'])<2048:raise ValueError('Featured game is not finished')
            meta=directory/('featured-game.json' if rotate_from is None else 'featured-next-'+rotate_from+'.json')
            if meta.exists():
                value=json.loads(_read_private(meta))
                if not isinstance(value,dict) or set(value)!={'version','game','black','chat'} or not isinstance(value['game'],dict) or set(value['game'])!={'channel','genesisHash','policyWire'} or value['chat']!=chat_channel or value['version']!='codi-featured-game-custody/1':raise ValueError('Featured game configuration changed')
                game=value['game'];_id(game['channel']);_id(game['genesisHash']);_id(value['black']);white=load_key(directory,game['channel']);black=load_key(directory,value['black'])
            else:
                white=ec.generate_private_key(ec.SECP256R1());black=ec.generate_private_key(ec.SECP256R1());channel=identity(white)[0];black_id=identity(black)[0]
                policy={'profile':CHANNEL_PROFILE,'type':'policy','channel':channel,'stream':'chess','validators':[channel],'publicWrite':False,'players':{'white':channel,'black':black_id},'publicRead':True};wire=sign_proof(white,'checkpoint',policy);parts=wire.split('.');game={'channel':channel,'genesisHash':jose.digest(jose.dumps([CHANNEL_PROFILE,'signed-content',parts[0],parts[1]])),'policyWire':wire};value={'version':'codi-featured-game-custody/1','game':game,'black':black_id,'chat':chat_channel}
                for key in (white,black):_create_private(directory/(identity(key)[0]+'.pem'),key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
                _create_private(meta,json.dumps(value,separators=(',',':')).encode());fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
                try:os.fsync(fd)
                finally:os.close(fd)
            policy=_proof(game['policyWire'],game['channel'])
            if policy.get('stream')!='chess' or policy.get('validators')!=[game['channel']] or policy.get('players')!={'white':game['channel'],'black':identity(black)[0]}:raise ValueError('Invalid featured game policy')
            existing=registry.get(game['channel'])
            if existing:
                if not existing['enabled'] or existing['genesisHash']!=game['genesisHash'] or existing['policyWire']!=game['policyWire']:raise ValueError('Featured game does not match the stored policy')
            else:
                now=int(time.time());listing={'profile':'codi-channel-listing/1','category':'user',**game,'label':'Featured game','description':'Stockfish versus Stockfish','issued':now,'expires':now+180};registry.enroll(sign_proof(white,'checkpoint',listing),now=now)
            game_invite={'version':'codi-device-member-invite/1','config':game};chat_invite={'version':'codi-device-member-invite/1','config':{k:chat[k] for k in ('channel','genesisHash','policyWire')}};label='Stockfish vs Stockfish';body={'version':'codi-device-chess-match/2','label':label,'game':game['genesisHash'],'chat':chat['genesisHash']}
            result=verify_invitation({'version':body['version'],'label':label,'game':game_invite,'chat':chat_invite,'proof':sign_proof(white,'chess.match',body)})
            if previous and rotate_from is None:
                if previous['game']!=result['game'] or previous['chat']!=result['chat']:raise ValueError('Another featured game is already configured')
            encoded=json.dumps(result,separators=(',',':'),ensure_ascii=False)
            registry._db.execute('BEGIN IMMEDIATE')
            try:
                if previous:
                    registry._db.execute('INSERT OR IGNORE INTO official_featured_game_history(channel,invitation,predecessor) VALUES(?,?,NULL)',(previous['game']['config']['channel'],old[0]))
                registry._db.execute('INSERT OR IGNORE INTO official_featured_game_history(channel,invitation,predecessor) VALUES(?,?,?)',(game['channel'],encoded,rotate_from))
                registry._db.execute('INSERT INTO official_featured_game(version,invitation) VALUES(1,?) ON CONFLICT(version) DO UPDATE SET invitation=excluded.invitation',(encoded,))
                registry._db.execute('COMMIT')
            except BaseException:
                registry._db.execute('ROLLBACK');raise
            return result
        finally:registry.close()
    finally:os.close(lock)
