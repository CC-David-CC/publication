"""Operator-held player and validator keys publish verified chess moves."""
import copy,json,re,secrets
import chess
from .official_authors import inspect_author_record
from .official_chat_replay import _digest
from .official_chess_replay import OfficialChessReplay
from .official_witness import apply_witness
from .protocol import CHANNEL_PROFILE,_proof
from .system_publisher import _proof as sign_proof,_witness,identity
from .protocol import jose

def post_move(registry,validator_key,player_key,san):
    if not isinstance(san,str) or not re.fullmatch(r'[A-Za-z0-9=+#xO\-]{1,32}',san) or san=='--':raise ValueError('Canonical chess move required')
    channel=identity(validator_key)[0];actor=identity(player_key)[0];db=registry._db;db.execute('BEGIN IMMEDIATE')
    try:
        row=db.execute('SELECT genesis_hash,policy_wire,enabled FROM official_channels WHERE channel=?',(channel,)).fetchone()
        if not row or not row[2]:raise ValueError('Official chess channel is not enabled')
        genesis,wire=row[:2];policy=_proof(wire,channel)
        if policy.get('validators')!=[channel]:raise ValueError('Publisher requires sole operator validator')
        replay=registry._load_replay(channel)
        if not isinstance(replay,OfficialChessReplay):raise ValueError('Official chess channel required')
        before=replay.snapshot();state=copy.deepcopy(before['state']);board=replay.board
        if len(state['moves'])>=2048 or board.is_game_over(claim_draw=False):raise ValueError('Chess game has ended')
        if actor!=replay.players['white' if board.turn==chess.WHITE else 'black']:raise ValueError('Wrong player key')
        try:move=board.parse_san(san)
        except ValueError as error:raise ValueError('Illegal chess move') from error
        if board.san(move)!=san:raise ValueError('Noncanonical chess move')
        position=_digest([CHANNEL_PROFILE,'board',genesis,board.fen(en_passant='legal'),state['moves']]);proposal=sign_proof(player_key,'operation',{'profile':CHANNEL_PROFILE,'type':'proposal','target':channel,'nonce':secrets.token_urlsafe(18),'kind':'move','data':{'san':san,'position':position}})
        parts=proposal.split('.');op=jose.digest(jose.dumps([CHANNEL_PROFILE,'signed-content',parts[0],parts[1]]));prior=next((a for a in state['authors'] if a['actor']==actor),None);sequence=(prior['sequence'] if prior else 0)+1
        authorization=sign_proof(player_key,'operation',{'profile':CHANNEL_PROFILE,'type':'authorize','target':channel,'proposal':op,'sequence':sequence,'previous':prior['last'] if prior else None,'permissionRevision':state['permissionRevision']})
        existing=[]
        for (old,) in db.execute('SELECT wire FROM official_replayed_blocks WHERE channel=? ORDER BY height',(channel,)):
            for record in json.loads(old)['operations']:existing.append(inspect_author_record(record,channel=channel)['operation'])
        witness,root=_witness(existing,op)
        if root!=state['acceptedRoot']:raise ValueError('Stored game history changed')
        record={'proposal':proposal,'authorization':authorization,'absence':witness};state['acceptedRoot']=apply_witness(state['acceptedRoot'],op,witness);state['moves'].append(san);state['count']+=1;state['height']+=1
        if prior:prior.update(sequence=sequence,last=op)
        else:state['authors'].append({'actor':actor,'sequence':sequence,'last':op});state['authors'].sort(key=lambda a:a['actor'])
        records=[record];header={'profile':CHANNEL_PROFILE,'channel':channel,'genesisHash':genesis,'height':state['height'],'parent':before['head'],'count':state['count'],'operationsRoot':_digest(records),'stateHash':_digest(state),'round':0}
        def vote(phase):return sign_proof(validator_key,'checkpoint',{'profile':CHANNEL_PROFILE,'type':'vote','channel':channel,'genesisHash':genesis,'phase':phase,'header':_digest(header)})
        block={'header':header,'operations':records,'prepare':[vote('prepare')],'commit':[vote('commit')]};after=replay.append([block]);db.execute('INSERT INTO official_replayed_blocks(channel,height,wire) VALUES(?,?,?)',(channel,state['height'],json.dumps(block,separators=(',',':'),ensure_ascii=False,allow_nan=False)));db.execute('COMMIT');return after
    except BaseException:
        db.execute('ROLLBACK');raise
