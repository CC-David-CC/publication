"""Verify a public chess channel from its signed genesis and legal moves.

The server accepts only signed, quorum-certified blocks and reconstructs every
position. Chat stays in its own channel. This is an official storage verifier,
not an engine or a source of authority for unsigned positions.
"""
import copy,re
import chess
from .protocol import CHANNEL_PROFILE,_proof,identifier,jose
from .official_authors import inspect_author_record
from .official_certificates import inspect_certificate
from .official_chat_replay import _digest
from .official_witness import apply_witness,ZEROS

class OfficialChessReplay:
    def __init__(self,policy_wire,*,channel,genesis):
        identifier(channel);identifier(genesis);policy=_proof(policy_wire,channel)
        if not isinstance(policy,dict) or set(policy)!={'profile','type','channel','stream','validators','publicWrite','players','publicRead'} or policy['profile']!=CHANNEL_PROFILE or policy['type']!='policy' or policy['channel']!=channel or policy['stream']!='chess' or policy['publicRead'] is not True or policy['publicWrite'] is not False:raise ValueError('Public chess policy required')
        players=policy['players'];validators=policy['validators']
        if not isinstance(players,dict) or set(players)!={'white','black'} or players['white']==players['black']:raise ValueError('Two distinct chess players required')
        for player in players.values():identifier(player)
        if not isinstance(validators,list) or not 1<=len(validators)<=31 or validators!=sorted(set(validators)):raise ValueError('Invalid chess validators')
        for voter in validators:identifier(voter)
        parts=policy_wire.split('.')
        if jose.digest(jose.dumps([CHANNEL_PROFILE,'signed-content',parts[0],parts[1]]))!=genesis:raise ValueError('Chess policy pin mismatch')
        self.channel=channel;self.genesis=genesis;self.validators=copy.deepcopy(validators);self.players=copy.deepcopy(players)
        self.state={'profile':CHANNEL_PROFILE,'channel':channel,'genesisHash':genesis,'height':0,'count':0,'permissionRevision':1,'permissions':[],'authors':[],'acceptedRoot':ZEROS[256],'messages':[],'moves':[]}
        self.head=_digest([CHANNEL_PROFILE,'genesis',genesis]);self.board=chess.Board()

    def snapshot(self):
        return {'status':'verified-public-chess-replay','head':self.head,'height':self.state['height'],'state':copy.deepcopy(self.state)}

    def append(self,blocks):
        if not isinstance(blocks,list) or not 1<=len(blocks)<=64:raise ValueError('Invalid bounded segment')
        channel,genesis=self.channel,self.genesis;state=copy.deepcopy(self.state);head=self.head;board=self.board.copy(stack=True);authors={a['actor']:a for a in state['authors']}
        for block in blocks:
            block=copy.deepcopy(block);cert=inspect_certificate(block,channel=channel,genesis=genesis,validators=self.validators);header=block['header'];records=block['operations']
            if header['parent']!=head or header['height']!=state['height']+1 or not isinstance(records,list) or not 1<=len(records)<=64 or _digest(records)!=header['operationsRoot']:raise ValueError('Invalid chess block ancestry or commitment')
            for record in records:
                op=inspect_author_record(record,channel=channel);actor=op['actor'];data=op['data']
                if op['kind']!='move' or set(data)!={'san','position'} or not isinstance(data['san'],str) or not re.fullmatch(r'[A-Za-z0-9=+#xO\-]{1,32}',data['san']) or data['san']=='--':raise ValueError('Canonical chess move required')
                identifier(data['position'])
                if len(state['moves'])>=2048 or board.is_game_over(claim_draw=False):raise ValueError('Chess game has ended')
                if actor!=self.players['white' if board.turn==chess.WHITE else 'black']:raise ValueError('Wrong chess player turn')
                if data['position']!=_digest([CHANNEL_PROFILE,'board',genesis,board.fen(en_passant='legal'),state['moves']]):raise ValueError('Move belongs to another board position')
                prior=authors.get(actor)
                if op['sequence']!=(prior['sequence'] if prior else 0)+1 or op['previous']!=(prior['last'] if prior else None) or op.get('permissionRevision')!=state['permissionRevision']:raise ValueError('Stale chess authorization')
                try:move=board.parse_san(data['san'])
                except ValueError as error:raise ValueError('Illegal chess move') from error
                if board.san(move)!=data['san']:raise ValueError('Noncanonical chess move')
                board.push(move);state['moves'].append(data['san']);state['acceptedRoot']=apply_witness(state['acceptedRoot'],op['operation'],record['absence']);authors[actor]={'actor':actor,'sequence':op['sequence'],'last':op['operation']};state['count']+=1
            state['authors']=sorted(authors.values(),key=lambda x:x['actor']);state['height']+=1
            if header['count']!=state['count'] or header['stateHash']!=_digest(state):raise ValueError('Chess block state differs')
            head=cert['head']
        self.state=state;self.head=head;self.board=board
        return self.snapshot()
