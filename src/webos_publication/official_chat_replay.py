"""Experimental bounded public-chat replay; fail closed on other operations.

Not a public endpoint or a general official-channel validator. Chess and
non-public policies remain unsupported.
"""
import copy,json,re
from .protocol import CHANNEL_PROFILE, _proof, identifier, jose
from .official_authors import inspect_author_record
from .official_certificates import inspect_certificate
from .official_witness import apply_witness, ZEROS
from .official_content import _id

def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)
def _digest(value):return jose.digest(_canonical(value))
def _account(value):
    return isinstance(value,dict) and set(value)=={'issuer','subject'} and isinstance(value['issuer'],str) and 1<=len(value['issuer'].encode('utf-16-le'))//2<=256 and isinstance(value['subject'],str) and re.fullmatch(r'user:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',value['subject']) is not None
def _account_key(value):return json.dumps([value['issuer'],value['subject']],separators=(',',':'),ensure_ascii=False)

class ExperimentalChatReplay:
    """Owns its in-process state; callers cannot supply a trusted floor."""
    def __init__(self, policy_wire, *, channel, genesis):
        identifier(channel);identifier(genesis)
        policy=_proof(policy_wire,channel)
        expected={'profile','type','channel','stream','validators','publicWrite','players','publicRead'}
        if isinstance(policy,dict) and 'authorAuthorization' in policy:expected=expected|{'authorAuthorization'}
        if not isinstance(policy,dict) or set(policy)!=expected or policy.get('authorAuthorization') not in (None,'actor-epoch/1','actor-epoch/2') or policy['profile']!=CHANNEL_PROFILE or policy['type']!='policy' or policy['channel']!=channel or policy['stream']!='chat' or policy['publicRead'] is not True or type(policy['publicWrite']) is not bool or policy['players'] is not None:raise ValueError('Only publicly readable chat policy is supported')
        parts=policy_wire.split('.')
        if jose.digest(jose.dumps([CHANNEL_PROFILE,'signed-content',parts[0],parts[1]]))!=genesis:raise ValueError('Policy pin mismatch')
        self.__channel=channel;self.__genesis=genesis;self.__validators=copy.deepcopy(policy['validators']);self.__author_policy=policy.get('authorAuthorization');self.__public_write=policy['publicWrite']
        self.__state={'profile':CHANNEL_PROFILE,'channel':channel,'genesisHash':genesis,'height':0,'count':0,'permissionRevision':1,'permissions':[],'authors':[],'acceptedRoot':ZEROS[256],'messages':[],'moves':[]}
        if self.__author_policy:self.__state['authorEpochs']=[]
        self.__head=_digest([CHANNEL_PROFILE,'genesis',genesis])
    @staticmethod
    def _advance_epoch(state,actor,operation):
        rows=state['authorEpochs'];row=next((x for x in rows if x['actor']==actor),None)
        if row:row['epoch']=operation
        else:
            if len(rows)>=16384:raise ValueError('Author epoch capacity reached')
            rows.append({'actor':actor,'epoch':operation})
        rows.sort(key=lambda x:x['actor'])
    def snapshot(self):
        return {'status':'experimental-in-process-public-chat-replay','head':self.__head,'height':self.__state['height'],'state':copy.deepcopy(self.__state)}
    def append(self, blocks):
        if not isinstance(blocks,list) or not 1<=len(blocks)<=64:raise ValueError('Invalid bounded segment')
        channel,genesis,validators=self.__channel,self.__genesis,self.__validators
        state=copy.deepcopy(self.__state);head=self.__head;authors={a['actor']:a for a in state['authors']}
        for block in blocks:
            block=copy.deepcopy(block);cert=inspect_certificate(block,channel=channel,genesis=genesis,validators=validators);header=block['header'];records=block['operations']
            if header['parent']!=head or header['height']!=state['height']+1 or not isinstance(records,list) or not 1<=len(records)<=64 or _digest(records)!=header['operationsRoot']:raise ValueError('Invalid block ancestry or operation commitment')
            for record in records:
                op=inspect_author_record(record,channel=channel)
                kind,data,actor=op['kind'],op['data'],op['actor']
                if kind=='chat':
                    fields={'text','authorEpoch'} if self.__author_policy=='actor-epoch/2' else {'text'}
                    if set(data)!=fields or not isinstance(data['text'],str) or not 1<=len(data['text'].encode('utf-8'))<=4096:raise ValueError('Invalid chat')
                    if self.__author_policy=='actor-epoch/2' and data['authorEpoch'] is not None:identifier(data['authorEpoch'])
                elif kind=='permission':
                    if actor!=channel or set(data) not in ({'subject','write','read'},{'subject','write','read','expectedHead'},{'subject','write','read','expectedHead','account'}) or type(data['write']) is not bool or type(data['read']) is not bool or data['write'] and not data['read'] or 'account' in data and not _account(data['account']):raise ValueError('Invalid permission')
                    _id(data['subject'])
                    if data['subject']==channel or data['subject'] in validators and not data['read'] or 'expectedHead' in data and data['expectedHead']!=head:raise ValueError('Permission conflicts with policy or head')
                elif kind=='moderation':
                    if actor!=channel or set(data) not in ({'message','action'},{'author','action'}) or data['action']!='spam':raise ValueError('Invalid moderation')
                    _id(data.get('message',data.get('author')))
                elif kind=='account-control':
                    if actor!=channel or set(data)!={'account','action'} or not _account(data['account']) or data['action'] not in ('block','unblock'):raise ValueError('Invalid account control')
                else:raise ValueError('Unsupported operation')
                permission=next((p for p in state['permissions'] if p['actor']==actor),None)
                binding=next((p for p in state.get('accountBindings',[]) if p['actor']==actor),None)
                blocked=binding is not None and any(_account_key(a)==_account_key(binding['account']) for a in state.get('accountBlocks',[]))
                if kind!='permission' and actor!=channel and (blocked or (not permission['write'] if permission is not None else not self.__public_write)):raise ValueError('Author lacks write permission')
                prior=authors.get(op['actor']);sequence=prior['sequence']+1 if prior else 1;previous=prior['last'] if prior else None
                epoch=next((x['epoch'] for x in state.get('authorEpochs',[]) if x['actor']==actor),None)
                field='authorEpoch' if self.__author_policy and kind=='chat' else 'permissionRevision';expected_epoch=epoch if field=='authorEpoch' else state['permissionRevision']
                if op['sequence']!=sequence or op['previous']!=previous or field not in op or op[field]!=expected_epoch:raise ValueError('Stale author authorization')
                if self.__author_policy=='actor-epoch/2' and kind=='chat' and data['authorEpoch']!=epoch:raise ValueError('Original message predates access change')
                state['acceptedRoot']=apply_witness(state['acceptedRoot'],op['operation'],record['absence']);authors[op['actor']]={'actor':op['actor'],'sequence':sequence,'last':op['operation']};state['count']+=1
                if kind=='chat':
                    state['messages'].append({'id':op['operation'],'actor':actor,'text':data['text'],'index':state['count']});state['messages']=state['messages'][-64:]
                elif kind=='permission':
                    if 'account' in data:
                        bindings=state.setdefault('accountBindings',[]);bound=next((p for p in bindings if p['actor']==data['subject']),None)
                        if bound and _account_key(bound['account'])!=_account_key(data['account']) or any(_account_key(a)==_account_key(data['account']) for a in state.get('accountBlocks',[])):raise ValueError('Conflicting or blocked account')
                        if bound is None:
                            if len(bindings)>=16384:raise ValueError('Account capacity reached')
                            bindings.append({'actor':data['subject'],'account':data['account']});bindings.sort(key=lambda x:x['actor'])
                    subject=next((p for p in state.get('accountBindings',[]) if p['actor']==data['subject']),None)
                    if (data['read'] or data['write']) and subject and any(_account_key(a)==_account_key(subject['account']) for a in state.get('accountBlocks',[])):raise ValueError('Cannot grant blocked account')
                    existing=next((p for p in state['permissions'] if p['actor']==data['subject']),None)
                    if existing is None:
                        if len(state['permissions'])>=16384:raise ValueError('Permission capacity reached')
                        existing={'actor':data['subject']};state['permissions'].append(existing)
                    existing.update({'write':data['write'],'read':data['read']});state['permissions'].sort(key=lambda p:p['actor']);state['permissionRevision']+=1
                    if self.__author_policy:self._advance_epoch(state,data['subject'],op['operation'])
                elif kind=='account-control':
                    accounts=state.setdefault('accountBlocks',[]);key=_account_key(data['account']);found=next((a for a in accounts if _account_key(a)==key),None)
                    if data['action']=='block':
                        if found or len(accounts)>=16384 or any(_account_key(b['account'])==key and b['actor'] in validators for b in state.get('accountBindings',[])):raise ValueError('Account cannot be blocked')
                        accounts.append(data['account']);accounts.sort(key=lambda a:_account_key(a).encode('utf-16-be'))
                    else:
                        if not found:raise ValueError('Account is not blocked')
                        accounts.remove(found)
                    if self.__author_policy:
                        for binding in state.get('accountBindings',[]):
                            if _account_key(binding['account'])==key:self._advance_epoch(state,binding['actor'],op['operation'])
                    state['permissionRevision']+=1
                else:
                    field='moderation' if 'message' in data else 'moderationAuthors';key='message' if 'message' in data else 'author';items=state.setdefault(field,[])
                    if len(items)>=16384 or any(item[key]==data[key] for item in items):raise ValueError('Duplicate moderation')
                    items.append({key:data[key],'by':actor,'index':state['count']})
            state['authors']=sorted(authors.values(),key=lambda x:x['actor']);state['height']+=1
            if header['count']!=state['count'] or header['stateHash']!=_digest(state):raise ValueError('Block state differs')
            head=cert['head']
        self.__state=state;self.__head=head
        return self.snapshot()

def replay_public_chat(policy_wire, *, channel, genesis, blocks):
    return ExperimentalChatReplay(policy_wire,channel=channel,genesis=genesis).append(blocks)
