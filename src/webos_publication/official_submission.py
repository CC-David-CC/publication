"""Experimental authorization boundary for official-history submissions.

The policy and transport are supplied by the server operator, never the
request. Authentication alone does not confer channel access.
"""
from .official_access import OfficialAccess
from .official_content import _id
from .official_errors import OfficialWriteDenied
from room_service.contract import jose,require


class OfficialSubmission:
    def __init__(self,access,*,authorize,forward,write_chat=None,write_receipt=None):
        if not isinstance(access,OfficialAccess) or not callable(authorize) or not callable(forward) or write_chat is not None and not callable(write_chat) or write_receipt is not None and not callable(write_receipt):raise ValueError('Explicit access, channel policy and storage transport required')
        self.access=access;self.authorize=authorize;self.forward=forward;self.write_chat=write_chat;self.write_receipt=write_receipt

    def challenge(self,key,request_sha):
        return self.access.challenge(key,request_sha)

    def submit(self,raw,confirmation,proof):
        principal=self.access.consume(raw,confirmation,proof)
        require(principal.identity.get('kind')=='registered','Registered identity required')
        value=jose.loads(raw)
        if isinstance(value,dict) and set(value)=={'channel','genesisHash','receipt'}:
            require(self.write_receipt is not None,'Official receipts unavailable')
            _id(value['channel']);_id(value['genesisHash'])
            receipt=value['receipt'];require(isinstance(receipt,dict) and set(receipt)=={'height','head'},'Exact receipt required')
            if self.authorize(principal,value['channel']) is not True:raise OfficialWriteDenied('Official channel access denied')
            return self.write_receipt(channel=value['channel'],genesis=value['genesisHash'],height=receipt['height'],head=receipt['head'],principal=principal)
        if isinstance(value,dict) and set(value)=={'channel','genesisHash','record','actorBinding'}:
            require(self.write_chat is not None and principal.identity.get('kind')=='registered','Registered official chat writer required')
            _id(value['channel']);_id(value['genesisHash'])
            if self.authorize(principal,value['channel']) is not True:
                if callable(getattr(self.write_chat,'note_denial',None)):self.write_chat.note_denial(value['channel'],value['genesisHash'],value['record'],value['actorBinding'],principal)
                raise OfficialWriteDenied('Official channel write denied')
            return self.write_chat(value['channel'],value['genesisHash'],value['record'],value['actorBinding'],principal)
        require(isinstance(value,dict) and set(value)=={'channel','expectedHead','nodes','history','height','head'},'Exact official offer required')
        _id(value['channel'])
        if self.authorize(principal,value['channel']) is not True:raise OfficialWriteDenied('Official channel upload denied')
        return self.forward(raw,principal)
