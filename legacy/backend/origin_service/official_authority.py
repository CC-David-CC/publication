"""Experimental request-bound live-session confirmation for official offers.

This establishes identity only. The receiving service must validate its own
one-use challenge, policy, request bytes and official-channel authorization.
The native launcher exposes it only when explicitly enabled.
"""
import secrets
from urllib.parse import urlsplit

from codiauth import jose
from codiauth.service import Failure

CHALLENGE='/api/v1/official-ingest/challenge'
AUTHORIZE='/api/v1/official-ingest/authorize'
CONFIRMATION_TYPE='codi-official-ingest-identity+jwt'


class OfficialAuthority:
    def __init__(self, issuer, application=None):
        self.issuer=issuer
        self.application=issuer if application is None else application
        self.audience=issuer.c.origin+issuer.base_path+'/official-ingest'

    def challenge(self, data):
        issuer=self.issuer
        if not isinstance(data,dict) or set(data)!={'key','path'} or data['path']!=issuer.base_path+AUTHORIZE:
            raise Failure(400,'Invalid official authorization challenge')
        key=jose.public_jwk(jose.load_public(data['key']))
        with issuer.lock:
            issuer.cleanup()
            if len(issuer.challenges)>=issuer.c.max_challenges:raise Failure(429,'Challenge capacity reached')
            nonce=secrets.token_urlsafe(32);issuer.challenges[nonce]={'key':key,'path':data['path'],'expires':issuer.now()+60}
        return {'nonce':nonce,'expires_at':issuer.now()+60}

    def authorize(self, data, key, proof, authorization):
        if not isinstance(data,dict) or set(data)!={'nonce','request_sha256'}:
            raise Failure(400,'Exact official request digest required')
        for field in ('nonce','request_sha256'):
            if not isinstance(data[field],str) or len(data[field])!=43 or len(jose.unb64(data[field]))!=32:
                raise Failure(400,'Invalid official request identifier')
        issuer=self.issuer
        with issuer.lock:
            checked=issuer.continue_session({},key,proof,'/api/v1/renew',authorization)
            identity=checked['identity'];session=issuer.sessions[jose.digest(authorization[5:])];now=issuer.now()
            expiry=min(now+30,checked['expires_at'],session['deadline'])
            if expiry<=now:raise Failure(401,'Session expired')
            claims={'v':1,'iss':issuer.c.origin,'aud':self.audience,'identity':identity,'iat':now,'exp':expiry,
                    'jti':secrets.token_urlsafe(32),'nonce':data['nonce'],'request_sha256':data['request_sha256'],'session_deadline':session['deadline']}
            return {'confirmation':jose.sign(claims,issuer.key,CONFIRMATION_TYPE,issuer.kid),'expires_at':expiry}

    def __call__(self, env, start):
        issuer=self.issuer;path=env.get('PATH_INFO','/')
        if path not in (CHALLENGE,AUTHORIZE):return self.application(env,start)
        try:
            if env.get('HTTP_HOST')!=urlsplit(issuer.c.origin).netloc or env.get('HTTP_ORIGIN')!=issuer.c.origin:raise Failure(403,'Unexpected origin')
            if env.get('REQUEST_METHOD')!='POST':raise Failure(405,'POST required')
            if env.get('CONTENT_TYPE','').split(';')[0].strip()!='application/json' or env.get('HTTP_TRANSFER_ENCODING'):raise Failure(415,'Plain JSON required')
            length=env.get('CONTENT_LENGTH','')
            if not length.isascii() or not length.isdecimal() or len(length)>5 or not 0<int(length)<=16384:raise Failure(413,'Bounded request required')
            # Many signed chat and delivery requests can share one upstream
            # address. Keep a separate bounded budget for this endpoint rather
            # than applying the login-sized budget to the entire group.
            issuer.throttle(('official-challenge-ip:' if path==CHALLENGE else 'official-authorize-ip:')+env.get('REMOTE_ADDR','unknown'),limit=20*issuer.c.rate_per_minute)
            raw=env['wsgi.input'].read(int(length))
            if len(raw)!=int(length):raise Failure(400,'Truncated request')
            data=jose.loads(raw)
            if path==CHALLENGE:result=self.challenge(data)
            else:
                body,key,proof=issuer.consume_proof(data,AUTHORIZE)
                result=self.authorize(body,key,proof,env.get('HTTP_AUTHORIZATION',''))
            return issuer.json_response(start,200,result)
        except Failure as error:return issuer.json_response(start,error.status,{'error':error.message})
        except (ValueError,TypeError,KeyError,UnicodeError):return issuer.json_response(start,400,{'error':'Invalid official authorization request'})
        except Exception:return issuer.json_response(start,500,{'error':'Official authorization unavailable'})
