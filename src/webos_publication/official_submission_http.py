"""Experimental HTTP adapter; caller must bind it to loopback only."""
import asyncio
from urllib.parse import urlsplit
from aiohttp import web
from gateway_service.http import offload
from room_service.contract import jose
from .official_submission import OfficialSubmission
from .official_errors import OfficialWriteDenied


class OfficialSubmissionHTTP:
    def __init__(self,service):
        if not isinstance(service,OfficialSubmission):raise ValueError('Explicit official submission service required')
        self.service=service;self.origin=service.access.policy['issuer'];self.host=urlsplit(self.origin).netloc;self.active=0;self.active_by_path={'challenge':0,'use':0};self.use_slots=asyncio.Semaphore(4);self.use_waiting=0

    def app(self):
        app=web.Application(client_max_size=8*1048576,handler_args={'auto_decompress':False,'max_headers':32,'read_bufsize':65536})
        app.router.add_post('/official-ingest/challenge',self.handle);app.router.add_post('/official-ingest/use',self.handle)
        return app

    async def handle(self,request):
        active=False;lane='challenge' if request.path.endswith('/challenge') else 'use'
        try:
            for header in ('Host','Origin','Content-Type','Content-Length'):
                if len(request.headers.getall(header,[]))!=1:raise ValueError('Unique headers required')
            if request.headers['Host']!=self.host or request.headers['Origin']!=self.origin or request.content_type!='application/json' or request.charset not in (None,'utf-8') or request.headers.get('Content-Encoding') or request.headers.get('Transfer-Encoding'):raise ValueError('Wrong request context')
            maximum=16384 if request.path.endswith('/challenge') else 8*1048576
            if request.content_length is None or not 0<request.content_length<=maximum:raise ValueError('Invalid request size')
            # Short challenge requests use their own bounded lane. A burst of
            # long writes must not prevent other clients from starting their
            # authenticated request; both lanes still have hard limits.
            if lane=='challenge':
                if self.active_by_path[lane]>=4:
                    response=web.json_response({'error':'busy'},status=503,headers={'Cache-Control':'no-store','Retry-After':'1'});response.force_close();return response
            else:
                headers=request.headers.getall('Authorization',[]);parts=headers[0].split(' ') if len(headers)==1 else []
                if len(parts)!=3 or parts[0]!='Codi-Official':raise ValueError('Proof required')
                if self.use_waiting>=8:
                    response=web.json_response({'error':'busy'},status=503,headers={'Cache-Control':'no-store','Retry-After':'1'});response.force_close();return response
                self.use_waiting+=1
                try:
                    try:await asyncio.wait_for(self.use_slots.acquire(),timeout=2)
                    except asyncio.TimeoutError:
                        response=web.json_response({'error':'busy'},status=503,headers={'Cache-Control':'no-store','Retry-After':'1'});response.force_close();return response
                finally:self.use_waiting-=1
            self.active+=1;self.active_by_path[lane]+=1;active=True
            async with asyncio.timeout(15):raw=await request.read()
            if len(raw)!=request.content_length:raise ValueError('Truncated request')
            if request.path.endswith('/challenge'):
                value=jose.loads(raw);require_keys={'key','request_sha256'}
                if not isinstance(value,dict) or set(value)!=require_keys:raise ValueError('Invalid challenge')
                result=await offload(self.service.challenge,value['key'],value['request_sha256'])
            else:
                result=await offload(self.service.submit,raw.decode('utf-8'),parts[1],parts[2])
            return web.json_response(result,headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})
        except OfficialWriteDenied:
            response=web.json_response({'error':'channel-write-denied'},status=403,headers={'Cache-Control':'no-store'});response.force_close();return response
        except (ValueError,TypeError,KeyError,UnicodeError,asyncio.TimeoutError):
            response=web.json_response({'error':'Official submission refused'},status=403,headers={'Cache-Control':'no-store'});response.force_close();return response
        finally:
            if active:
                self.active-=1;self.active_by_path[lane]-=1
                if lane=='use':self.use_slots.release()
