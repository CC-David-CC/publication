"""Disposable/local composition of experimental official-history services.

Not a production launcher: callers must provision protected files, proxy,
limits and issuer policy before considering any deployment.
"""
import asyncio
import functools
import secrets
import threading
from aiohttp import ClientError,ClientSession,ClientTimeout,TCPConnector,web
from .official_access import OfficialAccess
from .official_ingest_http import OfficialIngestServer
from .official_local_transport import LocalOfficialTransport
from .official_read_http import OfficialReadServer
from .official_submission import OfficialSubmission
from .official_submission_http import OfficialSubmissionHTTP
from .official_upload_policy import OfficialUploadPolicy
from .official_chat_authority import OfficialChatAuthority


class OfficialRuntime:
    def __init__(self,*,database,ledger,issuer_policy,base_path='',port=0,validator_key_dir=None,receipts=False):
        if type(port) is not int or not 0<=port<=65535:raise ValueError('Invalid loopback port')
        if type(receipts) is not bool:raise ValueError('Explicit receipt setting required')
        self.listen_port=port
        self.database=database;self.access=OfficialAccess(ledger,issuer_policy,base_path=base_path);self.policy=OfficialUploadPolicy(database);self.chat_writer=OfficialChatAuthority(database,validator_key_dir) if validator_key_dir is not None else None
        self.receipts=None
        if receipts:
            from .official_access import connection
            from .official_receipts import checkpoint,check_schema
            with connection(database) as db:check_schema(db)
            self.receipts=functools.partial(checkpoint,database)
        self.reader=None;self.worker=None;self.reader_thread=None;self.worker_thread=None;self.runner=None;self.client=None;self.port=None;self.lifecycle=asyncio.Lock();self.read_slots=asyncio.Semaphore(8)

    async def start(self):
        async with self.lifecycle:
            if self.runner is not None:raise ValueError('Runtime already started')
            try:
                token=secrets.token_hex(32);self.worker=OfficialIngestServer(self.database,token);self.worker_thread=threading.Thread(target=self.worker.serve_forever,daemon=True);self.worker_thread.start()
                self.reader=OfficialReadServer(self.database);self.reader_thread=threading.Thread(target=self.reader.serve_forever,daemon=True);self.reader_thread.start()
                service=OfficialSubmission(self.access,authorize=self.policy,forward=LocalOfficialTransport(self.worker.server_port,token),write_chat=self.chat_writer,write_receipt=self.receipts);http=OfficialSubmissionHTTP(service)
                self.client=ClientSession(timeout=ClientTimeout(total=30),connector=TCPConnector(limit=8),trust_env=False,auto_decompress=False)
                app=http.app();app.router.add_get('/internal/official-health',self._health);app.router.add_get('/official-head',self._read);app.router.add_get('/official-history',self._read);app.router.add_get('/official-directory',self._read);app.router.add_get('/official-channel',self._read)
                self.runner=web.AppRunner(app,access_log=None);await self.runner.setup();site=web.TCPSite(self.runner,'127.0.0.1',self.listen_port);await site.start();self.port=site._server.sockets[0].getsockname()[1]
                return self
            except BaseException:
                await self._close_unlocked();raise

    async def _health(self,request):
        from urllib.parse import urlsplit
        if len(request.headers.getall('Host',[]))!=1 or request.headers['Host']!=urlsplit(self.access.policy['issuer']).netloc:raise web.HTTPForbidden()
        if not self.worker_thread or not self.worker_thread.is_alive() or not self.reader_thread or not self.reader_thread.is_alive():raise web.HTTPServiceUnavailable()
        try:
            async with self.client.get('http://127.0.0.1:'+str(self.reader.server_port)+'/official-directory?after=&limit=1',allow_redirects=False) as response:
                if response.status!=200:raise web.HTTPServiceUnavailable()
                await response.read()
        except (ClientError,TimeoutError):raise web.HTTPServiceUnavailable()
        return web.json_response({'version':'codi-official-health/1','identity':self.access.policy},headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})

    async def _read(self,request):
        from urllib.parse import urlsplit
        if len(request.headers.getall('Host',[]))!=1 or request.headers['Host']!=urlsplit(self.access.policy['issuer']).netloc:raise web.HTTPForbidden()
        if len(request.headers.getall('Origin',[]))>1:raise web.HTTPForbidden()
        origin=request.headers.get('Origin')
        if origin and origin!=self.access.policy['issuer']:raise web.HTTPForbidden()
        try:
            async with asyncio.timeout(2):await self.read_slots.acquire()
        except TimeoutError:raise web.HTTPServiceUnavailable(text='Official reader busy')
        try:
            try:
                async with self.client.get('http://127.0.0.1:'+str(self.reader.server_port)+request.raw_path,allow_redirects=False) as upstream:
                    chunks=[];size=0
                    async for chunk in upstream.content.iter_chunked(65536):
                        size+=len(chunk)
                        if size>9*1048576:raise web.HTTPBadGateway()
                        chunks.append(chunk)
                    return web.Response(status=upstream.status,body=b''.join(chunks),content_type='application/json',headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})
            except (ClientError,TimeoutError):raise web.HTTPServiceUnavailable(text='Official reader unavailable')
        finally:self.read_slots.release()

    async def close(self):
        async with self.lifecycle:await self._close_unlocked()

    async def _close_unlocked(self):
        if self.runner:await self.runner.cleanup();self.runner=None
        if self.client:await self.client.close();self.client=None
        for server,thread in ((self.reader,self.reader_thread),(self.worker,self.worker_thread)):
            if server:
                if thread and thread.is_alive():await asyncio.to_thread(server.shutdown)
                server.server_close()
                if thread:await asyncio.to_thread(thread.join,3)
        self.reader=self.worker=self.reader_thread=self.worker_thread=None;self.port=None
