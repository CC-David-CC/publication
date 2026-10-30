"""Experimental bounded loopback transport to the private ingest worker."""
import json
import urllib.error
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None


class LocalOfficialTransport:
    def __init__(self,port,token):
        if type(port) is not int or not 1<=port<=65535 or not isinstance(token,str) or len(token)!=64 or any(c not in '0123456789abcdef' for c in token):raise ValueError('Explicit loopback port and private token required')
        self._url=f'http://127.0.0.1:{port}/official-ingest-authorized';self._token=token;self._opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())

    def __call__(self,raw,principal):
        if not isinstance(raw,str) or not 1<=len(raw.encode())<=8*1048576:raise ValueError('Invalid bounded official offer')
        identity=principal.identity;body=json.dumps({'offer':raw,'uploader':{'kind':identity['kind'],'sub':identity['sub']}},separators=(',',':')).encode()
        if len(body)>9*1048576:raise ValueError('Official transport envelope too large')
        request=urllib.request.Request(self._url,data=body,headers={'Content-Type':'application/json','Authorization':'Bearer '+self._token},method='POST')
        try:
            with self._opener.open(request,timeout=30) as response:
                data=response.read(4097)
                if response.status!=200 or len(data)>4096:raise ValueError('Official ingest unavailable')
        except (urllib.error.URLError,TimeoutError,OSError) as error:
            if isinstance(error,urllib.error.HTTPError):error.close()
            raise ValueError('Official ingest unavailable or rejected') from error
        value=json.loads(data)
        if not isinstance(value,dict) or set(value)!={'height','head'}:raise ValueError('Invalid official ingest receipt')
        return value
