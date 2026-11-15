#!/usr/bin/env python3
"""Real browser history, cache invalidation and corruption checks on loopback."""
import json,sys,tempfile,threading,urllib.request,urllib.error
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from steward.official_registry import OfficialChannelRegistry
from steward.official_read_http import OfficialReadServer

fixture=json.loads((ROOT/'.build/checks/official-browser-offer-export-r1.json').read_text())['offerFixture'];offer=fixture['offer'];channel=offer['channel']
with tempfile.TemporaryDirectory(prefix='codi-head-cache-') as temp:
    path=Path(temp)/'official.sqlite';store=OfficialChannelRegistry(path);store._db.execute('INSERT INTO official_channels VALUES(?,?,?,?,?,?,?)',(channel,fixture['genesisHash'],fixture['policyWire'],'fixture','',1,0))
    for node in offer['nodes']:store.stage_node(channel,node['cid'],node['wire'])
    store.append_staged_history(channel,expected_head=offer['expectedHead'],history=offer['history'],height=offer['height'],head=offer['head'])
    server=OfficialReadServer(path);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();url='http://127.0.0.1:'+str(server.server_port)+'/official-head?channel='+channel
    calls=[0];original=server.head_registry._load_replay
    def counted(*args):calls[0]+=1;return original(*args)
    server.head_registry._load_replay=counted
    page_url='http://127.0.0.1:'+str(server.server_port)+'/official-history?channel='+channel+'&afterHeight=0&afterHead='+offer['expectedHead']+'&limit=1'
    current_url='http://127.0.0.1:'+str(server.server_port)+'/official-history?channel='+channel+'&afterHeight='+str(offer['height'])+'&afterHead='+offer['head']+'&limit=32'
    directory_url='http://127.0.0.1:'+str(server.server_port)+'/official-directory?after=&limit=1'
    channel_url='http://127.0.0.1:'+str(server.server_port)+'/official-channel?channel='+channel
    def fetch(target=url):
        try:
            with urllib.request.urlopen(target,timeout=10) as response:return response.status,json.loads(response.read())
        except urllib.error.HTTPError as error:
            with error:return error.code,json.loads(error.read())
    try:
        assert fetch()[1]['head']==offer['head'] and calls[0]==1
        status,directory=fetch(directory_url);assert status==200 and len(directory['items'])==1 and directory['items'][0]['channel']==channel and directory['items'][0]['category']=='official' and directory['next'] is None
        status,entry=fetch(channel_url);assert status==200 and entry['items']==directory['items'] and entry['next'] is None
        for _ in range(10):assert fetch()[1]['head']==offer['head']
        assert calls[0]==1
        for _ in range(10):
            status,page=fetch(page_url);assert status==200 and page['head']==offer['head'] and len(page['blocks'])==1
        with urllib.request.urlopen(current_url,timeout=10) as response:
            body=response.read();idle=json.loads(body)
            assert response.status==200 and idle['complete'] and idle['blocks']==[] and idle['head']==offer['head']
            idle_bytes=len(body)
        assert calls[0]==1
        store.set_enabled(channel,False);assert fetch()[0]==404
        assert fetch(page_url)[0]==404
        assert fetch(directory_url)[1]['items']==[]
        assert fetch(channel_url)[0]==404
        store.set_enabled(channel,True);assert fetch()[1]['head']==offer['head'] and calls[0]==2
        wire=store._db.execute('SELECT wire FROM official_replayed_blocks WHERE channel=? AND height=1',(channel,)).fetchone()[0]
        store._db.execute('UPDATE official_replayed_blocks SET wire=? WHERE channel=? AND height=1',('{}',channel));assert fetch()[0]==409 and fetch(page_url)[0]==409
        store._db.execute('UPDATE official_replayed_blocks SET wire=? WHERE channel=? AND height=1',(wire,channel));assert fetch()[1]['head']==offer['head']
        store._db.execute('UPDATE official_channels SET label=? WHERE channel=?',('changed',channel))
        def concurrent_disable(*args):
            result=original(*args);other=OfficialChannelRegistry(path)
            try:other.set_enabled(channel,False)
            finally:other.close()
            return result
        server.head_registry._load_replay=concurrent_disable;assert fetch()[0]==404
    finally:
        server.shutdown();server.server_close();thread.join(3);store.close()
print(json.dumps({'status':'PASS','idleHistoryResponseBodyBytes':idle_bytes,'scope':'local response body only; HTTP/TLS headers and network overhead excluded'}))
