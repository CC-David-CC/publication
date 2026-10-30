#!/usr/bin/env python3
"""Bounded concurrent local HTTP reader/corruption race; disposable state."""
import concurrent.futures,json,socket,statistics,sys,tempfile,threading,time,urllib.error,urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from steward.official_registry import OfficialChannelRegistry
from steward.official_read_http import OfficialReadServer

fixture=json.loads((ROOT/'.build/checks/official-browser-offer-export-r1.json').read_text())['offerFixture'];offer=fixture['offer'];channel=offer['channel']
with tempfile.TemporaryDirectory(prefix='codi-reader-concurrent-') as directory:
 path=Path(directory)/'official.sqlite';store=OfficialChannelRegistry(path);store._db.execute('INSERT INTO official_channels VALUES(?,?,?,?,?,?,?)',(channel,fixture['genesisHash'],fixture['policyWire'],'fixture','',1,0))
 for node in offer['nodes']:store.stage_node(channel,node['cid'],node['wire'])
 store.append_staged_history(channel,expected_head=offer['expectedHead'],history=offer['history'],height=offer['height'],head=offer['head'])
 server=OfficialReadServer(path);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();url='http://127.0.0.1:'+str(server.server_port)+'/official-history?channel='+channel+'&afterHeight=0&afterHead='+offer['expectedHead']+'&limit=1'
 def request():
  try:
   with urllib.request.urlopen(url,timeout=10) as response:return response.status,json.loads(response.read())
  except urllib.error.HTTPError as error:
   with error:return error.code,json.loads(error.read())
 try:
  assert request()[0]==200;latencies=[];refusals=[0];guard=threading.Lock()
  def client(_):
   for _ in range(4):
    start=time.monotonic()
    for attempt in range(20):
     status,value=request()
     if status==200:
      assert value['head']==offer['head'] and len(value['blocks'])==1
      with guard:latencies.append(time.monotonic()-start)
      break
     assert status==503
     with guard:refusals[0]+=1
     time.sleep(.01*(attempt+1))
    else:raise AssertionError('Reader remained saturated')
  with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:list(pool.map(client,range(10)))
  assert len(latencies)==40
  ready=threading.Event();resume=threading.Event();original=server.head_registry._page_from_verified_tip
  def held(*args,**kwargs):
   result=original(*args,**kwargs);ready.set();assert resume.wait(5);return result
  server.head_registry._page_from_verified_tip=held
  with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
   pending=pool.submit(request);assert ready.wait(5);wire=store._db.execute('SELECT wire FROM official_replayed_blocks WHERE channel=? AND height=1',(channel,)).fetchone()[0]
   store._db.execute('UPDATE official_replayed_blocks SET wire=? WHERE channel=? AND height=1',('{}',channel));resume.set();assert pending.result(timeout=10)[0]==409
  server.head_registry._page_from_verified_tip=original;store._db.execute('UPDATE official_replayed_blocks SET wire=? WHERE channel=? AND height=1',(wire,channel));assert request()[0]==200
  held_connections=[]
  try:
   for _ in range(16):
    connection=socket.create_connection(('127.0.0.1',server.server_port),timeout=3);connection.sendall(b'GET / HTTP/1.1\r\nHost: fixture\r\n');held_connections.append(connection)
   deadline=time.monotonic()+5
   while server.connections._value and time.monotonic()<deadline:time.sleep(.01)
   assert server.connections._value==0
   with socket.create_connection(('127.0.0.1',server.server_port),timeout=3) as extra:
    extra.sendall(b'GET / HTTP/1.1\r\nHost: fixture\r\n\r\n');assert b'503 Service Unavailable' in extra.recv(1024)
  finally:
   for connection in held_connections:connection.close()
  deadline=time.monotonic()+5
  while server.connections._value<16 and time.monotonic()<deadline:time.sleep(.01)
  assert server.connections._value==16 and request()[0]==200
  print(json.dumps({'status':'PASS','clients':10,'requests':len(latencies),'capacityRefusals':refusals[0],'medianMs':round(statistics.median(latencies)*1000,2),'maxMs':round(max(latencies)*1000,2),'scope':'single workstation loopback, short browser-signed history, includes retries; corruption race refused'}))
 finally:server.shutdown();server.server_close();thread.join(3);store.close()
