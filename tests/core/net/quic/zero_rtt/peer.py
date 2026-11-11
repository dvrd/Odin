#!/usr/bin/env python3
"""Independent aioquic1.3.0 HTTP3 full/resumed/0RTT peer; trusted synthetic CA."""
import argparse, asyncio
from aioquic.asyncio import connect,serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived,DataReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted

class Peer(QuicConnectionProtocol):
 def __init__(self,*a,**kw):
  super().__init__(*a,**kw);self.http=H3Connection(self._quic);self.server=not self._quic.configuration.is_client;self.queues={};self.handshake=None;self.handshake_event=asyncio.Event();self.requests=0;self.early_requests=0
 def quic_event_received(self,event):
  if isinstance(event,HandshakeCompleted):self.handshake=event;self.handshake_event.set()
  for e in self.http.handle_event(event):
   if self.server:
    if isinstance(e,HeadersReceived):
     self.requests+=1
     if self.handshake is None:self.early_requests+=1
     self.http.send_headers(e.stream_id,[(b':status',b'200')]);self.http.send_data(e.stream_id,b'OK',end_stream=True);self.transmit()
   else:self.queues.setdefault(e.stream_id,asyncio.Queue()).put_nowait(e)
 async def get(self,path=b'/allow',status=b'200'):
  stream=self._quic.get_next_available_stream_id();self.http.send_headers(stream,[(b':method',b'GET'),(b':scheme',b'https'),(b':authority',b'localhost'),(b':path',path)],end_stream=True);self.transmit()
  body=b'';observed=None
  while True:
   event=await asyncio.wait_for(self.queues.setdefault(stream,asyncio.Queue()).get(),10)
   if isinstance(event,HeadersReceived):observed=dict(event.headers)[b':status'];ended=event.stream_ended
   else:body+=event.data;ended=event.stream_ended
   if ended:break
  assert observed==status,(observed,status)
  if status==b'200':assert body==b'OK',body
  await asyncio.wait_for(self.handshake_event.wait(),5)
  return self.handshake

async def main(args):
 cfg=QuicConfiguration(is_client=args.mode=='client',alpn_protocols=['h3']);cfg.load_verify_locations(args.fixtures+'/root.pem');cfg.server_name='localhost'
 if args.scenario=='mtls':cfg.load_cert_chain(args.fixtures+'/client.pem',args.fixtures+'/client-key.pem')
 if args.mode=='server':
  cfg.load_cert_chain(args.fixtures+'/server.pem',args.fixtures+'/server-key.pem');tickets={};peers=[]
  def factory(*a,**kw):p=Peer(*a,**kw);peers.append(p);return p
  def store(ticket):tickets[ticket.ticket]=ticket
  def fetch(label):return None if args.scenario=='reject' else tickets.get(label)
  server=await serve('127.0.0.1',0,configuration=cfg,create_protocol=factory,session_ticket_handler=store,session_ticket_fetcher=fetch,retry=args.scenario=='retry')
  print('READY 127.0.0.1:'+str(server._transport.get_extra_info('sockname')[1]),flush=True)
  until=asyncio.get_running_loop().time()+20
  while sum(p.requests for p in peers)<2 and asyncio.get_running_loop().time()<until:await asyncio.sleep(.01)
  await asyncio.sleep(.1);server.close()
  assert sum(p.requests for p in peers)==2
  assert len(peers)==2
  assert not peers[0].handshake.session_resumed
  assert peers[1].handshake.session_resumed==(args.scenario!='reject')
  assert peers[1].handshake.early_data_accepted==(args.scenario in ('accepted','retry'))
  assert sum(p.early_requests for p in peers)==(1 if args.scenario in ('accepted','retry') else 0)
  print('PASS aioquic-server',args.scenario,flush=True);return
 tickets=[]
 async with connect('127.0.0.1',args.port,configuration=cfg,create_protocol=Peer,session_ticket_handler=tickets.append) as peer:
  first=await peer.get();assert not first.session_resumed;await asyncio.sleep(.1)
 assert tickets,'native server did not issue NST'
 saved=tickets[-1];assert saved.max_early_data_size==(None if args.scenario=='default' else 0xffffffff)
 count=3 if args.scenario=='replay' else 2
 for index in range(1,count):
  cfg.session_ticket=saved
  async with connect('127.0.0.1',args.port,configuration=cfg,create_protocol=Peer,wait_connected=False) as peer:
   path=b'/deny' if args.scenario=='deny' else b'/allow'
   result=await peer.get(path)
   assert result.session_resumed
   assert result.early_data_accepted==(index==1 and args.scenario!='default'),result
 print('PASS aioquic-client',args.scenario,flush=True)

if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('mode',choices=['server','client']);parser.add_argument('--fixtures',required=True);parser.add_argument('--port',type=int,default=0);parser.add_argument('--scenario',default='accepted',choices=['accepted','reject','replay','deny','default','retry','mtls']);asyncio.run(main(parser.parse_args()))
