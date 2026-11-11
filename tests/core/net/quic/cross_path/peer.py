"""Published aioquic HTTP3 behind a second UDP ingress with original egress.

The relay changes no encrypted bytes: B forwards an actually received datagram
and its source metadata to the same server connection; replies use socket A.
This exercises an initiator's required acceptance of a cross-path response.
"""
import argparse,asyncio,os
from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnectionId
from aioquic.quic.events import ConnectionIdIssued,ConnectionIdRetired

class Peer(QuicConnectionProtocol):
 def __init__(self,*a,**kw):
  super().__init__(*a,**kw);self.http=H3Connection(self._quic);self.requests=0;self.initial_cid=self._quic.host_cid;self.preferred_cid=os.urandom(8);self.preferred_token=os.urandom(16);self.preferred_retired=False
  # Configure an optional preferred address with a genuinely issued sequence1
  # CID. The installed TLS/packet/parser implementation remains unchanged.
  self._quic._host_cids.append(QuicConnectionId(cid=self.preferred_cid,sequence_number=1,stateless_reset_token=self.preferred_token,was_sent=True));self._quic._host_cid_seq=2
  self._quic._events.append(ConnectionIdIssued(connection_id=self.preferred_cid))
  original=self._quic._serialize_transport_parameters
  def parameters():
   port=self._transport.get_extra_info('sockname')[1]
   value=bytes([127,0,0,1])+port.to_bytes(2,'big')+bytes(18)+bytes([8])+self.preferred_cid+self.preferred_token
   return original()+bytes([0x0d,len(value)])+value
  self._quic._serialize_transport_parameters=parameters
 def quic_event_received(self,event):
  if isinstance(event,ConnectionIdRetired) and event.connection_id==self.preferred_cid:self.preferred_retired=True
  for received in self.http.handle_event(event):
   if isinstance(received,HeadersReceived):
    self.requests+=1;self.http.send_headers(received.stream_id,[(b':status',b'200')]);self.http.send_data(received.stream_id,b'OK',end_stream=True);self.transmit()

class Relay(asyncio.DatagramProtocol):
 def __init__(self,server,peers):self.server=server;self.peers=peers;self.received=0
 def datagram_received(self,data,source):
  if self.received==0:
   assert len(self.peers)==1 and data[0]&0x80==0
   assert self.peers[0].preferred_retired,'preferred address CID was never retired'
   assert data[1:9] not in (self.peers[0].initial_cid,self.peers[0].preferred_cid),'new destination reused original/declined CID'
  self.received+=1;self.server.datagram_received(data,source)

class CheckedEgress:
 def __init__(self,transport,relay):self.transport=transport;self.relay=relay;self.corrupted=0;self.duplicates=0
 def __getattr__(self,name):return getattr(self.transport,name)
 def sendto(self,data,address):
  if self.relay.received and data and data[0]&0x80==0:
   bad=bytearray(data);bad[-1]^=1;self.transport.sendto(bytes(bad),address);self.corrupted+=1
   self.transport.sendto(data,address);self.duplicates+=1
  self.transport.sendto(data,address)

async def main(args):
 config=QuicConfiguration(is_client=False,alpn_protocols=['h3']);config.load_cert_chain(args.fixtures+'/server.pem',args.fixtures+'/server-key.pem')
 peers=[]
 def factory(*a,**kw):peer=Peer(*a,**kw);peers.append(peer);return peer
 server=await serve('127.0.0.1',0,configuration=config,create_protocol=factory)
 relay=Relay(server,peers);transport,_=await asyncio.get_running_loop().create_datagram_endpoint(lambda:relay,local_addr=('127.0.0.1',0))
 egress=CheckedEgress(server._transport,relay);server._transport=egress
 a=egress.get_extra_info('sockname')[1];b=transport.get_extra_info('sockname')[1]
 print(f'READY 127.0.0.1:{a} 127.0.0.1:{b}',flush=True)
 try:
  until=asyncio.get_running_loop().time()+20
  while sum(p.requests for p in peers)<2 and asyncio.get_running_loop().time()<until:await asyncio.sleep(.01)
  await asyncio.sleep(.2)
  assert len(peers)==1 and peers[0].requests==2 and peers[0].preferred_retired
  assert relay.received>0 and egress.corrupted>0 and egress.duplicates>0
  print('PASS independent cross-path response with corrupted/duplicate UDP copies',flush=True)
 finally:transport.close();server.close()

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--fixtures',required=True);asyncio.run(main(p.parse_args()))
