#!/usr/bin/env python3
"""Independent stdlib recvmsg ECN observations, including mapped send/receive."""
import argparse,json,select,socket,struct,subprocess,sys
from pathlib import Path

def payload():
    data=bytearray(i%251 for i in range(1200));data[:11]=b'webtools400';return bytes(data)
def completed(process):
    stdout,stderr=process.communicate(timeout=8)
    assert process.returncode==0 and 'AddressSanitizer' not in stderr and 'ThreadSanitizer' not in stderr,(stdout,stderr,process.returncode)
    return stdout

def main(binary):
    linux=sys.platform.startswith('linux');recv4=13 if linux else 27;recv6=66 if linux else 35;class6=67 if linux else 36
    for mode in ('ipv4','ipv6','mapped'):
        family=socket.AF_INET6 if mode=='ipv6' else socket.AF_INET
        with socket.socket(family,socket.SOCK_DGRAM) as receiver:
            receiver.setsockopt(socket.IPPROTO_IPV6 if family==socket.AF_INET6 else socket.IPPROTO_IP,recv6 if family==socket.AF_INET6 else recv4,1)
            receiver.bind(('::1' if family==socket.AF_INET6 else '127.0.0.1',0));receiver.settimeout(3)
            child=subprocess.Popen([str(binary),mode,str(receiver.getsockname()[1])],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:
                data,ancillary,flags,_=receiver.recvmsg(1200,128)
                assert data==payload() and not flags,(len(data),flags)
                values=[]
                for level,kind,value in ancillary:
                    if level==socket.IPPROTO_IP and kind in (recv4,1):values.append(value[0]&3)
                    if level==socket.IPPROTO_IPV6 and kind==class6:values.append(struct.unpack('i',value)[0]&3)
                assert values==[3],(mode,values,ancillary)
                print(json.dumps({'independent_recvmsg':mode,'ecn':values[0],'received':len(data),'native':completed(child).strip()}))
            finally:
                if child.poll() is None:child.kill();child.wait()
    child=subprocess.Popen([str(binary),'receive-mapped','0'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        ready,_,_=select.select([child.stdout],[],[],5);assert ready
        line=child.stdout.readline();assert line.startswith('READY '),line
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sender:
            sender.sendmsg([payload()],[(socket.IPPROTO_IP,socket.IP_TOS,struct.pack('i',3))],0,('127.0.0.1',int(line.split()[1])))
        stdout=completed(child);record=json.loads(stdout);assert record['ecn']==3 and record['received']==1200
        print(json.dumps({'independent_sender':'ipv4','native_receiver':'dual-stack-mapped','ecn':3,'received':1200}))
    finally:
        if child.poll() is None:child.kill();child.wait()
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('binary',type=Path);main(p.parse_args().binary)
