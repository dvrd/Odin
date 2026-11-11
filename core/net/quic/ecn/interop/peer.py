#!/usr/bin/env python3
"""Independent Python ancillary peer for a built Odin ECN fixture."""
import json, socket, subprocess, sys
rows=[]
for version in (4,6):
    p=subprocess.Popen([sys.argv[1],str(version)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        port=int(p.stdout.readline().strip())
        af=socket.AF_INET if version==4 else socket.AF_INET6
        level=socket.IPPROTO_IP if version==4 else socket.IPPROTO_IPV6
        tx=socket.IP_TOS if version==4 else socket.IPV6_TCLASS
        rx=(13 if sys.platform.startswith('linux') else 27) if version==4 else socket.IPV6_RECVTCLASS
        peer=('127.0.0.1',port) if version==4 else ('::1',port)
        with socket.socket(af,socket.SOCK_DGRAM) as s:
            s.settimeout(2);s.setsockopt(level,rx,1)
            for mark in (2,3,1,0):
                s.sendmsg([bytes([mark])],[(level,tx,mark.to_bytes(4,sys.byteorder))],0,peer)
                data,anc,flags,_=s.recvmsg(16,128)
                expect_rx=(socket.IP_TOS if sys.platform.startswith('linux') else 27) if version==4 else socket.IPV6_TCLASS
                values=[int.from_bytes(v,sys.byteorder)&3 for l,k,v in anc if l==level and k==expect_rx]
                assert data==bytes([mark]) and values==[mark] and not flags&socket.MSG_CTRUNC,(version,mark,data,anc,flags)
                rows.append({'ip':version,'ecn':mark,'echo':True})
        p.wait(timeout=3);err=p.stderr.read();assert p.returncode==0,err
    finally:
        if p.poll() is None:p.kill();p.wait()
print(json.dumps({'platform':sys.platform,'independent_python_peer':rows},indent=2))
