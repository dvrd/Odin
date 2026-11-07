#!/usr/bin/env python3
"""Local independent Go TLS1.3 peer; no external services or module downloads."""
import argparse
import json
import os
from pathlib import Path
import select
import subprocess
import tempfile

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--odin',required=True)
args=parser.parse_args()
root=Path(__file__).resolve().parent
with tempfile.TemporaryDirectory(prefix='odin-alpn-') as temporary:
    temp=Path(temporary)
    environment=dict(os.environ,GOTOOLCHAIN='local',GOPROXY='off',GOSUMDB='off',GOCACHE=str(temp/'cache'),GOTMPDIR=str(temp))
    peer=temp/'peer'
    subprocess.run(['go','build','-o',str(peer),str(root/'testdata/alpn_peer.go')],env=environment,check=True)
    binary=temp/'checks'
    subprocess.run([args.odin,'build',str(root/'testdata/alpn'),'-thread-count:1','-warnings-as-errors','-sanitize:address','-out:'+str(binary)],check=True)
    process=subprocess.Popen([str(peer),'-dir',str(root/'testdata')],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        ready,_,_=select.select([process.stdout],[],[],3)
        assert ready,'owned TLS peer did not publish endpoints'
        endpoints=json.loads(process.stdout.readline())
        subprocess.run([str(binary),endpoints['ordered'],endpoints['none'],endpoints['incompatible'],endpoints['http1']],check=True,timeout=20)
    finally:
        process.terminate()
        try:process.communicate(timeout=3)
        except subprocess.TimeoutExpired:process.kill();process.communicate()
