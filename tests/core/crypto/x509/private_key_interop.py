#!/usr/bin/env python3
"""Verify imported synthetic keys with independent Go and OpenSSL, offline."""
import argparse,os
from pathlib import Path
import subprocess,tempfile
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--odin',required=True)
args=parser.parse_args()
root=Path(__file__).resolve().parent
with tempfile.TemporaryDirectory(prefix='rsa-import-fixtures-') as temporary:
    temp=Path(temporary)
    environment=dict(os.environ,GOTOOLCHAIN='local',GOPROXY='off',GOSUMDB='off',GOCACHE=str(temp/'cache'),GOTMPDIR=str(temp))
    peer=temp/'peer'
    subprocess.run(['go','build','-o',str(peer),str(root/'testdata/key_import_peer.go')],env=environment,check=True)
    subprocess.run([str(peer),'-dir',str(temp)],check=True)
    subprocess.run(['openssl','pkcs8','-topk8','-in',str(temp/'rsa2048.pem'),'-passout','pass:public-test-fixture','-outform','DER','-out',str(temp/'encrypted.der')],check=True,capture_output=True)
    binary=temp/'native'
    subprocess.run([args.odin,'build',str(root/'testdata/key_import'),'-thread-count:1','-warnings-as-errors','-sanitize:address','-out:'+str(binary)],check=True)
    subprocess.run([str(binary),str(temp)],check=True,timeout=60)
    subprocess.run([str(peer),'-dir',str(temp),'-verify'],check=True)
    for bits in (1024,2048,4096):
        stem=temp/f'rsa{bits}'
        for mode,options in [('pkcs1',[]),('pss',['-sigopt','rsa_padding_mode:pss','-sigopt','rsa_pss_saltlen:32'])]:
            result=subprocess.run(['openssl','dgst','-sha256','-verify',str(stem)+'.pub.pem',*options,'-signature',str(stem)+f'.{mode}.sig',str(temp/'message')],check=True,capture_output=True,text=True)
            assert 'Verified OK' in result.stdout
    print('Independent Go +OpenSSL verified native PKCS1/PSS signatures at1024/2048/4096bits; no services used.')
