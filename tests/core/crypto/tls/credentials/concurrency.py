#!/usr/bin/env python3
"""Offline native concurrent signing verified independently by Go/OpenSSL."""
import argparse,json,os,pathlib,subprocess,tempfile
p=argparse.ArgumentParser();p.add_argument('--odin',required=True);p.add_argument('--sanitize',choices=['address','thread'],default='address');p.add_argument('--go',required=True);p.add_argument('--report',required=True);args=p.parse_args()
root=pathlib.Path(__file__).resolve().parent;fixture=root/'testdata';report=pathlib.Path(args.report).resolve();report.parent.mkdir(parents=True,exist_ok=True)
def run(cmd,env=None):
 r=subprocess.run([str(x) for x in cmd],env=env,text=True,capture_output=True,timeout=180)
 if r.returncode: raise RuntimeError('Command failed: '+str(cmd)+'\n'+r.stdout+r.stderr)
 return r.stdout.strip()
env=os.environ.copy();env['GOROOT']=str(pathlib.Path(args.go).resolve().parents[1]);env['GOTOOLCHAIN']='local';env['GO111MODULE']='off';env['GOPROXY']='off';env['GOSUMDB']='off';env['GOCACHE']=str(report.parent/'go-cache');env['GOTMPDIR']=str(report.parent)
results=[]
with tempfile.TemporaryDirectory(dir=report.parent,prefix='signing-') as directory:
 work=pathlib.Path(directory);binary=work/'native';peer=work/'peer'
 run([pathlib.Path(args.odin).resolve(),'build',fixture/'concurrent','-sanitize:'+args.sanitize,'-out:'+str(binary),'-thread-count:1','-warnings-as-errors'])
 run([args.go,'build','-o',peer,fixture/'verify.go'],env)
 for bits in (2048,4096):
  target=work/str(bits);target.mkdir();cert=fixture/f'rsa{bits}-valid.pem';key=fixture/f'rsa{bits}.pem'
  native=run([binary,cert,key,target]);signatures=sorted(target.glob('*.sig'));assert len(signatures)==64
  go=run([peer,cert,*signatures]);public=target/'public.pem';public.write_text(run(['openssl','x509','-in',cert,'-pubkey','-noout'])+'\n')
  message=target/'message';message.write_bytes(b'credential-concurrency-fixture')
  for signature in signatures:
   output=run(['openssl','dgst','-sha256','-verify',public,'-signature',signature,'-sigopt','rsa_padding_mode:pss','-sigopt','rsa_pss_saltlen:32','-sigopt','rsa_mgf1_md:sha256',message]);assert output=='Verified OK'
  results.append({'bits':bits,'signatures':64,'native':native,'go':go,'openssl_verified':64})
receipt={'sanitizer':args.sanitize,'go':run([args.go,'version'],env),'openssl':run(['openssl','version']),'results':results,'passed':True}
report.write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt,indent=2))
