#!/usr/bin/env python3
"""Offline native immutable signing, independently verified by Go/OpenSSL."""
import argparse,hashlib,json,os,pathlib,subprocess,tempfile
p=argparse.ArgumentParser();p.add_argument('--odin',required=True);p.add_argument('--sanitize',choices=['address','thread'],default='address');p.add_argument('--go',required=True);p.add_argument('--go-root');p.add_argument('--openssl',default='openssl');p.add_argument('--report',required=True);args=p.parse_args()
root=pathlib.Path(__file__).resolve().parent;fixture=root/'testdata';report=pathlib.Path(args.report).resolve();report.parent.mkdir(parents=True,exist_ok=True)
def run(cmd,env=None):
 r=subprocess.run([str(x) for x in cmd],env=env,text=True,capture_output=True,timeout=180)
 if r.returncode: raise RuntimeError('Command failed: '+str(cmd)+'\n'+r.stdout+r.stderr)
 return r.stdout.strip()
go_root=pathlib.Path(args.go).resolve().parents[1]
if (go_root/'libexec/src').exists():go_root=go_root/'libexec'
env=os.environ.copy();env.update(GOROOT=args.go_root or str(go_root),GOTOOLCHAIN='local',GO111MODULE='off',GOPROXY='off',GOSUMDB='off',GOCACHE=str(report.parent/'go-cache'),GOTMPDIR=str(report.parent))
receipt={'sanitizer':args.sanitize,'compiler_sha256':hashlib.sha256(pathlib.Path(args.odin).read_bytes()).hexdigest(),'results':[],'passed':False}
try:
 receipt.update(compiler=run([args.odin,'version']),go=run([args.go,'version'],env),openssl=run([args.openssl,'version']))
 with tempfile.TemporaryDirectory(dir=report.parent,prefix='signing-') as directory:
  work=pathlib.Path(directory);binary=work/'native';peer=work/'peer'
  run([pathlib.Path(args.odin).resolve(),'build',fixture/'concurrent','-sanitize:'+args.sanitize,'-out:'+str(binary),'-thread-count:1','-warnings-as-errors'])
  run([args.go,'build','-o',peer,fixture/'verify.go'],env)
  for profile in ('rsa2048','rsa4096','p256'):
   target=work/profile;target.mkdir();cert=fixture/f'{profile}-valid.pem';key=fixture/f'{profile}.pem'
   native=run([binary,cert,key,target]);signatures=sorted(target.glob('*.sig'));assert len(signatures)==64
   assert len({p.read_bytes() for p in signatures})==64,'hedged signing repeated signatures'
   go=run([peer,cert,*signatures]);public=target/'public.pem';public.write_text(run([args.openssl,'x509','-in',cert,'-pubkey','-noout'])+'\n')
   message=target/'message';message.write_bytes(b'credential-concurrency-fixture')
   for signature in signatures:
    options=['-sigopt','rsa_padding_mode:pss','-sigopt','rsa_pss_saltlen:32','-sigopt','rsa_mgf1_md:sha256'] if profile.startswith('rsa') else []
    output=run([args.openssl,'dgst','-sha256','-verify',public,'-signature',signature,*options,message]);assert output=='Verified OK'
   receipt['results'].append({'profile':profile,'signatures':64,'unique_signatures':64,'native':native,'go':go,'openssl_verified':64});print(profile+':64 concurrent signatures pass',flush=True)
 receipt['passed']=True
finally:report.write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps(receipt,indent=2))
