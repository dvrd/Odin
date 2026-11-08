#!/usr/bin/env python3
"""Owned Go/OpenSSL interoperability for the actual native async TCP adapter."""
import argparse, hashlib, json, os, pathlib, select, shlex, subprocess, tempfile, time

def main():
    p=argparse.ArgumentParser();p.add_argument('--odin',required=True);p.add_argument('--go',required=True);p.add_argument('--go-root',required=True);p.add_argument('--openssl',required=True);p.add_argument('--sanitize',choices=['address','thread']);p.add_argument('--report',required=True);p.add_argument('--case');a=p.parse_args()
    root=pathlib.Path(__file__).resolve().parents[4];source=root/'tests/core/crypto/tls/server_tcp';fixtures=root/'tests/core/crypto/tls/credentials/testdata'
    env=os.environ.copy();env.update(GOROOT=a.go_root,GOTOOLCHAIN='local',GOPROXY='off',GOSUMDB='off')
    report={'scope':'actual native async TCP record adapter; owned peers, not broad platform/performance certification','sanitizer':a.sanitize,'compiler_sha256':hashlib.sha256(pathlib.Path(a.odin).read_bytes()).hexdigest(),'case_filter':a.case,'cases':[],'passed':False}
    def run(command,environment=None):
        r=subprocess.run([str(x) for x in command],env=environment,capture_output=True,text=True,timeout=100)
        if r.returncode:raise RuntimeError(f'{command}: {r.returncode}\n{r.stdout}\n{r.stderr}')
        return r.stdout+r.stderr
    try:
        report['compiler']=run([a.odin,'version']).strip();report['go']=run([a.go,'version'],env).strip();report['openssl']=run([a.openssl,'version']).strip()
        with tempfile.TemporaryDirectory(prefix='webtools-tcp147-') as td:
            temp=pathlib.Path(td);native=temp/'server';peer=temp/'peer';client=temp/'openssl-client'
            run([a.odin,'build',source,'-warnings-as-errors','-out:'+str(native)]+(['-sanitize:'+a.sanitize] if a.sanitize else []))
            run([a.go,'build','-o',peer,source/'peer.go'],env)
            flags=shlex.split(run(['pkg-config','--cflags','--libs','openssl']));run(['clang','-Wall','-Wextra','-Werror',source/'openssl_client.c','-o',client,*flags])
            large=temp/'large.pem';run([peer,'--large-cert',fixtures/'rsa2048.pem',large]);chain=temp/'chain.pem';chain.write_bytes(large.read_bytes()*16)
            base=(fixtures/'rsa2048-valid.pem',fixtures/'rsa2048.pem')
            go_cases=[('x25519',*base,1,'normal'),('rsa4096',fixtures/'rsa4096-valid.pem',fixtures/'rsa4096.pem',1,'normal'),('chain16',chain,base[1],1,'normal')]+[(mode,*base,8 if mode in ['rotate','concurrent'] else 1,'normal' if mode=='concurrent' else mode) for mode in ['p256','retry','retry-p256','concurrent','key-update','fragment','backpressure','rotate','raw-oversize','raw-type','raw-truncate','timeout','cancel','close-active','trust','hostname','time','before','no-alpn','no-overlap','bad-record']]
            for name,cert,key,count,mode in go_cases:
                if a.case and not ('go-'+name).startswith(a.case):continue
                command=[peer,native,cert,key,str(count),mode]
                if mode=='rotate':command += [fixtures/'rsa4096-valid.pem',fixtures/'rsa4096.pem']
                start=time.monotonic();output=run(command,env)
                report['cases'].append({'name':'go-'+name,'result':'pass','seconds':time.monotonic()-start,'output':output.strip()});print('go-'+name+': pass',flush=True)
            openssl_cases=[('x25519',*base,'X25519','normal'),('rsa4096',fixtures/'rsa4096-valid.pem',fixtures/'rsa4096.pem','X25519','normal'),('chain16',chain,base[1],'X25519','normal')]+[(mode,*base,groups,'key-update-peer' if mode=='key-update' else 'normal') for mode,groups in [('p256','P-256'),('retry','P-256:X25519'),('retry-p256','P-384:P-256'),('key-update','X25519')]]+[(mode,*base,'X25519','peer-reject') for mode in ['trust','hostname','time','before']]
            for name,cert,key,groups,mode in openssl_cases:
                if a.case and not ('openssl-'+name).startswith(a.case):continue
                server=subprocess.Popen([str(x) for x in [native,cert,key,'1',mode]],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                try:
                    ready,_,_=select.select([server.stdout],[],[],5);assert ready,'no owned listener readiness'
                    line=server.stdout.readline();assert line.startswith('READY '),line
                    ca=fixtures/'rsa4096-valid.pem' if name=='trust' else cert
                    output=run([client,line.strip().split()[1],ca,groups,name],env)
                    stdout,stderr=server.communicate(timeout=25)
                    if server.returncode:raise RuntimeError(f'native OpenSSL case {name}: {stdout}\n{stderr}')
                    assert 'DONE 1' in stdout
                    report['cases'].append({'name':'openssl-'+name,'result':'pass','output':output.strip()+'\n'+stdout+stderr});print('openssl-'+name+': pass',flush=True)
                finally:
                    if server.poll() is None:server.kill();server.communicate()
        assert report['cases'],'no matching cases'
        report['passed']=True
    finally:pathlib.Path(a.report).write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'passed':True,'cases':len(report['cases']),'report':a.report}))
if __name__=='__main__':main()
