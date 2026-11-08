#!/usr/bin/env python3
"""Offline independent Go TLS client / public Odin handshake API. No TCP listener."""
import argparse, hashlib, json, os, pathlib, subprocess, tempfile, resource, time, shlex

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--odin',required=True);ap.add_argument('--go',required=True);ap.add_argument('--go-root',required=True);ap.add_argument('--sanitize',choices=['address','thread']);ap.add_argument('--report',required=True);ap.add_argument('--openssl');a=ap.parse_args()
    root=pathlib.Path(__file__).resolve().parents[4];source=root/'tests/core/crypto/tls/server_flight';fixtures=root/'tests/core/crypto/tls/credentials/testdata'
    env=os.environ.copy();env.update(GOROOT=a.go_root,GOTOOLCHAIN='local')
    def run(cmd,**kwargs):
        p=subprocess.run([str(x) for x in cmd],capture_output=True,text=True,timeout=120,**kwargs)
        if p.returncode:raise RuntimeError(f'{cmd}: {p.returncode}\n{p.stdout}\n{p.stderr}')
        return p.stdout+p.stderr
    report={'odin':run([a.odin,'version']).strip(),'odin_sha256':hashlib.sha256(pathlib.Path(a.odin).read_bytes()).hexdigest(),'go':run([a.go,'version'],env=env).strip(),'sanitize':a.sanitize,'cases':[]}
    with tempfile.TemporaryDirectory(prefix='webtools-finished154-') as td:
        temp=pathlib.Path(td);binary=temp/'flight';peer=temp/'peer'
        run([a.odin,'build',source,'-out:'+str(binary)]+(['-sanitize:'+a.sanitize] if a.sanitize else []))
        run([a.go,'build','-o',peer,source/'peer.go',source/'quic_peer.go',source/'openssl_peer.go'],env=env)
        large=temp/'large.pem';run([peer,'--large-cert',fixtures/'rsa2048.pem',large])
        chain=temp/'chain.pem';chain.write_bytes(large.read_bytes()*16)
        for name,cert,key in [('rsa2048',fixtures/'rsa2048-valid.pem',fixtures/'rsa2048.pem'),('rsa4096',fixtures/'rsa4096-valid.pem',fixtures/'rsa4096.pem'),('large16',chain,fixtures/'rsa2048.pem')]:
            before=resource.getrusage(resource.RUSAGE_CHILDREN);started=time.monotonic();output=run([peer,binary,cert,key,temp]);after=resource.getrusage(resource.RUSAGE_CHILDREN)
            report['cases'].append({'name':name,'result':'pass','output':output.strip(),'wall_seconds':time.monotonic()-started,'child_user_cpu_seconds':after.ru_utime-before.ru_utime,'child_system_cpu_seconds':after.ru_stime-before.ru_stime})
            print(name+': '+output.strip(),flush=True)
        negative_env=env.copy();negative_env['WEBTOOLS_BAD_FINISHED']='1'
        output=run([peer,binary,fixtures/'rsa2048-valid.pem',fixtures/'rsa2048.pem',temp],env=negative_env)
        report['cases'].append({'name':'altered-client-finished','result':'pass','output':output.strip()})
        print('altered-client-finished: '+output.strip(),flush=True)
        for mode in ['alpn','opaque','quic']:
            parameter_env=env.copy();parameter_env['WEBTOOLS_PARAMETERS']=mode
            output=run([peer,binary,fixtures/'rsa2048-valid.pem',fixtures/'rsa2048.pem',temp],env=parameter_env)
            report['cases'].append({'name':mode,'result':'pass','output':output.strip()})
            print(mode+': '+output.strip(),flush=True)
        for mode in ['p256','retry','retry-p256']:
            curve_env=env.copy();curve_env['WEBTOOLS_CURVE']=mode
            output=run([peer,binary,fixtures/'rsa2048-valid.pem',fixtures/'rsa2048.pem',temp],env=curve_env)
            report['cases'].append({'name':mode,'result':'pass','output':output.strip()})
            print(mode+': '+output.strip(),flush=True)
        for mode in ['retry-opaque','retry-bad-finished']:
            extra_env=env.copy();extra_env['WEBTOOLS_CURVE']='retry'
            if mode=='retry-opaque':extra_env['WEBTOOLS_PARAMETERS']='opaque'
            else:extra_env['WEBTOOLS_BAD_FINISHED']='1'
            output=run([peer,binary,fixtures/'rsa2048-valid.pem',fixtures/'rsa2048.pem',temp],env=extra_env)
            report['cases'].append({'name':mode,'result':'pass','output':output.strip()})
            print(mode+': '+output.strip(),flush=True)
        for mode in ['trust','hostname','time','before']:
            rejection_env=env.copy();rejection_env['WEBTOOLS_NEGATIVE']=mode
            output=run([peer,binary,fixtures/'rsa2048-valid.pem',fixtures/'rsa2048.pem',temp],env=rejection_env)
            report['cases'].append({'name':'go-reject-'+mode,'result':'pass','output':output.strip()})
            print('go-reject-'+mode+': '+output.strip(),flush=True)
        if a.openssl:
            report['openssl']=run([a.openssl,'version']).strip()
            report['openssl_pkg_config']=run(['pkg-config','--modversion','openssl']).strip()
            large_client=temp/'openssl-large-client'
            flags=shlex.split(run(['pkg-config','--cflags','--libs','openssl']))
            run(['clang','-Wall','-Wextra','-Werror',source/'openssl_large_client.c','-o',large_client,*flags])
            for mode,cert,key in [('x25519',fixtures/'rsa2048-valid.pem',fixtures/'rsa2048.pem'),('rsa4096',fixtures/'rsa4096-valid.pem',fixtures/'rsa4096.pem'),('large16',chain,fixtures/'rsa2048.pem')]+[(mode,fixtures/'rsa2048-valid.pem',fixtures/'rsa2048.pem') for mode in ['p256','retry','retry-p256','alpn','trust','hostname','time','before']]:
                openssl_env=env.copy();openssl_env['WEBTOOLS_OPENSSL']=a.openssl;openssl_env['WEBTOOLS_OPENSSL_CASE']=mode;openssl_env['WEBTOOLS_OPENSSL_LARGE_CLIENT']=str(large_client)
                output=run([peer,binary,cert,key,temp],env=openssl_env)
                report['cases'].append({'name':'openssl-'+mode,'result':'pass','output':output.strip()})
                print('openssl-'+mode+': '+output.strip(),flush=True)
    pathlib.Path(a.report).write_text(json.dumps(report,indent=2)+'\n')
if __name__=='__main__': main()
