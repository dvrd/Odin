#!/usr/bin/env python3
"""Offline independent Go TLS client / public Odin handshake API. No TCP listener."""
import argparse, hashlib, json, os, pathlib, subprocess, tempfile, resource, time

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--odin',required=True);ap.add_argument('--go',required=True);ap.add_argument('--go-root',required=True);ap.add_argument('--sanitize',choices=['address','thread']);ap.add_argument('--report',required=True);a=ap.parse_args()
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
        run([a.go,'build','-o',peer,source/'peer.go'],env=env)
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
    pathlib.Path(a.report).write_text(json.dumps(report,indent=2)+'\n')
if __name__=='__main__': main()
