#!/usr/bin/env python3
"""Owned TLS1.3 resumption peers: normal Saba, native blocking/async, Go/OpenSSL."""
import argparse, hashlib, json, os, subprocess, tempfile
from pathlib import Path

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--odin',required=True,type=Path)
    parser.add_argument('--go',required=True,type=Path)
    parser.add_argument('--openssl',required=True,type=Path)
    parser.add_argument('--shared-root',required=True,type=Path)
    parser.add_argument('--sanitize',choices=['address','thread'])
    parser.add_argument('--report',required=True,type=Path)
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[4]
    fixture=root/'core/crypto/tls/testdata/mtls'
    source=root/'tests/core/crypto/tls/resumption_wire'
    files=list((root/'core/crypto/tls').rglob('*.odin'))+list(fixture.glob('*'))+list(source.glob('*'))+[root/'core/net/quic/conn/post_handshake.odin']
    def manifest():return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in files if p.is_file()}
    before=manifest()
    report={'passed':False,'sanitize':args.sanitize,'cases':[],'commands':[],'compiler_sha256':hashlib.sha256(args.odin.read_bytes()).hexdigest()}
    env=os.environ.copy();env['ODIN_ROOT']=str(root)
    def run(command,timeout=45,stdin=None):
        result=subprocess.run([str(x) for x in command],cwd=root,env=env,capture_output=True,text=True,input=stdin,timeout=timeout)
        report['commands'].append({'command':[str(x) for x in command],'returncode':result.returncode,'stdout':result.stdout,'stderr':result.stderr})
        assert result.returncode==0,report['commands'][-1]
        return result
    def pair(server,client,name):
        process=subprocess.Popen([str(x) for x in server],cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            line=process.stdout.readline();assert line.startswith('READY '),line
            client(line.split()[1])
            stdout,stderr=process.communicate(timeout=30)
            report['commands'].append({'command':[str(x) for x in server],'returncode':process.returncode,'stdout':line+stdout,'stderr':stderr})
            assert process.returncode==0,report['commands'][-1]
            report['cases'].append(name)
        finally:
            if process.poll() is None:process.kill();process.communicate()
    try:
        with tempfile.TemporaryDirectory(prefix='webtools-resumption-') as temp:
            temp=Path(temp);env['GOCACHE']=str(temp/'go-cache');native=temp/'native';go=temp/'peer'
            run([args.odin,'build',source,'-warnings-as-errors','-collection:shared='+str(args.shared_root.resolve()),'-out:'+str(native)]+(['-sanitize:'+args.sanitize] if args.sanitize else []))
            run([args.go,'build','-o',go,source/'peer.go'],timeout=120)
            for mode in ['normal','rotate','credential','policy']:
                for policy in ['anonymous','mtls']:
                    pair([native,fixture,mode,policy],lambda endpoint:run([go,'client',endpoint,fixture,policy,'full' if mode in ['credential','policy'] else 'resume']),f'Go-client/Saba/{mode}/{policy}')
            for kind in ['blocking','async']:
                for policy in ['anonymous','mtls']:
                    mode='client'+('-async' if kind=='async' else '')+('-mtls' if policy=='mtls' else '')
                    pair([go,'server','-',fixture,policy],lambda endpoint:run([native,fixture,mode,endpoint]),f'native-{kind}/Go-server/{policy}')
            for policy in ['anonymous','mtls']:
                def openssl_client(endpoint):
                    session=temp/('session-'+policy+'.pem')
                    for i in range(2):
                        command=[args.openssl,'s_client','-connect',endpoint,'-servername','localhost','-CAfile',fixture/'root.pem','-verify_return_error','-tls1_3','-alpn','http/1.1','-quiet','-sess_out' if i==0 else '-sess_in',session]
                        if policy=='mtls':command+=['-cert',fixture/'client.pem','-key',fixture/'client-key.pem']
                        result=run(command,stdin='GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
                        assert result.stdout.endswith('OK'),result.stdout
                pair([native,fixture,'normal',policy],openssl_client,f'OpenSSL-client/Saba/{policy}')
            assert len(report['cases'])==14
            report['source_unchanged']=before==manifest();assert report['source_unchanged'],'source changed during matrix'
            report['source_sha256']=before;report['passed']=True
    finally:args.report.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'passed':report['passed'],'cases':len(report['cases']),'report':str(args.report)}))
if __name__=='__main__':main()
