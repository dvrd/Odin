#!/usr/bin/env python3
"""Reproducible real QUIC resumption/0RTT through native HTTP3, Surf and Saba."""
import argparse, hashlib, json, os, selectors, subprocess, tempfile
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument('--odin',required=True,type=Path);p.add_argument('--python',required=True,type=Path);p.add_argument('--shared-root',required=True,type=Path);p.add_argument('--sanitize',choices=['address','thread']);p.add_argument('--report',required=True,type=Path);args=p.parse_args()
    root=Path(__file__).resolve().parents[4];shared=args.shared_root.resolve();source=root/'tests/core/net/quic/zero_rtt';fixtures=root/'core/crypto/tls/testdata/mtls'
    def manifest():
        paths=list((root/'core/crypto/tls').rglob('*.odin'))+list((root/'core/net/quic').rglob('*.odin'))+list(source.glob('*'))+list(fixtures.glob('*'))+[Path(__file__).resolve()]
        for library in ['http/v3','surf','saba/core']:paths+=list((shared/library).rglob('*.odin'))
        return {str(x):hashlib.sha256(x.read_bytes()).hexdigest() for x in paths if x.is_file()}
    before=manifest();report={'passed':False,'cases':[],'commands':[],'sanitize':args.sanitize,'compiler_sha256':hashlib.sha256(args.odin.read_bytes()).hexdigest()};env=os.environ.copy();env['ODIN_ROOT']=str(root)
    def run(command,timeout=40):
        r=subprocess.run([str(x) for x in command],cwd=root,env=env,capture_output=True,text=True,timeout=timeout)
        record={'command':[str(x) for x in command],'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr};report['commands'].append(record);assert r.returncode==0,record;return r
    def pair(command,client,name):
        server=subprocess.Popen([str(x) for x in command],cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            selector=selectors.DefaultSelector();selector.register(server.stdout,selectors.EVENT_READ);assert selector.select(20),'server readiness timeout';selector.close()
            line=server.stdout.readline();assert line.startswith('READY '),line;client(line.split()[1]);out,err=server.communicate(timeout=25)
            record={'command':[str(x) for x in command],'returncode':server.returncode,'stdout':line+out,'stderr':err};report['commands'].append(record);assert server.returncode==0,record;report['cases'].append(name)
        finally:
            if server.poll() is None:server.kill();server.communicate()
    try:
        versions=run([args.python,'-c','import aioquic,sys;assert aioquic.__version__=="1.3.0";print(sys.version);print(aioquic.__version__)']);report['peer_version']=versions.stdout
        with tempfile.TemporaryDirectory(prefix='webtools-zero-rtt-') as temp:
            native=Path(temp)/'native'
            run([args.odin,'build',source,'-vet','-warnings-as-errors','-collection:shared='+str(shared),'-out:'+str(native)]+(['-sanitize:'+args.sanitize] if args.sanitize else []),120)
            for scenario in ['accepted','reject','retry','large','large-retry']:
                pair([args.python,source/'peer.py','server','--fixtures',fixtures,'--scenario',scenario],lambda address:run([native,fixtures,address,scenario]),'nativeHTTP3/aioquic/'+scenario)
            for scenario in ['accepted','reject','default']:
                pair([args.python,source/'peer.py','server','--fixtures',fixtures,'--scenario',scenario],lambda address:run([native,fixtures,address,'surf-'+scenario]),'Surf/aioquic/'+scenario)
            for scenario in ['accepted','replay','deny','default','mtls','zero']:
                pair([native,fixtures,'server',scenario],lambda address:run([args.python,source/'peer.py','client','--fixtures',fixtures,'--port',address.rsplit(':',1)[1],'--scenario',scenario]),'aioquic/Saba/'+scenario)
            for scenario in ['retry','large','large-retry']:
                pair([native,fixtures,'server',scenario],lambda address:run([native,fixtures,address,scenario]),'nativeHTTP3/Saba/'+scenario)
            assert len(report['cases'])==17
            report['source_unchanged']=before==manifest();assert report['source_unchanged'],'source changed during wire matrix';report['source_sha256']=before;report['passed']=True
    finally:args.report.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'passed':report['passed'],'cases':len(report['cases']),'report':str(args.report)}))
if __name__=='__main__':main()
