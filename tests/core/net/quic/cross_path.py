#!/usr/bin/env python3
"""Fresh paired native/published-aioquic cross-path validation evidence."""
import argparse,hashlib,json,os,selectors,subprocess,tempfile
from pathlib import Path

def main():
 p=argparse.ArgumentParser();p.add_argument('--odin',required=True,type=Path);p.add_argument('--python',required=True,type=Path);p.add_argument('--shared-root',required=True,type=Path);p.add_argument('--sanitize',choices=['address','thread']);p.add_argument('--report',required=True,type=Path);a=p.parse_args()
 root=Path(__file__).resolve().parents[4];source=root/'tests/core/net/quic/cross_path';fixtures=root/'core/crypto/tls/testdata/mtls';shared=a.shared_root.resolve()
 def manifest():
  paths=list((root/'core/net/quic').rglob('*.odin'))+list((root/'core/crypto/tls').rglob('*.odin'))+list(source.glob('*'))+list(fixtures.glob('*'))+[Path(__file__).resolve()]
  for part in ['http/v3','async']:paths+=list((shared/part).rglob('*.odin'))
  return {str(x):hashlib.sha256(x.read_bytes()).hexdigest() for x in paths if x.is_file()}
 before=manifest();report={'passed':False,'sanitize':a.sanitize,'commands':[],'compiler_sha256':hashlib.sha256(a.odin.read_bytes()).hexdigest()};env=os.environ.copy();env['ODIN_ROOT']=str(root)
 def run(command,timeout=40):
  r=subprocess.run([str(x) for x in command],cwd=root,env=env,capture_output=True,text=True,timeout=timeout);record={'command':[str(x) for x in command],'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr};report['commands'].append(record);assert r.returncode==0,record;return r
 server=None
 try:
  report['peer_version']=run([a.python,'-c','import aioquic;assert aioquic.__version__=="1.3.0";print(aioquic.__version__)']).stdout
  with tempfile.TemporaryDirectory(prefix='webtools-cross-path-') as temp:
   native=Path(temp)/'native';run([a.odin,'build',source,'-vet','-warnings-as-errors','-collection:shared='+str(shared),'-out:'+str(native)]+(['-sanitize:'+a.sanitize] if a.sanitize else []),120)
   command=[a.python,source/'peer.py','--fixtures',fixtures];server=subprocess.Popen([str(x) for x in command],cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
   selector=selectors.DefaultSelector();selector.register(server.stdout,selectors.EVENT_READ);assert selector.select(20),'peer readiness timeout';selector.close();line=server.stdout.readline();assert line.startswith('READY '),line
   parts=line.split();run([native,fixtures,parts[1],parts[2]])
   out,err=server.communicate(timeout=25);record={'command':[str(x) for x in command],'returncode':server.returncode,'stdout':line+out,'stderr':err};report['commands'].append(record);assert server.returncode==0,record
   report['source_unchanged']=before==manifest();assert report['source_unchanged'];report['source_sha256']=before;report['passed']=True
 finally:
  if server is not None and server.poll() is None:server.kill();server.communicate()
  a.report.write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({'passed':report['passed'],'report':str(a.report)}))
if __name__=='__main__':main()
