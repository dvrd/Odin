#!/usr/bin/env python3
"""Owned native UDP no-fragment kernel/interop gate; no package downloads."""
import argparse, hashlib, json, os, platform, subprocess, sys, time
from pathlib import Path
HERE=Path(__file__).resolve().parent
CORE=HERE.parents[3]
SHARED=CORE.parent/'shared'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def sources():
    roots=[CORE/'core',CORE/'base',CORE/'vendor',SHARED/'async']
    return {str(p):sha(p) for root in roots for p in sorted(root.rglob('*')) if p.is_file() and (p.suffix in ('.odin','.py','.c','.h','.s','.S') or 'testdata' in p.parts) and '.git' not in p.parts and '__pycache__' not in p.parts}
def main():
    p=argparse.ArgumentParser();p.add_argument('--odin',type=Path,required=True);p.add_argument('--cc',default='clang');p.add_argument('--sanitize',choices=['address','thread'],required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    env=os.environ.copy();env['ODIN_ROOT']=str(CORE);env['PATH']='/opt/homebrew/opt/llvm@22/bin:'+env.get('PATH','')
    prefix=Path(f'/tmp/webtools400-{a.sanitize}-{os.getpid()}');records=[];before=sources()
    report={'compiler_sha256':sha(a.odin),'platform':platform.platform(),'architecture':platform.machine(),'sanitizer':a.sanitize,'source_before':before,'records':records}
    def run(command,timeout=120):
        start=time.monotonic();r=subprocess.run(list(map(str,command)),env=env,capture_output=True,text=True,timeout=timeout)
        item={'command':list(map(str,command)),'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr,'seconds':time.monotonic()-start};records.append(item)
        assert r.returncode==0,item
        assert 'ERROR: AddressSanitizer' not in r.stderr and 'WARNING: ThreadSanitizer' not in r.stderr,item
        return r.stdout
    try:
        report['compiler_version']=run([a.odin,'version']).strip()
        names=['udp_fragmentation_policy_sets_queries_and_preserves_ecn','udp_fragmentation_ipv6_preserves_explicit_single_and_dual_stack','udp_fragmentation_rejects_invalid_family_descriptor_and_tcp','udp_fragmentation_mapped_ipv4_ecn_send_and_receive']
        packages=[(CORE/'core/net',','.join(names)),(SHARED/'async','udp_fragmentation_borrow_checks_kind_generation_and_closure')]
        for index,(package,selection) in enumerate(packages):
            run([a.odin,'test',package,f'-collection:shared={SHARED}','-warnings-as-errors','-vet',f'-sanitize:{a.sanitize}',f'-define:ODIN_TEST_NAMES={selection}','-define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true','-keep-executable',f'-out:{prefix}.test{index}'])
        probe=Path(str(prefix)+'.probe');peer=Path(str(prefix)+'.peer')
        run([a.odin,'build',HERE,'-warnings-as-errors','-vet',f'-sanitize:{a.sanitize}',f'-out:{probe}'])
        run([a.cc,'-std=c11','-Wall','-Wextra','-Werror',HERE/'peer.c','-o',peer])
        report['probe_sha256']=sha(probe);report['peer_sha256']=sha(peer)
        for mode in ['ipv4','ipv6','mapped']:run([peer,probe,mode],15)
        run([sys.executable,HERE/'peer.py',probe],25)
        report['darwin_wire_capture_qualified']=platform.system()!='Darwin'
        report['passed']=True
    finally:
        report['source_after']=sources();report['source_unchanged']=before==report['source_after'];report['passed']=report.get('passed',False) and report['source_unchanged'];a.report.write_text(json.dumps(report,indent=2)+'\n')
    assert report['source_unchanged'],'source changed during gate'
if __name__=='__main__':main()
