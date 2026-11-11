#!/usr/bin/env python3
"""Owned native Saba/Surf/async mutual-TLS matrix against independent Go peers."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--odin', required=True, type=Path)
    parser.add_argument('--go', required=True, type=Path)
    parser.add_argument('--shared-root', required=True, type=Path)
    parser.add_argument('--sanitize', choices=['address', 'thread'])
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[4]
    source = root / 'tests/core/crypto/tls/mtls'
    fixtures = root / 'core/crypto/tls/testdata/mtls'
    report = {'passed': False, 'sanitize': args.sanitize, 'commands': [],
              'compiler_sha256': hashlib.sha256(args.odin.read_bytes()).hexdigest()}
    def manifest():
        paths = list((root / 'core/crypto/tls').rglob('*.odin'))
        paths += list(fixtures.glob('*')) + list(source.glob('*'))
        paths += [root / 'core/net/quic/handshake.odin', root / 'core/net/quic/conn/conn.odin']
        return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in paths if p.is_file()}
    before = manifest()
    def run(command, env):
        result = subprocess.run([str(x) for x in command], cwd=root, env=env,
                                capture_output=True, text=True, timeout=180)
        report['commands'].append({'command': [str(x) for x in command],
                                   'returncode': result.returncode,
                                   'stdout': result.stdout, 'stderr': result.stderr})
        if result.returncode:
            raise RuntimeError(f'{command}: {result.returncode}\n{result.stdout}\n{result.stderr}')
        return result.stdout
    try:
        with tempfile.TemporaryDirectory(prefix='webtools-mtls-') as temporary:
            work = Path(temporary)
            env = os.environ.copy()
            env['ODIN_ROOT'] = str(root)
            env['GOCACHE'] = str(work / 'go-cache')
            native, peer = work / 'native', work / 'peer'
            run([args.odin, 'build', source, '-warnings-as-errors',
                 '-collection:shared=' + str(args.shared_root.resolve()), '-out:' + str(native)]
                + (['-sanitize:' + args.sanitize] if args.sanitize else []), env)
            run([args.go, 'build', '-o', peer, source / 'peer.go'], env)
            output = run([peer, native, fixtures], env)
            report['cases'] = [line for line in output.splitlines() if line.startswith('PASS Go-') or line.startswith('PASS native-Surf/')]
            assert len(report['cases']) == 25, report['cases']
            report['source_unchanged'] = before == manifest()
            assert report['source_unchanged'], 'Source changed during the owned matrix'
            report['source_sha256'] = before
            report['passed'] = True
    finally:
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': report['passed'], 'cases': len(report.get('cases', [])),
                      'report': str(args.report)}))


if __name__ == '__main__':
    main()
