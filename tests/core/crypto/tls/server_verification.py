#!/usr/bin/env python3
"""Repeatable native server gate: credentials, engine, async TCP and consumers."""
import argparse
import hashlib
import json
import pathlib
import platform
import re
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--odin', required=True)
    parser.add_argument('--go', required=True)
    parser.add_argument('--go-root', required=True)
    parser.add_argument('--openssl', required=True)
    parser.add_argument('--sanitize', choices=['address', 'thread'], default='address')
    parser.add_argument('--report', required=True)
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parents[4]
    compiler = pathlib.Path(args.odin).resolve()
    source_root = root if (root/'ci/webtools_consumer_gate.py').is_file() else compiler.parent
    report = {
        'scope': 'native credentials/recordless engine/async TCP correctness and ownership; no platform/throughput certification',
        'platform': platform.platform(), 'machine': platform.machine(),
        'compiler_sha256': hashlib.sha256(compiler.read_bytes()).hexdigest(),
        'sanitizer': args.sanitize, 'checks': [], 'passed': False,
    }
    destination = pathlib.Path(args.report).resolve()

    def check(name, command, timeout=300):
        started = time.monotonic()
        result = subprocess.run([str(x) for x in command], cwd=root, capture_output=True,
                                text=True, timeout=timeout)
        record = {'name': name, 'command': [str(x) for x in command],
                  'returncode': result.returncode, 'stdout': result.stdout,
                  'stderr': result.stderr, 'seconds': time.monotonic() - started}
        report['checks'].append(record)
        if result.returncode:
            raise RuntimeError(f'{name} failed: {result.stdout}\n{result.stderr}')
        print(f'{name}: pass', flush=True)
        return result.stdout.strip()

    try:
        report['compiler_version'] = check('compiler', [compiler, 'version'])
        report['openssl_version'] = check('OpenSSL', [args.openssl, 'version'])
        with tempfile.TemporaryDirectory(prefix='webtools-verify157-') as temporary:
            temp = pathlib.Path(temporary)
            flags = ['-warnings-as-errors', '-sanitize:' + args.sanitize,
                     '-define:ODIN_TEST_THREADS=1', '-define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true']
            for name, package in [('server', root/'core/crypto/tls'),
                                  ('credentials', root/'core/crypto/tls/credentials'),
                                  ('credential-store', root/'core/crypto/tls/credentials/store'),
                                  ('native-client', source_root/'tests/core/crypto/tls')]:
                check(name, [compiler, 'test', package, *flags, '-out:' + str(temp/name)])
            check('Surf', [compiler, 'test', source_root/'shared/surf/tests', *flags,
                           '-out:' + str(temp/'surf')])
            check('public-owner', [compiler, 'run', source_root/'tests/core/crypto/tls/server_owner',
                                   '-warnings-as-errors', '-sanitize:' + args.sanitize,
                                   '-out:' + str(temp/'owner')])
            peer_report = temp/'peers.json'
            check('independent-peers', ['python3', root/'tests/core/crypto/tls/server_flight.py',
                  '--odin', compiler, '--go', args.go, '--go-root', args.go_root,
                  '--openssl', args.openssl, '--sanitize', args.sanitize, '--report', peer_report])
            report['peers'] = json.loads(peer_report.read_text())
            signing_report = temp/'signing.json'
            check('concurrent-signing', ['python3', root/'tests/core/crypto/tls/credentials/concurrency.py',
                  '--odin', compiler, '--go', args.go, '--go-root', args.go_root,
                  '--openssl', args.openssl, '--sanitize', args.sanitize, '--report', signing_report])
            report['signing'] = json.loads(signing_report.read_text())
            tcp_report = temp/'tcp.json'
            check('async-tcp', ['python3', root/'tests/core/crypto/tls/server_tcp.py',
                  '--odin', compiler, '--go', args.go, '--go-root', args.go_root,
                  '--openssl', args.openssl, '--sanitize', args.sanitize, '--report', tcp_report])
            report['tcp'] = json.loads(tcp_report.read_text())
            consumer_report = temp/'consumers.json'
            check('isolated-consumers', ['python3', source_root/'ci/webtools_consumer_gate.py',
                  '--odin', compiler, '--packages', 'surf', '--report', consumer_report])
            report['consumers'] = json.loads(consumer_report.read_text())
        output = next(x['stdout'] for x in report['checks'] if x['name'] == 'server')
        owner = re.search(r'retry fixed owner=(\d+) event=(\d+)', output)
        transient = re.search(r'retry max first\+second hello\+scratch=(\d+) bytes/(\d+) grants', output)
        if not owner or not transient:
            raise RuntimeError('missing server memory measurement evidence')
        report['measured_engine'] = {'owner_bytes': int(owner[1]), 'event_bytes': int(owner[2]),
                                    'retry_peak_grant_bytes': int(transient[1]),
                                    'simultaneous_grants': int(transient[2])}
        report['passed'] = True
    finally:
        destination.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': True, 'report': str(destination)}, indent=2))


if __name__ == '__main__':
    main()
