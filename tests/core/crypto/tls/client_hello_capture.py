#!/usr/bin/env python3
"""Generate independent Go/OpenSSL ClientHellos in temporary storage; no network."""
import argparse
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--odin', required=True)
parser.add_argument('--go', default='go')
parser.add_argument('--go-root')
args = parser.parse_args()
root = Path(__file__).resolve().parents[4]
generators = root / 'core/crypto/tls/testdata'
checker = root / 'tests/core/crypto/tls/testdata/server_hello'
with tempfile.TemporaryDirectory(prefix='odin-clienthello-') as temporary:
    temp = Path(temporary)
    captures = temp / 'core/crypto/tls/testdata'
    captures.mkdir(parents=True)
    environment = dict(os.environ, GOTOOLCHAIN='local', GOPROXY='off', GOSUMDB='off',
                       GOCACHE=str(temp / 'go-cache'), GOTMPDIR=str(temp))
    if args.go_root:
        environment['GOROOT'] = args.go_root

    def run(command, **kwargs):
        return subprocess.run(command, check=True, timeout=60, **kwargs)

    run([args.go, 'version'], env=environment)
    run([args.go, 'run', str(generators / 'generate_server_go_hello.go')],
        cwd=temp, env=environment)
    flags = subprocess.check_output(['pkg-config', '--cflags', '--libs', 'openssl'],
                                    text=True, timeout=10)
    run(['cc', str(generators / 'generate_server_openssl_hello.c'),
         '-o', str(temp / 'openssl-capture'), *shlex.split(flags)])
    run([str(temp / 'openssl-capture')], cwd=temp)
    run([str(Path(args.odin).resolve()), 'build', str(checker), '-sanitize:address',
         '-warnings-as-errors', '-out:' + str(temp / 'check')])
    run([str(temp / 'check'), str(captures / 'server_go_client_hello.wire'),
         str(captures / 'server_openssl_client_hello.wire')])
