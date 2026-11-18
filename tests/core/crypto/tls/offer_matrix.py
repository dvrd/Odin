#!/usr/bin/env python3
"""Offline OpenSSL interoperability for the Upstream offer of both engines.

Client half: the blocking client restricted to each cipher suite and group,
against `openssl s_server` holding Ed25519, RSA, ECDSA P-256 and ECDSA P-384
credentials and forced signature algorithms.
Server half: the asynchronous server engine against `openssl s_client`
restricted to each cipher suite and group, with RSA and ECDSA P-256
credentials (the only keys the credential store signs with).

Everything runs on loopback with fixtures from this repository.
"""
import argparse, json, pathlib, socket, subprocess, time

SUITES = ['TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256']
GROUPS = ['X25519MLKEM768', 'X448', 'P-384', 'X25519', 'P-256']


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def wait_listening(port, process):
    for _ in range(200):
        if process.poll() is not None:
            raise RuntimeError('server exited early: ' + process.stderr.read())
        with socket.socket() as s:
            s.settimeout(0.2)
            if s.connect_ex(('127.0.0.1', port)) == 0:
                return
        time.sleep(0.02)
    raise RuntimeError('server never listened')


def client_case(a, client, cert, key, roots, name, suite, group, sigalgs):
    port = free_port()
    command = [a.openssl, 's_server', '-accept', f'127.0.0.1:{port}', '-cert', str(cert), '-key', str(key),
               '-tls1_3', '-ciphersuites', suite, '-groups', group, '-rev', '-quiet']
    if sigalgs:
        command += ['-sigalgs', sigalgs]
    server = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        # The probe connection is closed before any TLS byte; s_server keeps accepting.
        wait_listening(port, server)
        result = subprocess.run([str(client), '127.0.0.1', str(port), str(roots), name, suite, group],
                                capture_output=True, text=True, timeout=30)
        if result.returncode != 0 or not result.stdout.startswith('OK '):
            raise RuntimeError(f'client {suite} {group} {sigalgs}: {result.stdout}{result.stderr}')
        return result.stdout.strip()
    finally:
        server.kill()
        server.communicate()


def server_case(a, server_binary, cert, key, roots, name, suite, groups, hellos=1):
    server = subprocess.Popen([str(server_binary), str(cert), str(key)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        line = server.stdout.readline()
        if not line.startswith('READY '):
            raise RuntimeError('server not ready: ' + line + server.stderr.read())
        command = [a.openssl, 's_client', '-connect', line.split()[1], '-tls1_3', '-ciphersuites', suite, '-groups', groups,
                   '-CAfile', str(roots), '-verify_return_error', '-servername', name, '-ign_eof', '-msg']
        result = subprocess.run(command, input='from openssl\n', capture_output=True, text=True, timeout=30)
        stdout, stderr = server.communicate(timeout=30)
        if server.returncode != 0 or 'served by odin' not in result.stdout or 'Verify return code: 0 (ok)' not in result.stdout:
            raise RuntimeError(f'server {suite} {groups}: {stdout}{stderr}\n{result.stdout[-2000:]}{result.stderr[-2000:]}')
        if result.stdout.count(', ClientHello') != hellos:
            raise RuntimeError(f'server {suite} {groups}: expected {hellos} ClientHello\n{result.stdout[:2000]}')
        if suite not in result.stdout:
            raise RuntimeError(f'server {suite} {groups}: suite not negotiated\n{result.stdout[-2000:]}')
        return stdout.strip().splitlines()[-1]
    finally:
        if server.poll() is None:
            server.kill()
            server.communicate()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--odin', required=True)
    p.add_argument('--openssl', default='openssl')
    p.add_argument('--build', required=True, help='directory for the two test binaries')
    p.add_argument('--report', required=True)
    a = p.parse_args()

    root = pathlib.Path(__file__).resolve().parents[4]
    here = root / 'tests/core/crypto/tls'
    credentials = here / 'credentials/testdata'
    mtls = root / 'core/crypto/tls/testdata/mtls'
    build = pathlib.Path(a.build)
    build.mkdir(parents=True, exist_ok=True)
    for program in ['client', 'server']:
        subprocess.run([a.odin, 'build', str(here / 'offer_matrix' / program), '-out:' + str(build / program)], check=True)

    ed25519 = (here / 'testdata/leaf.pem', here / 'testdata/key.pem', here / 'testdata/root.pem', 'localhost')
    rsa = (mtls / 'server.pem', mtls / 'server-key.pem', mtls / 'root.pem', 'localhost')
    p256 = (credentials / 'p256-valid.pem', credentials / 'p256.pem', credentials / 'p256-valid.pem', 'synthetic.invalid')
    p384 = (credentials / 'p384-valid.pem', credentials / 'p384.pem', credentials / 'p384-valid.pem', 'synthetic.invalid')

    report = {'openssl': subprocess.run([a.openssl, 'version'], capture_output=True, text=True).stdout.strip(), 'cases': [], 'passed': False}

    def record(name, output):
        report['cases'].append({'name': name, 'output': output})
        print(name + ': pass', flush=True)

    try:
        for suite in SUITES:
            for group in GROUPS:
                cert, key, roots, name = ed25519
                record(f'client {suite} {group} ed25519', client_case(a, build / 'client', cert, key, roots, name, suite, group, 'ed25519'))

        signatures = [(rsa, 'rsa_pss_rsae_sha256'), (rsa, 'rsa_pss_rsae_sha384'), (rsa, 'rsa_pss_rsae_sha512'),
                      (p256, 'ecdsa_secp256r1_sha256'), (p384, 'ecdsa_secp384r1_sha384')]
        for (cert, key, roots, name), sigalg in signatures:
            for suite in SUITES:
                record(f'client {suite} X25519 {sigalg}', client_case(a, build / 'client', cert, key, roots, name, suite, 'X25519', sigalg))

        for suite in SUITES:
            for group in GROUPS:
                record(f'server {suite} {group} rsa', server_case(a, build / 'server', *rsa, suite, group))
            record(f'server {suite} X25519 ecdsa-p256', server_case(a, build / 'server', *p256, suite, 'X25519'))

        # P-521 is outside the server's groups: the only share is unusable and
        # the server has to ask for the group it selected.
        for groups in ['P-521:X25519MLKEM768', 'P-521:X448', 'P-521:P-384:P-256']:
            record(f'server retry {groups}', server_case(a, build / 'server', *rsa, SUITES[1], groups, hellos=2))

        report['passed'] = True
    finally:
        pathlib.Path(a.report).write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': True, 'cases': len(report['cases']), 'report': a.report}))


if __name__ == '__main__':
    main()
