#!/usr/bin/env python3
"""Verify public TCP options against owned loopback kernel readback (host native)."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess

SOURCE = Path(__file__).resolve().parent
NAMES = {
    'public_dial_default_matches_kernel',
    'public_dial_explicit_true_matches_kernel',
    'public_dial_explicit_false_matches_kernel',
    'public_accept_default_overrides_listener',
    'public_accept_explicit_true_overrides_listener',
    'public_accept_explicit_false_disables_inherited_true',
    'independent_kernel_accept_inherits_enabled_listener',
    'public_signatures_and_invalid_inputs_preserved',
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inputs(sdk):
    paths = [p for root in [sdk/'base', sdk/'core', SOURCE]
             for p in root.rglob('*') if p.is_file() and '__pycache__' not in p.parts]
    return {str(p): digest(p) for p in sorted(set(paths))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--odin', type=Path, required=True)
    parser.add_argument('--sdk-root', type=Path, required=True)
    parser.add_argument('--evidence-dir', type=Path, required=True)
    parser.add_argument('--expect-old-failure', action='store_true')
    args = parser.parse_args()
    sdk, compiler = args.sdk_root.resolve(), args.odin.resolve()
    evidence = args.evidence_dir.resolve()
    assert not evidence.is_relative_to(sdk), 'Evidence must stay outside SDK'
    evidence.mkdir(parents=True, exist_ok=False)
    source = inputs(sdk)
    compiler_hash = digest(compiler)
    environment = dict(os.environ, ODIN_ROOT=str(sdk))
    environment['PATH'] = '/opt/homebrew/opt/llvm@22/bin:' + environment.get('PATH', '')
    report = dict(passed=False, host=platform.platform(), scope='native host kernel only; no cross-platform execution claim',
                  old_negative_control=args.expect_old_failure, compiler=str(compiler),
                  compiler_sha256=compiler_hash, sources=source, cells=[])

    def execute(name, command):
        result = subprocess.run(list(map(str, command)), env=environment,
                                capture_output=True, text=True, timeout=60)
        log = evidence/(name+'.log')
        log.write_text(result.stdout+result.stderr)
        return result.returncode, log.read_text(), dict(command=list(map(str, command)),
            returncode=result.returncode, log=str(log), log_sha256=digest(log))

    try:
        version = subprocess.run([str(compiler), 'version'], env=environment,
                                 capture_output=True, text=True, timeout=10, check=True)
        report['compiler_version'] = version.stdout.strip()
        declarations = set(re.findall(r'@\(test\)\s+(\w+)\s*::', (SOURCE/'options_test.odin').read_text()))
        assert declarations == NAMES, declarations
        for sanitizer in ['address', 'thread']:
            for default in [True, False]:
                name = sanitizer+'-default-'+str(default).lower()
                binary = evidence/name
                flags = ['-thread-count:1', '-warnings-as-errors', '-vet', '-sanitize:'+sanitizer,
                         '-define:ODIN_TEST_THREADS=1', '-define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true',
                         '-define:ODIN_TEST_LOG_STATE_CHANGES=true', '-define:ODIN_TEST_FANCY=false',
                         '-define:ODIN_NET_TCP_NODELAY_DEFAULT='+str(default).lower()]
                code, output, build = execute(name+'-build', [compiler, 'build', SOURCE,
                    '-build-mode:test', *flags, '-out:'+str(binary)])
                assert code == 0, output
                binary_hash = digest(binary)
                code, output, run = execute(name+'-run', [binary])
                cell = dict(sanitizer=sanitizer, default=default, build=build, run=run,
                            binary=str(binary), binary_sha256=binary_hash)
                report['cells'].append(cell)
                assert re.search(r'Finished 8 tests\b', output), output
                actual = re.findall(r'Test #\d+ tcp_options\.(\w+) changed state to (Successful|Failed)\.', output)
                assert len(actual) == 8 and {n for n, _ in actual} == NAMES, output
                failed = [n for n, state in actual if state == 'Failed']
                if args.expect_old_failure:
                    assert code != 0 and len(failed) == (5 if default else 4), output
                else:
                    assert code == 0 and not failed and 'All tests were successful.' in output, output
                assert 'ERROR: AddressSanitizer' not in output and 'WARNING: ThreadSanitizer' not in output, output
                assert len(re.findall(r'^READBACK ', output, re.M)) == 7, output
                assert inputs(sdk) == source and digest(compiler) == compiler_hash, 'Inputs changed'
                assert digest(binary) == binary_hash, 'Binary changed'
                cell['tests'] = len(actual)
                cell['failed_tests'] = failed
                cell['passed'] = True
        report['inputs_unchanged'] = inputs(sdk) == source
        assert report['inputs_unchanged']
        report['tests_per_cell'] = 8
        report['total_test_executions'] = 32
        report['passed'] = True
    finally:
        (evidence/'receipt.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(dict(passed=True, cells=4, total_test_executions=32,
                         receipt=str(evidence/'receipt.json'))))


if __name__ == '__main__':
    main()
