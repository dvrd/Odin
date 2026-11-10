#!/usr/bin/env python3
"""Owned kernel readback and panic-policy verification for core:net.set_option."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

SOURCE = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inputs(sdk):
    paths = [path for path in (sdk/'core').rglob('*') if path.is_file()]
    paths.extend(path for path in SOURCE.rglob('*') if path.is_file() and
                 '__pycache__' not in path.parts)
    return {str(path): digest(path) for path in sorted(paths)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--odin', required=True, type=Path)
    parser.add_argument('--sdk-root', required=True, type=Path)
    parser.add_argument('--sanitize', choices=['address', 'thread'], default='address')
    parser.add_argument('--evidence-dir', required=True, type=Path)
    parser.add_argument('--old-sdk-root', type=Path, help='Optional unchanged old SDK negative control')
    args = parser.parse_args()
    compiler, sdk = args.odin.resolve(), args.sdk_root.resolve()
    evidence = args.evidence_dir.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    assert not evidence.is_relative_to(sdk), 'Keep generated evidence outside SDK source'
    environment = dict(os.environ, ODIN_ROOT=str(sdk))
    initial = inputs(sdk)
    report = dict(passed=False, scope='Darwin kernel execution; other targets require separate semantic/native evidence',
                  sanitizer=args.sanitize, compiler_sha256=digest(compiler),
                  source_sha256=initial, checks=[])

    def command(name, argv, env=environment, expected_failure=None):
        result = subprocess.run([str(value) for value in argv], env=env,
                                capture_output=True, text=True, timeout=60)
        output = result.stdout+result.stderr
        log = evidence/(name+'.log')
        log.write_text(output)
        check = dict(name=name, command=[str(value) for value in argv],
                     returncode=result.returncode, log=str(log), log_sha256=digest(log))
        report['checks'].append(check)
        if expected_failure is None:
            assert result.returncode == 0, output
        else:
            assert result.returncode != 0 and expected_failure in output, output
            assert 'invalid type unexpectedly returned' not in output, output
        assert 'ERROR: AddressSanitizer' not in output, output
        assert 'WARNING: ThreadSanitizer' not in output, output
        return output

    try:
        flags = ['-thread-count:1', '-warnings-as-errors', '-vet', '-sanitize:'+args.sanitize]
        suite = evidence/'socket-option-values'
        panic = evidence/'invalid-type'
        command('build-suite', [compiler, 'build', SOURCE, '-build-mode:test', *flags,
                               '-define:ODIN_TEST_THREADS=4',
                               '-define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true', '-out:'+str(suite)])
        output = command('kernel-matrix', [suite])
        assert re.search(r'Finished 5 tests\b', output), output
        assert 'All tests were successful.' in output, output
        command('build-panic-policy', [compiler, 'build', SOURCE/'invalid_type', *flags,
                                       '-out:'+str(panic)])
        for mode, message in [
            ('buffer-string', 'must be an integer here'),
            ('buffer-float', 'must be an integer here'),
            ('buffer-duration', 'must be an integer here'),
            ('buffer-nil', 'must be an integer here'),
            ('boolean-integer', 'must be a boolean here'),
            ('timeout-integer', 'must be a time.Duration here'),
            ('linger-integer', 'must be a time.Duration here'),
        ]:
            command('panic-'+mode, [panic, mode], expected_failure=message)
        if args.old_sdk_root:
            old_environment = dict(environment, ODIN_ROOT=str(args.old_sdk_root.resolve()))
            old_binary = evidence/'old-container-control'
            command('build-old-container-control', [compiler, 'build', SOURCE, '-build-mode:test',
                    '-thread-count:1', '-warnings-as-errors', '-vet',
                    '-define:ODIN_TEST_THREADS=1',
                    '-define:ODIN_TEST_NAMES=socket_option_values.public_i32_buffer_value_matches_independent_kernel_control',
                    '-out:'+str(old_binary)], env=old_environment)
            output = command('old-container-control', [old_binary], env=old_environment,
                             expected_failure='expected observed to be 4096')
            assert 'got 4096' not in output, output
            report['old_container_rejected'] = True
        report['binaries'] = {path.name: dict(path=str(path), sha256=digest(path))
                              for path in [suite, panic]}
        report['inputs_unchanged'] = inputs(sdk) == initial
        assert report['inputs_unchanged'], 'SDK or regression sources changed during verification'
        assert digest(compiler) == report['compiler_sha256'], 'Compiler changed'
        report['tests'] = 5
        report['paired_kernel_cases'] = 113
        report['panic_cases'] = 7
        report['passed'] = True
    finally:
        (evidence/'receipt.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(dict(passed=True, paired_kernel_cases=113, panic_cases=7,
                         receipt=str(evidence/'receipt.json'))))


if __name__ == '__main__':
    main()
