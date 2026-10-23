"""Exercise Make dispatch without requiring or mutating a Kubernetes cluster."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

MAKEFILE = Path(__file__).resolve().parents[2] / 'Makefile'


class MakeDispatchTests(unittest.TestCase):
    def test_every_operator_target_runs_even_when_a_matching_file_exists(self):
        commands = {
            'bootstrap': ['secrets'], 'build': ['build'], 'up': ['up'],
            'check': ['check'], 'status': ['status'], 'stop': ['stop'],
            'start': ['start'], 'bootstrap-admin': ['bootstrap-admin'],
            'schedule-backups': ['schedule-backups'], 'backup': ['backup'],
            'restore-verify': ['restore-verify', '--backup', '.local/backups/complete'],
            'schema-gate': ['schema-gate'], 'repair-certificates': ['repair-certificates'],
            'rekey': ['rekey'],
            'chaos': ['chaos', '--target', 'identity-service', '--probe', 'sh scripts/acceptance/probe.sh'],
            'persistence': ['persistence'], 'alerts': ['alerts'], 'mailpit': ['mailpit'],
            'prometheus': ['prometheus'], 'grafana': ['grafana'], 'tempo': ['tempo'],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            recorder = root / 'recorder.py'
            recorder.write_text('import json, pathlib, sys\npathlib.Path("invocation.json").write_text(json.dumps(sys.argv[1:]))\n')
            python = f'{shlex.quote(sys.executable)} {shlex.quote(str(recorder))}'
            for target, arguments in commands.items():
                with self.subTest(target=target):
                    (root / target).touch()
                    subprocess.run(['make', '-f', str(MAKEFILE), target, f'PYTHON={python}', 'BACKUP=.local/backups/complete', 'PROBE=sh scripts/acceptance/probe.sh'], cwd=root, check=True, capture_output=True)
                    invocation = root / 'invocation.json'
                    self.assertEqual(json.loads(invocation.read_text()), ['scripts/cli.py', *arguments])
                    invocation.unlink()
            for target, arguments in {
                'test': ['-m', 'unittest', 'discover', '-s', 'scripts/tests', '-p', 'test_*.py'],
                'acceptance': ['scripts/acceptance/run.py', 'core'],
            }.items():
                with self.subTest(target=target):
                    (root / target).touch()
                    subprocess.run(['make', '-f', str(MAKEFILE), target, f'PYTHON={python}'], cwd=root, check=True, capture_output=True)
                    invocation = root / 'invocation.json'
                    self.assertEqual(json.loads(invocation.read_text()), arguments)
                    invocation.unlink()

    def test_backup_and_probe_arguments_preserve_shell_metacharacters(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            recorder = root / 'recorder.py'
            recorder.write_text('import json, pathlib, sys\npathlib.Path("invocation.json").write_text(json.dumps(sys.argv[1:]))\n')
            python = f'{shlex.quote(sys.executable)} {shlex.quote(str(recorder))}'
            backup = 'saved backups/owner\'s "copy"; $HOME'
            probe = 'uv run --no-project python -c "print(\'business probe\')"'
            for target, variable, value, expected in (
                ('restore-verify', 'BACKUP', backup, ['restore-verify', '--backup', backup]),
                ('chaos', 'PROBE', probe, ['chaos', '--target', 'identity-service', '--probe', probe]),
                ('rekey', 'ARGS', '--unused', ['rekey', '--unused']),
                ('acceptance', 'GATE', 'tls', None),
            ):
                with self.subTest(target=target):
                    subprocess.run(['make', '-f', str(MAKEFILE), target, f'PYTHON={python}', f'{variable}={value.replace("$", "$$")}'], cwd=root, check=True, capture_output=True)
                    actual = json.loads((root / 'invocation.json').read_text())
                    self.assertEqual(actual, ['scripts/cli.py', *expected] if expected else ['scripts/acceptance/run.py', 'tls'])

    def test_shared_host_fault_requires_explicit_make_flag_and_remains_phony(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'host-fault').touch()
            forward = root / 'wslpath'
            forward.write_text('#!/bin/sh\nprintf "%s\\n" "$2"\n')
            forward.chmod(0o700)
            observer = root / 'powershell.exe'
            observer.write_text(f'#!{sys.executable}\nimport json, pathlib, sys\npathlib.Path("host-invocation.json").write_text(json.dumps(sys.argv[1:]))\n')
            observer.chmod(0o700)
            environment = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'])
            expected = ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(root / 'scripts/verify-docker-host.ps1'), '-Repository', str(root)]
            for flag, suffix in (('', []), ('ALLOW_SHARED_HOST_OUTAGE=1', ['-AllowSharedHostOutage']), ('ALLOW_SHARED_HOST_OUTAGE=0', [])):
                with self.subTest(flag=flag):
                    subprocess.run(['make', '-f', str(MAKEFILE), 'host-fault', *([flag] if flag else [])], cwd=root, env=environment, check=True, capture_output=True)
                    self.assertEqual(json.loads((root / 'host-invocation.json').read_text()), expected + suffix)


if __name__ == '__main__':
    unittest.main()
