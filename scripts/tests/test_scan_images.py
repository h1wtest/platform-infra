"""Exercise scanner orchestration without Docker or registry requests."""
import contextlib
import io
import json
from pathlib import Path
import runpy
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'scan_images.py'


class ImageScanTests(unittest.TestCase):
    def scan(self, vulnerabilities, packages=None):
        with tempfile.TemporaryDirectory() as directory:
            calls = []
            saved = []
            report = {'Results': [{'Type': 'debian', 'Class': 'os-pkgs', 'Packages': [{'Name': 'example', 'Version': '1'}] if packages is None else packages, 'Vulnerabilities': vulnerabilities}]}
            runtime = types.ModuleType('cli')
            runtime.STATE = Path(directory)
            runtime.K3S = 'example/k3s@sha256:' + 'a' * 64
            runtime.PINS = {}
            runtime.PATCHED_COMPONENTS = {}

            def run(args, **kwargs):
                calls.append(args)
                return types.SimpleNamespace(returncode=0, stdout=json.dumps(report))

            runtime.run = run
            private_files = types.ModuleType('private_files')
            private_files.atomic_json = lambda path, value: saved.append((path, value))
            output = io.StringIO()
            error = None
            with patch.dict(sys.modules, {'cli': runtime, 'private_files': private_files}), contextlib.redirect_stdout(output):
                try:
                    runpy.run_path(str(SCRIPT), run_name='__main__')
                except SystemExit as caught:
                    error = caught
            return calls, saved, output.getvalue(), error

    def test_every_lower_severity_is_fatal_and_retained(self):
        for severity in ('LOW', 'MEDIUM', 'UNKNOWN'):
            with self.subTest(severity=severity):
                finding = {'VulnerabilityID': 'CVE-example', 'PkgName': 'example', 'InstalledVersion': '1', 'Severity': severity}
                calls, saved, output, error = self.scan([finding])
                self.assertNotIn('--severity', calls[0])
                self.assertEqual(saved[0][1]['Results'][0]['Vulnerabilities'], [finding])
                self.assertIn(severity + '=1', output)
                self.assertIsNotNone(error)
                self.assertIn('vulnerabilities (all severities)', str(error))

    def test_high_finding_remains_fatal_and_persisted(self):
        finding = {'VulnerabilityID': 'CVE-example', 'PkgName': 'example', 'InstalledVersion': '1', 'Severity': 'HIGH'}
        _, saved, output, error = self.scan([finding])
        self.assertEqual(len(saved), 1)
        self.assertIn('HIGH=1', output)
        self.assertIsNotNone(error)
        self.assertIn('vulnerabilities (all severities)', str(error))

    def test_empty_vulnerability_inventory_passes(self):
        _, saved, _, error = self.scan([])
        self.assertEqual(len(saved), 1)
        self.assertIsNone(error)

    def test_zero_package_inventory_is_not_clean(self):
        _, saved, _, error = self.scan([], packages=[])
        self.assertEqual(saved[0][1]['Results'][0]['Packages'], [])
        self.assertIsNotNone(error)
        self.assertIn('zero evaluated package inventories', str(error))
