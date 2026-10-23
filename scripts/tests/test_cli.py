"""Operator mistakes fail before prerequisites, locks or cluster mutations."""
import contextlib
import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import patch

import subprocess
import sys
import tempfile
spec = importlib.util.spec_from_file_location('operator_cli', Path(__file__).resolve().parents[1] / 'cli.py')
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)


class CommandBoundaryTests(unittest.TestCase):
    def test_invalid_arguments_fail_before_tool_checks(self):
        cases = [
            (['restore-verify'], '--backup'),
            (['restore-verify', '--backup', ''], '--backup'),
            (['restore-verify', '--backup', '   '], '--backup'),
            (['chaos'], '--probe'),
            (['chaos', '--probe', '   '], '--probe'),
            (['chaos', '--probe', '"unterminated'], '--probe'),
            (['chaos', '--probe', 'probe', '--target', 'unknown'], '--target'),
            (['up', '--unused'], '--unused'),
            (['chaos', '--probe', "''"], '--probe'),
            (['check', '--backup', 'backup'], '--backup'),
            (['status', '--target', 'postgres'], '--target'),
            (['backup', '--probe', 'probe'], '--probe'),
            (['cluster-identity', '--initialize'], '--initialize'),
            (['start', '--reset'], '--reset'),
        ]
        for arguments, diagnostic in cases:
            with self.subTest(arguments=arguments):
                errors = io.StringIO()
                with patch.object(cli, 'require_tools', side_effect=AssertionError('tools must not run')):
                    with patch('sys.argv', ['cli.py', *arguments]), contextlib.redirect_stderr(errors):
                        with self.assertRaises(SystemExit) as raised:
                            cli.main()
                self.assertEqual(raised.exception.code, 2)
                self.assertIn(diagnostic, errors.getvalue())

    def test_restore_path_preserves_spaces(self):
        arguments = cli.parse_arguments(['restore-verify', '--backup', 'saved backups/complete'])
        self.assertEqual(arguments.backup, Path('saved backups/complete'))

    def test_chaos_defaults_target_and_preserves_quoted_probe(self):
        arguments = cli.parse_arguments(['chaos', '--probe', "uv run --no-project python 'business probe.py'"])
        self.assertEqual(arguments.target, 'identity-service')
        self.assertEqual(arguments.probe, "uv run --no-project python 'business probe.py'")

    def test_unused_key_cutover_is_explicit(self):
        self.assertFalse(cli.parse_arguments(['rekey']).unused)
        self.assertTrue(cli.parse_arguments(['rekey', '--unused']).unused)

    def test_generic_owner_release_choices_follow_argument_profile_without_global_configuration(self):
        image = 'example.invalid/owner@sha256:' + '1' * 64
        for owner in ('catalog', 'billing', 'subscription', 'referral'):
            for command, options in (('release', ['--image', image]),
                                     ('release-rollback', ['--revision', '1'])):
                arguments = [command, '--service', owner + '-service', *options, '--probe', 'true']
                with self.subTest(owner=owner, command=command):
                    generic = cli.parse_arguments(['--profile', 'generic', '--context',
                                                   'k3d-sso-remediation', *arguments])
                    self.assertEqual(generic.service, owner + '-service')
                    with contextlib.redirect_stderr(io.StringIO()):
                        with self.assertRaises(SystemExit) as raised:
                            cli.parse_arguments(arguments)
                    self.assertEqual(raised.exception.code, 2)

    def test_generic_schema_gate_refuses_before_tools_or_original_state_access(self):
        with patch.object(cli, 'require_tools', side_effect=AssertionError('tools must not run')):
            with patch('sys.argv', ['cli.py', '--profile', 'generic', '--context',
                                    'k3d-sso-remediation', 'schema-gate']):
                with self.assertRaisesRegex(RuntimeError, 'namespace-only'):
                    cli.main()
        cli.configure_profile('default', None)

    def test_owned_port_forward_failure_cannot_fall_back_to_other_listener(self):
        with subprocess.Popen([sys.executable, '-c', 'raise SystemExit(1)'], stdout=subprocess.PIPE) as process:
            with self.assertRaisesRegex(RuntimeError, 'forward'):
                cli.wait_port_forward(process, 39090, 9090, timeout=2)
        self.assertTrue(process.stdout.closed)

    def test_owned_port_forward_requires_exact_selected_port_readiness(self):
        with subprocess.Popen([sys.executable, '-c',
            'import time; print("Forwarding from 127.0.0.1:39090 -> 9090", flush=True); time.sleep(10)'],
            stdout=subprocess.PIPE) as process:
            try:
                cli.wait_port_forward(process, 39090, 9090, timeout=2)
            finally:
                process.terminate()
                process.wait(timeout=5)
        self.assertTrue(process.stdout.closed)

    def test_generic_restore_command_requires_writable_database_before_restoration(self):
        import cluster_identity
        for writable in ('t', 'f'):
            with self.subTest(writable=writable), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / 'platform-infra'
                root.mkdir()
                backup = Path(directory) / 'saved backup'
                calls = []
                def query(statement):
                    self.assertEqual(statement, 'SELECT NOT pg_is_in_recovery()')
                    calls.append('readiness')
                    return writable
                def restore(selected):
                    self.assertEqual(selected, backup)
                    self.assertEqual(cli.NS, 'generic-subscriptions')
                    self.assertEqual(cli.STATE, root / '.generic-local')
                    self.assertTrue((cli.STATE / 'fault.lock').is_file())
                    calls.append('restore')
                arguments = ['cli.py', '--profile', 'generic', '--context',
                             'k3d-sso-remediation', 'restore-verify', '--backup', str(backup)]
                with patch.object(cli, 'ROOT', root), patch.object(cli, 'require_tools'), \
                        patch.object(cli, 'kube'), patch.object(cli, 'dbsql', side_effect=query), \
                        patch.object(cli, 'restore_verify', side_effect=restore), \
                        patch.object(cluster_identity, 'guard'), \
                        patch.dict(sys.modules, {'operator_cli': cli}), patch('sys.argv', arguments):
                    try:
                        if writable == 't':
                            cli.main()
                            self.assertEqual(calls, ['readiness', 'restore'])
                        else:
                            with self.assertRaisesRegex(RuntimeError, 'not writable'):
                                cli.main()
                            self.assertEqual(calls, ['readiness'])
                    finally:
                        cli.configure_profile('default', None)
        cli.configure_profile('default', None)

    def test_help_requires_no_external_tools(self):
        for arguments in (['--help'], ['rekey', '--help'], ['chaos', '--help']):
            with self.subTest(arguments=arguments):
                with patch.object(cli, 'require_tools', side_effect=AssertionError('tools must not run')):
                    with patch('sys.argv', ['cli.py', *arguments]), contextlib.redirect_stdout(io.StringIO()):
                        with self.assertRaises(SystemExit) as raised:
                            cli.main()
                self.assertEqual(raised.exception.code, 0)


if __name__ == '__main__':
    unittest.main()
