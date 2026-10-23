"""Operator mistakes fail before prerequisites, locks or cluster mutations."""
import contextlib
import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import patch

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
