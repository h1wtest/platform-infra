"""Operator mistakes must fail before migrations or release mutations."""
import contextlib
import io
from pathlib import Path
import sys
import unittest
import json
import tempfile
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cli
import release_control


class ReleaseArguments(unittest.TestCase):
    def test_service_update_requires_immutable_target_and_real_probe(self):
        cases = [
            ['release'],
            ['release', '--service', 'profile-service', '--image', 'example/profile:latest', '--probe', 'true'],
            ['release', '--service', 'redpanda', '--image', 'example/profile@sha256:' + 'a' * 64, '--probe', 'true'],
            ['release', '--service', 'profile-service', '--image', 'example/profile@sha256:' + 'a' * 64],
            ['release', '--service', 'profile-service', '--image', 'example/profile@sha256:' + 'a' * 64, '--probe', '  '],
            ['release', '--service', 'profile-service', '--image', 'example/profile@sha256:' + 'a' * 64, '--probe', 'true', '--timeout', '0'],
        ]
        for args in cases:
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    cli.parse_arguments(args)
                self.assertEqual(raised.exception.code, 2)

    def test_selected_service_and_probe_arguments_are_preserved(self):
        image = 'example/profile@sha256:' + 'a' * 64
        args = cli.parse_arguments(['release', '--service', 'profile-service', '--image', image,
                                    '--probe', 'uv run --no-project python "real probe.py"', '--timeout', '180'])
        self.assertEqual((args.service, args.image, args.timeout), ('profile-service', image, 180))
        self.assertEqual(args.probe, 'uv run --no-project python "real probe.py"')

    def test_local_image_name_matches_target_before_any_release_mutation(self):
        runtime = SimpleNamespace(manifests=cli.manifests)
        image = 'sso-remediation/profile-candidate:sha256-' + 'a' * 64
        with self.assertRaises(ValueError):
            release_control.service_image(runtime, 'profile-service', image)
        canonical = 'sso-remediation/profile:sha256-' + 'a' * 64
        self.assertEqual(release_control.service_image(runtime, 'profile-service', canonical), canonical)

    def test_saved_independent_image_survives_full_build_lock_without_touching_siblings(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            image = 'sso-remediation/profile:sha256-' + 'b' * 64
            (state / 'release-images.json').write_text(json.dumps({'profile-service': image}))
            base = {'profile': 'old-profile', 'identity': 'unchanged-identity'}
            runtime = SimpleNamespace(STATE=state, manifests=cli.manifests)
            result = release_control.selected_images(runtime, base)
            self.assertEqual(result['profile'], image)
            self.assertEqual(result['profile_id'], 'sha256:' + 'b' * 64)
            self.assertEqual(result['identity'], 'unchanged-identity')
            self.assertEqual(base, {'profile': 'old-profile', 'identity': 'unchanged-identity'})

    def test_saved_selection_rejects_infrastructure_or_mutable_images(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            runtime = SimpleNamespace(STATE=state, manifests=cli.manifests)
            for selection in ({'redpanda': 'registry/redpanda@sha256:' + 'a' * 64},
                              {'profile-service': 'registry/profile:latest'}, []):
                (state / 'release-images.json').write_text(json.dumps(selection))
                with self.subTest(selection=selection), self.assertRaises((RuntimeError, ValueError)):
                    release_control.selected_images(runtime, {})

    def test_full_up_reconciles_recovered_image_instead_of_redeploying_rejected_selection(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            rejected = 'sso-remediation/profile:sha256-' + 'b' * 64
            recovered = 'sso-remediation/profile:sha256-' + 'a' * 64
            path = state / 'release-images.json'
            path.write_text(json.dumps({'profile-service': rejected}))
            runtime = SimpleNamespace(STATE=state, manifests=cli.manifests)
            with patch('helm_release.status', return_value={'status': 'deployed'}), patch('helm_release.current_values', return_value={'image': recovered}):
                result = release_control.selected_images(runtime, {'identity': 'unchanged'}, reconcile=True)
            self.assertEqual(result['profile'], recovered)
            self.assertEqual(result['identity'], 'unchanged')
            self.assertEqual(json.loads(path.read_text()), {'profile-service': recovered})
            path.write_text(json.dumps({'profile-service': rejected}))
            with patch('helm_release.status', return_value={'status': 'pending-rollback'}):
                with self.assertRaises(RuntimeError):
                    release_control.selected_images(runtime, {}, reconcile=True)
            self.assertEqual(json.loads(path.read_text()), {'profile-service': rejected})


if __name__ == '__main__':
    unittest.main()
