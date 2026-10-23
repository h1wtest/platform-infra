import base64
import json
from pathlib import Path
import subprocess
import sys
import types
import unittest
import tempfile
from unittest.mock import Mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import env_secrets
import manifests
import rekey
import credential_guard


class StatefulCredentialGuard(unittest.TestCase):
    def fixture(self):
        values = {key: 'original-' + key for key in credential_guard.IMMUTABLE_KEYS}
        values['telegram_bot_token'] = 'original-token'
        data = {key: base64.b64encode(value.encode()).decode() for key, value in values.items()}
        runtime = types.SimpleNamespace(kube=Mock(return_value=subprocess.CompletedProcess([], 0, json.dumps({'data': data}).encode())))
        return runtime, values, data

    def test_fresh_namespace_has_no_prior_credentials(self):
        runtime = types.SimpleNamespace(kube=Mock(return_value=subprocess.CompletedProcess([], 0, b'')))
        credential_guard.verify(runtime, {})

    def test_unchanged_and_telegram_only_edit_allowed(self):
        runtime, values, _ = self.fixture()
        credential_guard.verify(runtime, values)
        values['telegram_bot_token'] = 'edited-token'
        credential_guard.verify(runtime, values)

    def test_each_stateful_credential_edit_refused_without_leaking_values(self):
        for key in credential_guard.IMMUTABLE_KEYS:
            with self.subTest(key=key):
                runtime, values, _ = self.fixture()
                values[key] = 'do-not-print-edited-secret'
                with self.assertRaisesRegex(RuntimeError, 'explicit rotation') as error:
                    credential_guard.verify(runtime, values)
                self.assertNotIn(values[key], str(error.exception))
                self.assertNotIn('original-', str(error.exception))

    def test_existing_incomplete_or_malformed_secret_fails_closed(self):
        for body in (b'{}', b'{"data":{}}', b'not-json', b'{"data":{"postgres_password":"%%%"}}'):
            runtime = types.SimpleNamespace(kube=Mock(return_value=subprocess.CompletedProcess([], 0, body)))
            with self.subTest(body=body), self.assertRaises(RuntimeError):
                credential_guard.verify(runtime, {})

    def test_completed_explicit_rekey_publishes_credentials_before_env_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            state = workspace / 'platform-infra' / '.local'
            state.mkdir(parents=True)
            for owner in ('identity-service', 'user-notification-service'):
                (workspace / owner).mkdir()
            values = {key: 'old-' + key for key in env_secrets.REQUIRED_KEYS if key not in env_secrets.PURPOSE_KEYS}
            values.update(encryption_key='legacy-key', telegram_bot_token='')
            env_secrets.save(state, values)
            stored = {'data': {key: base64.b64encode(value.encode()).decode() for key, value in values.items()}}
            completed_jobs = []
            partitions = [{'start_offset': 0, 'high_watermark': 0} for _ in range(6)]
            def kube(*args, **kwargs):
                result = b''
                if args[:3] == ('get', 'secret', 'platform-secrets'):
                    result = json.dumps(stored).encode()
                elif args[:2] == ('get', 'deployment'):
                    result = b'{"spec":{"replicas":1}}'
                elif 'topic' in args and 'describe' in args:
                    result = json.dumps(partitions).encode()
                elif 'group' in args and 'describe' in args:
                    result = json.dumps([{'topic': 'notification.commands.v1', 'current_offset': 0, 'log_end_offset': 0} for _ in range(6)]).encode()
                elif args[:2] == ('wait', '--for=condition=complete'):
                    completed_jobs.append(args[2])
                return subprocess.CompletedProcess(args, 0, result)
            def apply(objects):
                nonlocal stored
                for obj in objects:
                    if obj['kind'] == 'Secret' and obj['metadata']['name'] == 'platform-secrets':
                        self.assertEqual(len(completed_jobs), 4)
                        self.assertTrue(list(state.glob('rekey-complete-*.json')))
                        self.assertIn('encryption_key', env_secrets.load(state))
                        stored = obj
            runtime = types.SimpleNamespace(STATE=state, CONTEXT='test-context', NS='test-ns',
                run=lambda *a, **k: subprocess.CompletedProcess([], 0, b'test-context\n'),
                kube=kube, dbsql=lambda *a: '0', backup=lambda: None, apply=apply,
                load_images=lambda: {'postgres': 'test/postgres', **{target: 'test/' + target for target, _, _ in manifests.APPS.values()}})
            rekey.execute(runtime)
            final = env_secrets.load(state)
            self.assertNotIn('encryption_key', final)
            credential_guard.verify(runtime, final)
            self.assertEqual(len(completed_jobs), 4)


if __name__ == '__main__':
    unittest.main()
