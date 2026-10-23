import base64
import json
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest.mock import Mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
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



if __name__ == '__main__':
    unittest.main()
