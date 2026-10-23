import pathlib
import tempfile
import unittest
import sys
import json
import subprocess
import types
import shutil
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import cli


class SecurityMaterialBehavior(unittest.TestCase):
    def test_legacy_key_refuses_automatic_purpose_key_generation(self):
        import security_material
        with tempfile.TemporaryDirectory() as directory:
            values = {'encryption_key': 'legacy-ciphertext-owner-key'}
            with self.assertRaises(RuntimeError):
                security_material.ensure(pathlib.Path(directory), values, cli.run)
            self.assertEqual(values, {'encryption_key': 'legacy-ciphertext-owner-key'})

    def test_private_service_keys_and_encryption_purposes_are_distinct(self):
        with tempfile.TemporaryDirectory() as directory:
            state = pathlib.Path(directory) / 'platform-infra' / '.local'
            for owner in ('identity-service', 'user-notification-service'):
                (pathlib.Path(directory) / owner).mkdir()
            values = cli.create_secrets(state)
            keys = [values[key] for key in ('mfa_encryption_key', 'delivery_encryption_key', 'profile_quarantine_key', 'notification_quarantine_key', 'admin_quarantine_key')]
            self.assertEqual(len(keys), len(set(keys)))
            identity = state / 'certificates/identity-service'
            profile = state / 'certificates/profile-service'
            self.assertNotEqual((identity / 'tls.key').read_bytes(), (profile / 'tls.key').read_bytes())
            cli.run(['openssl', 'verify', '-CAfile', state / 'ca.crt', '-verify_hostname', 'identity-service', identity / 'tls.crt'])
            with self.assertRaises(RuntimeError):
                cli.run(['openssl', 'verify', '-CAfile', state / 'ca.crt', '-verify_hostname', 'identity-service', profile / 'tls.crt'])
            self.assertEqual(values, cli.create_secrets(state))

    def test_explicit_unused_legacy_bootstrap_preserves_root_identity_and_credentials(self):
        import env_secrets
        import rekey
        with tempfile.TemporaryDirectory() as directory:
            workspace = pathlib.Path(directory)
            state = workspace / 'platform-infra' / '.local'
            state.mkdir(parents=True)
            for owner in ('identity-service', 'user-notification-service'):
                (workspace / owner).mkdir()
            for name in ('ca.key', 'tls.key', 'signing.pem'):
                cli.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', state / name])
            cli.run(['openssl', 'req', '-x509', '-new', '-key', state / 'ca.key', '-subj', '/CN=Legacy unused CA', '-days', '1', '-out', state / 'ca.crt'])
            shutil.copyfile(state / 'ca.crt', state / 'tls.crt')
            (state / 'backup.key').write_bytes(b'legacy-backup-key\n')
            values = {key: 'preserved-' + key for key in env_secrets.REQUIRED_KEYS
                      if key not in env_secrets.PURPOSE_KEYS and not key.startswith('kafka_') and key != 'gateway_token'}
            values.update(encryption_key='legacy-shared-key', telegram_bot_token='')
            legacy = state / 'secrets.json'
            legacy.write_text(json.dumps(values))
            before = {name: (state / name).read_bytes() for name in ('ca.key', 'ca.crt', 'tls.key', 'tls.crt', 'signing.pem', 'backup.key')}
            def run(command, **kwargs):
                if command[:4] == ['kubectl', 'config', 'get-contexts', '-o']:
                    return subprocess.CompletedProcess(command, 0, b'')
                if command[:3] == ['k3d', 'cluster', 'list']:
                    return subprocess.CompletedProcess(command, 0, b'[]')
                return cli.run(command, **kwargs)
            runtime = types.SimpleNamespace(STATE=state, CONTEXT='test-context', CLUSTER='test-cluster', run=run, create_secrets=cli.create_secrets)
            original_legacy = legacy.read_bytes()
            def occupied(command, **kwargs):
                if command[:3] == ['k3d', 'cluster', 'list']:
                    return subprocess.CompletedProcess(command, 0, b'[{"name":"test-cluster"}]')
                return run(command, **kwargs)
            runtime.run = occupied
            with self.assertRaisesRegex(RuntimeError, 'cannot prove empty'):
                rekey.execute(runtime, unused=True)
            self.assertEqual(legacy.read_bytes(), original_legacy)
            self.assertFalse((state.parent / '.env').exists())
            runtime.run = run
            rekey.execute(runtime, unused=True)
            saved = env_secrets.load(state)
            for key, value in values.items():
                if key != 'encryption_key':
                    self.assertEqual(saved[key], value)
            self.assertNotIn('encryption_key', saved)
            self.assertFalse(legacy.exists())
            self.assertEqual(before, {name: (state / name).read_bytes() for name in before})
            self.assertEqual(saved, cli.create_secrets(state))
            archive = next(state.glob('unused-legacy-key-*.json'))
            self.assertEqual(json.loads(archive.read_text())['keys']['encryption_key'], values['encryption_key'])


if __name__ == '__main__': unittest.main()
