import pathlib
import tempfile
import unittest
import sys
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
            state = pathlib.Path(directory)
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


if __name__ == '__main__': unittest.main()
