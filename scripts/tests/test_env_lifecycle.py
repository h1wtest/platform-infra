import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import cli


class EnvironmentCredentialLifecycle(unittest.TestCase):
    def test_bootstrap_persists_reusable_owner_env_and_restores_derived_key(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = pathlib.Path(directory)
            state = workspace / 'platform-infra' / '.local'
            (workspace / 'identity-service').mkdir()
            (workspace / 'user-notification-service').mkdir()
            first = cli.create_secrets(state)
            for repository in ('platform-infra', 'identity-service', 'user-notification-service'):
                self.assertTrue((workspace / repository / '.env').is_file(), repository)
            self.assertFalse((state / 'secrets.json').exists())
            key = state / 'signing.pem'
            original = key.read_bytes()
            key.unlink()
            second = cli.create_secrets(state)
            self.assertEqual(first, second)
            self.assertEqual(key.read_bytes(), original)

    def test_missing_owner_env_never_rotates_existing_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = pathlib.Path(directory)
            state = workspace / 'platform-infra' / '.local'
            (workspace / 'identity-service').mkdir()
            (workspace / 'user-notification-service').mkdir()
            cli.create_secrets(state)
            key = (state / 'ca.key').read_bytes()
            path = workspace / 'identity-service' / '.env'
            self.assertTrue(path.is_file())
            path.unlink()
            with self.assertRaises(RuntimeError):
                cli.create_secrets(state)
            self.assertFalse(path.exists())
            self.assertEqual((state / 'ca.key').read_bytes(), key)

    def test_bootstrap_uses_user_dotenv_without_executing_or_interpolating_values(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = pathlib.Path(directory)
            state = workspace / 'platform-infra' / '.local'
            identity = workspace / 'identity-service'
            notifications = workspace / 'user-notification-service'
            identity.mkdir()
            notifications.mkdir()
            password = 'literal-$HOME-$(touch never)-#-secret'
            (identity / '.env').write_text('ADMIN_PASSWORD=' + password + '\nADMIN_EMAIL=owner@example.test\n')
            (notifications / '.env').write_text('TELEGRAM_BOT_TOKEN=123456:example\n')
            values = cli.create_secrets(state)
            self.assertEqual(values['admin_password'], password)
            self.assertEqual(values['admin_email'], 'owner@example.test')
            self.assertEqual(values['telegram_bot_token'], '123456:example')
            self.assertEqual(cli.create_secrets(state), values)


if __name__ == '__main__':
    unittest.main()
