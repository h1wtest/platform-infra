"""Database URL credentials retain literal dotenv characters and TLS boundaries."""
import base64
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, unquote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cli
import env_secrets
import manifests
import schema_gate
import security_material
import helm_release
from release_values import release_specs
from types import SimpleNamespace


class DatabaseCredentialURLs(unittest.TestCase):
    PASSWORD = 'spaces @:/?#&=%+ \\"\'\nпароль'

    def assert_url(self, value, username, password, database):
        parsed = urlsplit(value)
        self.assertEqual(parsed.scheme, 'postgresql')
        self.assertEqual(parsed.hostname, 'postgres-rw.sso-remediation.svc')
        self.assertEqual(parsed.port, 5432)
        self.assertEqual(unquote(parsed.username), username)
        self.assertEqual(unquote(parsed.password), password)
        self.assertEqual(unquote(parsed.path[1:]), database)
        self.assertEqual(parsed.fragment, '')
        self.assertEqual(parse_qs(parsed.query), {
            'sslmode': ['verify-full'], 'sslrootcert': ['/run/postgres/ca.crt']})

    def fixture(self, directory):
        workspace = Path(directory)
        state = workspace / 'platform-infra' / '.local'
        state.mkdir(parents=True)
        for owner in ('identity-service', 'user-notification-service'):
            (workspace / owner).mkdir()
        values = {key: 'fixture-' + key for key in env_secrets.REQUIRED_KEYS}
        for database in manifests.DBS:
            for role in ('runtime', 'migration'):
                values[database + '_' + role + '_password'] = self.PASSWORD + database + role
        env_secrets.save(state, values)
        return state, values

    def test_database_url_encodes_all_dynamic_components_without_changing_credentials(self):
        username = 'user:/@?#%+ space'
        database = 'database/@?#%+ space'
        self.assert_url(manifests.database_url(username, self.PASSWORD, database),
                        username, self.PASSWORD, database)

    def test_infrastructure_database_secrets_preserve_runtime_and_migration_passwords(self):
        with tempfile.TemporaryDirectory() as directory:
            state, values = self.fixture(directory)
            (state / 'ca.crt').write_bytes(b'fixture certificate')
            (state / 'signing.pem').write_bytes(b'fixture signing key')
            for service in security_material.SERVICES:
                leaf = state / 'certificates' / service
                leaf.mkdir(parents=True)
                (leaf / 'tls.crt').write_bytes(b'fixture certificate')
                (leaf / 'tls.key').write_bytes(b'fixture private key')
            databases = {}
            runtime = SimpleNamespace(ROOT=cli.ROOT, STATE=state, NS=cli.NS, CONTEXT=cli.CONTEXT, run=cli.run, kube=cli.kube)
            images = {**cli.PINS, **{target: 'fixture/' + target for target in ('identity', 'profile', 'notification', 'worker', 'admin', 'frontend')}}
            spec = release_specs(images, state, cli.ROOT)['platform-config']
            for resource in helm_release.render(runtime, 'platform-config', spec):
                name = resource['metadata']['name']
                if resource['kind'] == 'Secret' and name in {db + '-database' for db in manifests.DBS}:
                    databases[name] = resource['data']
                    if len(databases) == len(manifests.DBS):
                        break
            self.assertEqual(len(databases), len(manifests.DBS))
            for database in manifests.DBS:
                for role, key in (('runtime', 'DATABASE_URL'), ('migration', 'MIGRATION_DATABASE_URL')):
                    url = base64.b64decode(databases[database + '-database'][key]).decode()
                    self.assert_url(url, database + '_' + role,
                                    values[database + '_' + role + '_password'], database + '_db')

    def test_schema_probe_secret_preserves_both_role_passwords(self):
        class CapturedSecret(Exception):
            pass
        captured = []
        def capture(resources):
            captured.extend(resources)
            raise CapturedSecret()
        with tempfile.TemporaryDirectory() as directory:
            state, values = self.fixture(directory)
            with patch.object(cli, 'STATE', state), patch.object(cli, 'load_images', return_value={'identity': 'fixture-image'}), \
                    patch.object(cli, 'dbsql'), patch.object(cli, 'kube'), patch.object(cli, 'apply', side_effect=capture):
                with self.assertRaises(CapturedSecret):
                    schema_gate.verify()
            self.assertEqual(len(captured), 1)
            for role in ('runtime', 'migration'):
                url = base64.b64decode(captured[0]['data'][role]).decode()
                database = unquote(urlsplit(url).path[1:])
                self.assertRegex(database, r'^schema_gate_[0-9a-f]{10}$')
                self.assert_url(url, 'identity_' + role, values['identity_' + role + '_password'], database)


if __name__ == '__main__':
    unittest.main()
