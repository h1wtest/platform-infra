"""Owner-local dotenv credentials, migration durability and derived-key safety."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import env_secrets


class OwnerEnvironmentStore(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.workspace = Path(self.temporary.name)
        self.state = self.workspace / 'platform-infra' / '.local'
        self.state.mkdir(parents=True)
        for owner in ('identity-service', 'user-notification-service'):
            (self.workspace / owner).mkdir()
        self.values = {key: 'fixture-' + key for key in env_secrets.REQUIRED_KEYS}
        self.values['telegram_bot_token'] = ''
        self.private = {}
        for relative in env_secrets.PRIVATE_FILES:
            data = (b'backup-password-with-newline\r\n' if relative == 'backup.key'
                    else b'-----BEGIN PRIVATE KEY-----\r\nfixture-' + relative.encode() + b'\r\n-----END PRIVATE KEY-----\r\n')
            self.private[relative] = data

    def env(self, owner):
        return self.workspace / owner / '.env'

    def write_material(self):
        for relative, data in self.private.items():
            path = self.state / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        for relative in ('ca.crt', 'tls.crt', *('certificates/' + service + '/tls.crt' for service in (
                'identity-service', 'profile-service', 'notification-service', 'notification-worker',
                'admin-audit-service', 'gateway', 'redpanda'))):
            path = self.state / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'fixture public certificate\n')

    def legacy(self):
        self.write_material()
        (self.state / 'secrets.json').write_text(json.dumps(self.values), encoding='utf-8')

    def initialized(self):
        self.write_material()
        env_secrets.save(self.state, self.values)
        env_secrets.capture_private(self.state)
        env_secrets.initialize(self.state)

    def test_roundtrip_preserves_special_characters_without_interpolation(self):
        self.values['admin_password'] = ' p$HOME#x="quoted" \\ newline\nкириллица\t '
        env_secrets.save(self.state, self.values)
        self.assertEqual(env_secrets.load(self.state), self.values)

    def test_canonical_ownership_and_delivery_key_single_source(self):
        env_secrets.save(self.state, self.values)
        expected = {'postgres_password': 'platform-infra', 'gateway_token': 'platform-infra',
                    'grafana_password': 'platform-infra', 'kafka_bootstrap_password': 'platform-infra',
                    'admin_email': 'identity-service', 'admin_password': 'identity-service',
                    'identity_runtime_password': 'identity-service', 'identity_migration_password': 'identity-service',
                    'kafka_identity_password': 'identity-service', 'mfa_encryption_key': 'identity-service',
                    'delivery_encryption_key': 'identity-service', 'audit_runtime_password': 'user-notification-service',
                    'telegram_bot_token': 'user-notification-service', 'kafka_admin_password': 'user-notification-service'}
        for key, owner in expected.items():
            with self.subTest(key=key):
                for candidate in ('platform-infra', 'identity-service', 'user-notification-service'):
                    _, assignments = env_secrets._parse(self.env(candidate))
                    self.assertEqual(key.upper() in assignments, candidate == owner)
                    if candidate == owner:
                        self.assertEqual(assignments[key.upper()], self.values[key])

    def test_save_preserves_unrelated_configuration_comments_and_line_endings(self):
        original = b'# local overrides\r\nCUSTOM="literal # $HOME" # comment\r\n\r\n'
        self.env('identity-service').write_bytes(original)
        env_secrets.save(self.state, self.values)
        self.assertTrue(self.env('identity-service').read_bytes().startswith(original))
        self.values['admin_password'] = 'edited'
        env_secrets.save(self.state, self.values)
        self.assertTrue(self.env('identity-service').read_bytes().startswith(original))
        self.assertEqual(env_secrets.load(self.state), self.values)

    def test_telegram_edits_are_loaded_immediately_and_environment_is_not_override(self):
        env_secrets.save(self.state, self.values)
        path = self.env('user-notification-service')
        text = path.read_text().replace('TELEGRAM_BOT_TOKEN=""', 'TELEGRAM_BOT_TOKEN="edited:#=$HOME"')
        path.write_text(text)
        with patch.dict(os.environ, {'TELEGRAM_BOT_TOKEN': 'must-not-override'}):
            self.assertEqual(env_secrets.load(self.state)['telegram_bot_token'], 'edited:#=$HOME')

    def test_private_material_owner_mapping_and_exact_byte_derivation(self):
        self.initialized()
        expected = {'ca.key': ('platform-infra', 'CA_PRIVATE_KEY'),
                    'tls.key': ('platform-infra', 'TLS_PRIVATE_KEY'),
                    'backup.key': ('platform-infra', 'BACKUP_ENCRYPTION_KEY'),
                    'signing.pem': ('identity-service', 'SIGNING_PRIVATE_KEY'),
                    'certificates/identity-service/tls.key': ('identity-service', 'IDENTITY_SERVICE_TLS_PRIVATE_KEY'),
                    'certificates/gateway/tls.key': ('platform-infra', 'GATEWAY_TLS_PRIVATE_KEY'),
                    'certificates/redpanda/tls.key': ('platform-infra', 'REDPANDA_TLS_PRIVATE_KEY'),
                    'certificates/notification-worker/tls.key': ('user-notification-service', 'NOTIFICATION_WORKER_TLS_PRIVATE_KEY')}
        for relative, destination in expected.items():
            self.assertEqual(env_secrets.PRIVATE_FILES[relative], destination)
        for relative in self.private:
            (self.state / relative).unlink()
        env_secrets.materialize(self.state)
        for relative, data in self.private.items():
            self.assertEqual((self.state / relative).read_bytes(), data)

    def test_materialize_rejects_mismatch_without_overwriting_any_key(self):
        self.initialized()
        (self.state / 'backup.key').write_bytes(b'different\n')
        (self.state / 'ca.key').unlink()
        with self.assertRaisesRegex(RuntimeError, 'mismatch'):
            env_secrets.materialize(self.state)
        self.assertFalse((self.state / 'ca.key').exists())
        self.assertEqual((self.state / 'backup.key').read_bytes(), b'different\n')

    def test_migration_preserves_every_credential_private_byte_and_user_variable(self):
        self.legacy()
        self.values['encryption_key'] = 'legacy-rekey-key'
        (self.state / 'secrets.json').write_text(json.dumps(self.values))
        original = b'# preserved\nCUSTOM_SETTING=keep\n'
        self.env('platform-infra').write_bytes(original)
        self.assertEqual(env_secrets.migrate(self.state), self.values)
        self.assertFalse((self.state / 'secrets.json').exists())
        self.assertTrue(env_secrets.exists(self.state))
        self.assertTrue(self.env('platform-infra').read_bytes().startswith(original))
        self.assertEqual(env_secrets.load(self.state), self.values)
        snapshots = {owner: self.env(owner).read_bytes() for owner in set(env_secrets.OWNERS.values())}
        self.assertEqual(env_secrets.migrate(self.state), self.values)
        for owner, data in snapshots.items():
            self.assertEqual(self.env(owner).read_bytes(), data)
        for relative, data in self.private.items():
            (self.state / relative).unlink()
        env_secrets.materialize(self.state)
        for relative, data in self.private.items():
            self.assertEqual((self.state / relative).read_bytes(), data)

    def test_interrupted_environment_publication_retains_legacy_for_resume(self):
        self.legacy()
        real_replace = os.replace
        published = []
        def interrupted(source, destination):
            if Path(destination).name == '.env':
                published.append(destination)
                if len(published) == 2:
                    raise OSError('simulated interruption')
            return real_replace(source, destination)
        with patch.object(env_secrets.os, 'replace', side_effect=interrupted):
            with self.assertRaises(OSError):
                env_secrets.migrate(self.state)
        self.assertTrue((self.state / 'secrets.json').exists())
        self.assertEqual(env_secrets.migrate(self.state), self.values)
        self.assertFalse((self.state / 'secrets.json').exists())

    def test_interrupted_legacy_deletion_can_resume_after_marker_publication(self):
        self.legacy()
        real_unlink = Path.unlink
        def interrupted(path, *args, **kwargs):
            if path.name == 'secrets.json':
                raise OSError('simulated deletion interruption')
            return real_unlink(path, *args, **kwargs)
        with patch.object(Path, 'unlink', interrupted):
            with self.assertRaises(OSError):
                env_secrets.migrate(self.state)
        self.assertTrue((self.state / 'secrets.json').exists())
        self.assertEqual(env_secrets.load(self.state), self.values)
        self.assertEqual(env_secrets.migrate(self.state), self.values)

    def test_completed_migration_never_falls_back_to_leftover_json(self):
        self.legacy()
        env_secrets.migrate(self.state)
        (self.state / 'secrets.json').write_text(json.dumps(self.values))
        self.env('identity-service').unlink()
        with self.assertRaises(RuntimeError):
            env_secrets.load(self.state)
        with self.assertRaises(RuntimeError):
            env_secrets.migrate(self.state)
        self.assertFalse(self.env('identity-service').exists())

    def test_incomplete_legacy_import_never_publishes_or_deletes_source(self):
        self.legacy()
        (self.state / 'signing.pem').unlink()
        with self.assertRaises(RuntimeError):
            env_secrets.migrate(self.state)
        self.assertTrue((self.state / 'secrets.json').exists())
        self.assertFalse(self.env('platform-infra').exists())

    def test_existing_conflicting_canonical_credential_is_not_overwritten(self):
        self.legacy()
        self.env('identity-service').write_text('ADMIN_PASSWORD="different"\n')
        with self.assertRaisesRegex(RuntimeError, 'conflict'):
            env_secrets.migrate(self.state)
        self.assertTrue((self.state / 'secrets.json').exists())
        self.assertEqual(self.env('identity-service').read_text(), 'ADMIN_PASSWORD="different"\n')
        self.assertFalse(self.env('platform-infra').exists())

    def test_missing_or_empty_required_value_fails_without_regeneration(self):
        self.initialized()
        path = self.env('identity-service')
        original = path.read_text()
        for replacement in ('', 'ADMIN_PASSWORD=""\n'):
            with self.subTest(replacement=replacement):
                path.write_text(''.join(line for line in original.splitlines(keepends=True)
                                        if not line.startswith('ADMIN_PASSWORD=')) + replacement)
                before = path.read_bytes()
                with self.assertRaises(RuntimeError):
                    env_secrets.load(self.state)
                self.assertEqual(path.read_bytes(), before)
        path.unlink()
        self.assertTrue(env_secrets.exists(self.state))

    def test_missing_private_environment_value_cannot_be_recaptured_after_initialization(self):
        self.initialized()
        path = self.env('platform-infra')
        path.write_text(''.join(line for line in path.read_text().splitlines(keepends=True)
                                if not line.startswith('BACKUP_ENCRYPTION_KEY=')))
        with self.assertRaises(RuntimeError):
            env_secrets.materialize(self.state)
        with self.assertRaises(RuntimeError):
            env_secrets.capture_private(self.state)

    def test_existing_key_artifact_blocks_fresh_but_draft_env_supplies_preferences(self):
        self.assertFalse(env_secrets.exists(self.state))
        (self.state / 'ca.key').write_bytes(b'previous identity')
        self.assertTrue(env_secrets.exists(self.state))
        (self.state / 'ca.key').unlink()
        self.env('identity-service').write_text('CUSTOM=value\n')
        self.assertFalse(env_secrets.exists(self.state))
        self.env('identity-service').write_text('ADMIN_PASSWORD="previous"\n')
        self.assertFalse(env_secrets.exists(self.state))
        self.assertEqual(env_secrets.initial_values(self.state), {'admin_password': 'previous'})
        self.env('identity-service').write_text('ADMIN_PASSWORD=""\n')
        self.assertEqual(env_secrets.initial_values(self.state), {})

    def test_fresh_preset_private_environment_refuses_generation(self):
        self.env('identity-service').write_text('SIGNING_PRIVATE_KEY="saved identity"\n')
        with self.assertRaises(RuntimeError):
            env_secrets.initial_values(self.state)

    def test_save_removes_obsolete_legacy_key_without_deleting_unknown_config(self):
        self.values['encryption_key'] = 'legacy'
        env_secrets.save(self.state, self.values)
        path = self.env('identity-service')
        with path.open('a') as stream:
            stream.write('LOCAL_USER_CONFIGURATION=keep\n')
        self.values.pop('encryption_key')
        env_secrets.save(self.state, self.values)
        self.assertNotIn('encryption_key', env_secrets.load(self.state))
        self.assertIn('LOCAL_USER_CONFIGURATION=keep', path.read_text())

    def test_dotenv_quotes_comments_literals_and_json_escaped_newlines(self):
        env_secrets.save(self.state, self.values)
        path = self.env('identity-service')
        text = ''.join(line for line in path.read_text().splitlines(keepends=True)
                       if not line.startswith(('ADMIN_PASSWORD=', 'ADMIN_EMAIL=', 'IDENTITY_TOKEN=')))
        text += "export ADMIN_PASSWORD=' literal $HOME # \\n' # preserved literal\n"
        text += 'ADMIN_EMAIL=admin@example.test # comment\nIDENTITY_TOKEN="line1\\nline2\\r\\n" # comment\n'
        path.write_text(text)
        loaded = env_secrets.load(self.state)
        self.assertEqual(loaded['admin_password'], ' literal $HOME # \\n')
        self.assertEqual(loaded['admin_email'], 'admin@example.test')
        self.assertEqual(loaded['identity_token'], 'line1\nline2\r\n')

    def test_malformed_duplicate_and_invalid_utf8_diagnostics_do_not_disclose_values(self):
        env_secrets.save(self.state, self.values)
        path = self.env('identity-service')
        original = path.read_bytes()
        secret = 'never-disclose-this-sentinel'
        for extra in (f'ADMIN_PASSWORD={secret}\n', f'INVALID {secret}\n',
                      f'UNRELATED="{secret}\n', f'OTHER="{secret}" trailing\n'):
            with self.subTest(kind=extra.split('=')[0]):
                path.write_bytes(original + extra.encode())
                with self.assertRaises(RuntimeError) as raised:
                    env_secrets.load(self.state)
                self.assertNotIn(secret, str(raised.exception))
        path.write_bytes(original + b'OTHER=\xff\n')
        with self.assertRaises(RuntimeError):
            env_secrets.load(self.state)

    def test_save_validates_all_inputs_before_any_publication(self):
        self.values['unrecognized_credential'] = 'do-not-drop'
        with self.assertRaises(RuntimeError):
            env_secrets.save(self.state, self.values)
        self.assertFalse(self.env('platform-infra').exists())
        self.values.pop('unrecognized_credential')
        self.values.pop('admin_password')
        with self.assertRaises(RuntimeError):
            env_secrets.save(self.state, self.values)
        self.assertFalse(self.env('platform-infra').exists())

    def test_explicit_legacy_reader_preserves_incomplete_rekey_inputs(self):
        (self.state / 'secrets.json').write_text(json.dumps({'encryption_key': 'old-key'}))
        self.assertEqual(env_secrets.read_legacy(self.state), {'encryption_key': 'old-key'})
        with self.assertRaises(RuntimeError):
            env_secrets.load(self.state)

    def test_legacy_shared_key_import_retains_missing_purpose_keys_for_explicit_rekey(self):
        self.values['encryption_key'] = 'legacy-ciphertext-key'
        for key in env_secrets.PURPOSE_KEYS:
            self.values.pop(key)
        self.legacy()
        self.assertEqual(env_secrets.migrate(self.state), self.values)
        self.assertEqual(env_secrets.load(self.state), self.values)
        self.assertFalse((self.state / 'secrets.json').exists())

    def test_corrupt_initialized_marker_is_not_treated_as_fresh_state(self):
        (self.state / env_secrets.MARKER).write_bytes(b'incomplete')
        with self.assertRaises(RuntimeError):
            env_secrets.exists(self.state)
        with self.assertRaises(RuntimeError):
            env_secrets.load(self.state)

    def test_invalid_duplicate_legacy_manifest_keeps_source_without_disclosing_values(self):
        sentinel = 'never-disclose-legacy-sentinel'
        path = self.state / 'secrets.json'
        path.write_text('{"encryption_key":"' + sentinel + '","encryption_key":"other"}')
        with self.assertRaises(RuntimeError) as raised:
            env_secrets.read_legacy(self.state)
        self.assertNotIn(sentinel, str(raised.exception))
        self.assertTrue(path.exists())

    def test_legacy_source_survives_reread_verification_failure(self):
        self.legacy()
        real_replace = os.replace
        def corrupt_after_publication(source, destination):
            result = real_replace(source, destination)
            path = Path(destination)
            if path == self.env('identity-service'):
                text = path.read_text().replace('ADMIN_PASSWORD="fixture-admin_password"',
                                                'ADMIN_PASSWORD="corrupted"')
                path.write_text(text)
            return result
        with patch.object(env_secrets.os, 'replace', side_effect=corrupt_after_publication):
            with self.assertRaises(RuntimeError):
                env_secrets.migrate(self.state)
        self.assertTrue((self.state / 'secrets.json').exists())
        self.assertFalse((self.state / env_secrets.MARKER).exists())

    def test_updated_credential_preserves_its_inline_comment(self):
        self.env('identity-service').write_text('export ADMIN_PASSWORD=old # keep password note\n')
        env_secrets.save(self.state, self.values)
        self.assertIn('# keep password note\n', self.env('identity-service').read_text())
        self.assertEqual(env_secrets.load(self.state), self.values)

    def test_comment_only_required_placeholder_is_empty_not_a_password(self):
        self.env('identity-service').write_text('ADMIN_PASSWORD= # configure locally\n')
        self.assertEqual(env_secrets.initial_values(self.state), {})

    def test_non_unicode_scalar_credential_is_rejected_without_publication(self):
        self.values['admin_password'] = '\ud800'
        with self.assertRaises(RuntimeError):
            env_secrets.save(self.state, self.values)
        self.assertFalse(self.env('platform-infra').exists())

    @unittest.skipUnless(os.name == 'posix', 'POSIX symlink safety')
    def test_symlinked_environment_and_derived_mount_are_rejected(self):
        outside = self.workspace / 'outside'
        outside.write_bytes(b'do not overwrite')
        self.env('identity-service').symlink_to(outside)
        with self.assertRaises(RuntimeError):
            env_secrets.save(self.state, self.values)
        self.assertEqual(outside.read_bytes(), b'do not overwrite')
        self.env('identity-service').unlink()
        self.initialized()
        (self.state / 'backup.key').unlink()
        (self.state / 'backup.key').symlink_to(outside)
        with self.assertRaises(RuntimeError):
            env_secrets.materialize(self.state)
        self.assertEqual(outside.read_bytes(), b'do not overwrite')

    @unittest.skipUnless(os.name == 'posix', 'POSIX file permission contract')
    def test_environment_marker_and_derived_private_files_are_owner_only(self):
        self.initialized()
        for owner in set(env_secrets.OWNERS.values()):
            self.assertEqual(self.env(owner).stat().st_mode & 0o777, 0o600)
        for relative in self.private:
            (self.state / relative).unlink()
        env_secrets.materialize(self.state)
        for relative in self.private:
            self.assertEqual((self.state / relative).stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.state / env_secrets.MARKER).stat().st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
