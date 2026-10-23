"""Behavior regressions; controller runs after integration, never source-text assertions."""
import importlib.util
import pathlib
import tempfile
import unittest
import json
import hashlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('platform_runtime', ROOT / 'scripts' / 'cli.py')
platform = importlib.util.module_from_spec(spec)
spec.loader.exec_module(platform)


class BootstrapBehavior(unittest.TestCase):
    def test_bootstrap_retains_secrets_and_creates_valid_internal_certificate(self):
        with tempfile.TemporaryDirectory() as directory:
            state = pathlib.Path(directory) / 'platform-infra' / '.local'
            for owner in ('identity-service', 'user-notification-service'):
                (pathlib.Path(directory) / owner).mkdir()
            first = platform.create_secrets(state)
            second = platform.create_secrets(state)
            self.assertEqual(first, second)
            self.assertNotEqual(first['identity_runtime_password'], first['identity_migration_password'])
            self.assertNotEqual(first['profile_token'], first['admin_token'])
            platform.run(['openssl', 'verify', '-CAfile', str(state / 'ca.crt'), '-verify_hostname', 'identity-service', str(state / 'tls.crt')])
            platform.run(['openssl', 'verify', '-CAfile', str(state / 'ca.crt'), '-verify_hostname', 'localhost', str(state / 'tls.crt')])

    def test_authenticated_backup_roundtrip_and_wrong_password_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            state = pathlib.Path(directory)
            plain = state / 'dump'; plain.write_bytes(b'PostgreSQL durable backup\x00\xff')
            key = state / 'key'; key.write_text('test-only random passphrase\n')
            encrypted = state / 'dump.enc'; restored = state / 'restored'
            platform.encrypt_file(plain, encrypted, key)
            platform.decrypt_file(encrypted, restored, key)
            self.assertEqual(plain.read_bytes(), restored.read_bytes())
            payload = bytearray(encrypted.read_bytes()); payload[-1] ^= 1; encrypted.write_bytes(payload)
            with self.assertRaises(RuntimeError):
                platform.decrypt_file(encrypted, restored, key)

    def test_missing_image_lock_fails_closed_before_render(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(RuntimeError):
                platform.load_images(pathlib.Path(directory))

    def test_gateway_lock_requires_content_addressed_tag_matching_recorded_id(self):
        with tempfile.TemporaryDirectory() as directory:
            state = pathlib.Path(directory)
            image_id = 'sha256:' + 'a' * 64
            images = {'k3s': platform.K3S, **platform.PINS}
            for name in platform.PATCHED_COMPONENTS:
                images.update({name: f'sso-remediation/{name}:sha256-' + 'a' * 64, name + '_id': image_id,
                               name + '_base': platform.PINS[name], name + '_recipe_sha256': platform.component_recipe_hash(name)})
            lock = state / 'images.lock.json'
            lock.write_text(json.dumps(images))
            self.assertEqual(platform.load_images(state)['gateway_id'], image_id)
            for invalid in ('sso-remediation/gateway:latest', 'sso-remediation/gateway:sha256-' + 'b' * 64, platform.PINS['gateway']):
                images['gateway'] = invalid
                lock.write_text(json.dumps(images))
                with self.subTest(image=invalid), self.assertRaises(RuntimeError):
                    platform.load_images(state)

    def test_grafana_lock_rejects_unpatched_base_and_stale_recipe(self):
        with tempfile.TemporaryDirectory() as directory:
            state = pathlib.Path(directory)
            images = {'k3s': platform.K3S, **platform.PINS}
            for name in platform.PATCHED_COMPONENTS:
                images.update({name: f'sso-remediation/{name}:sha256-' + 'b' * 64, name + '_id': 'sha256:' + 'b' * 64,
                               name + '_base': platform.PINS[name], name + '_recipe_sha256': platform.component_recipe_hash(name)})
            lock = state / 'images.lock.json'
            lock.write_text(json.dumps(images))
            self.assertEqual(platform.load_images(state)['grafana_id'], images['grafana_id'])
            for updates in ({'grafana': platform.PINS['grafana']},
                            {'grafana': 'sso-remediation/grafana:sha256-' + 'c' * 64},
                            {'grafana_recipe_sha256': '0' * 64}):
                lock.write_text(json.dumps({**images, **updates}))
                with self.subTest(updates=updates), self.assertRaises(RuntimeError):
                    platform.load_images(state)

    def test_changed_registry_and_k3s_pins_reject_previous_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            state = pathlib.Path(directory)
            images = {'k3s': platform.K3S, **platform.PINS}
            for name in platform.PATCHED_COMPONENTS:
                images.update({name: f'sso-remediation/{name}:sha256-' + 'a' * 64, name + '_id': 'sha256:' + 'a' * 64,
                               name + '_base': platform.PINS[name], name + '_recipe_sha256': platform.component_recipe_hash(name)})
            lock = state / 'images.lock.json'
            for name in ('k3s', *(name for name in platform.PINS if name not in platform.PATCHED_COMPONENTS)):
                changed = {**images, name: images[name].rsplit('@', 1)[0] + '@sha256:' + 'f' * 64}
                lock.write_text(json.dumps(changed))
                with self.subTest(image=name), self.assertRaises(RuntimeError):
                    platform.load_images(state)



if __name__ == '__main__':
    unittest.main()
