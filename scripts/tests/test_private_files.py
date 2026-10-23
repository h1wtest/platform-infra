import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from private_files import atomic_json, preserve_key_manifest


class DurablePrivatePublication(unittest.TestCase):
    def test_failure_before_replace_retains_original_complete_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'secrets.json'
            original = {'encryption_key': 'legacy', 'delivery_encryption_key': 'target'}
            atomic_json(path, original)
            def interrupt():
                raise RuntimeError('injected crash before atomic replace')
            with self.assertRaises(RuntimeError):
                atomic_json(path, {'delivery_encryption_key': 'replacement'}, before_replace=interrupt)
            self.assertEqual(json.loads(path.read_text()), original)
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_precommit_manifest_preserves_all_target_keys_after_final_cutover(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            values = {'encryption_key': 'legacy', 'mfa_encryption_key': 'mfa-target', 'delivery_encryption_key': 'delivery-target', 'profile_quarantine_key': 'profile-target', 'notification_quarantine_key': 'notification-target', 'admin_quarantine_key': 'audit-target'}
            archive = preserve_key_manifest(state, values, name='rekey-precommit.json')
            values.pop('encryption_key')
            atomic_json(state / 'secrets.json', values)
            recovered = json.loads(archive.read_text())['keys']
            self.assertEqual(recovered['encryption_key'], 'legacy')
            for key, value in values.items():
                self.assertEqual(recovered[key], value)
            self.assertEqual(os.stat(archive).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(state / 'secrets.json').st_mode & 0o777, 0o600)


if __name__ == '__main__': unittest.main()
