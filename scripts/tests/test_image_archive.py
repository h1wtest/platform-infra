import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from image_archive import config_identity


class ImageArchiveIdentityTests(unittest.TestCase):
    def archive(self, path, corrupt=False, corrupt_config=False, wrong_link=False):
        content = b'{"architecture":"amd64","rootfs":{"type":"layers","diff_ids":[]}}'
        config_id = 'sha256:' + hashlib.sha256(content).hexdigest()
        manifest = json.dumps({'schemaVersion': 2, 'config': {'digest': 'sha256:' + 'e' * 64 if wrong_link else config_id}}).encode()
        manifest_id = 'sha256:' + hashlib.sha256(manifest).hexdigest()
        index = json.dumps({'schemaVersion': 2, 'manifests': [{'digest': manifest_id}]}).encode()
        image_id = 'sha256:' + hashlib.sha256(index).hexdigest()
        files = {'manifest.json': json.dumps([{'Config': 'blobs/sha256/' + config_id[7:]}]).encode(),
                 'index.json': json.dumps({'manifests': [{'digest': image_id}]}).encode(),
                 'blobs/sha256/' + image_id[7:]: index,
                 'blobs/sha256/' + manifest_id[7:]: manifest + (b' ' if corrupt else b''),
                 'blobs/sha256/' + config_id[7:]: content + (b' ' if corrupt_config else b'')}
        with tarfile.open(path, 'w') as archive:
            for name, value in files.items():
                member = tarfile.TarInfo(name)
                member.size = len(value)
                archive.addfile(member, io.BytesIO(value))
        return image_id, config_id

    def test_classic_and_containerd_identities_bind_to_the_same_exact_config(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'image.tar'
            image_id, config_id = self.archive(path)
            self.assertEqual(config_identity(path, image_id), config_id)
            self.assertEqual(config_identity(path, config_id), config_id)

    def test_unrelated_image_id_and_tampered_manifest_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'image.tar'
            self.archive(path)
            with self.assertRaisesRegex(RuntimeError, 'root differs'):
                config_identity(path, 'sha256:' + 'f' * 64)
            image_id, _ = self.archive(path, corrupt=True)
            with self.assertRaisesRegex(RuntimeError, 'blob differs'):
                config_identity(path, image_id)
            image_id, _ = self.archive(path, corrupt_config=True)
            with self.assertRaisesRegex(RuntimeError, 'does not bind'):
                config_identity(path, image_id)
            image_id, _ = self.archive(path, wrong_link=True)
            with self.assertRaisesRegex(RuntimeError, 'does not bind'):
                config_identity(path, image_id)


if __name__ == '__main__':
    unittest.main()
