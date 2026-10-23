# SPDX-License-Identifier: MIT
"""Actual Docker ignore interpretation, including Dockerfile-specific precedence."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

WORKSPACE = Path(__file__).resolve().parents[3]
OWNERS = ('identity-service', 'user-notification-service', 'catalog-service',
          'billing-service', 'subscription-service', 'referral-service')


@unittest.skipUnless(os.environ.get('RUN_DOCKER_CONTEXT_CONTRACT') == '1',
                     'Opt-in actual Docker context export; parent owns Docker execution')
class DockerContextPrivacy(unittest.TestCase):
    def test_root_and_every_owner_ignore_export_source_but_no_private_or_build_artifacts(self):
        for selected in ('root', *OWNERS):
            with self.subTest(selected=selected), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / 'context'
                root.mkdir()
                for owner in (*OWNERS, 'platform-contracts', 'frontend', 'platform-infra'):
                    source = root / owner
                    source.mkdir()
                    (source / 'source.txt').write_text('public source')
                    for secret in ('.env', '.env.private', 'credential.key', 'identity.pem', 'ca.crt'):
                        (source / secret).write_text('private-context-sentinel')
                    for hidden in ('.local', '.generic-local', '.git', 'target', 'dist', 'node_modules', 'bin', '.venv'):
                        (source / hidden).mkdir()
                        (source / hidden / 'sentinel').write_text('private-context-sentinel')
                (root / 'unrelated-secret.txt').write_text('private-context-sentinel')
                shutil.copyfile(WORKSPACE / '.dockerignore', root / '.dockerignore')
                if selected == 'root':
                    dockerfile = root / 'Dockerfile'
                    expected = 'catalog-service'
                else:
                    dockerfile = root / selected / 'Dockerfile'
                    expected = selected
                    shutil.copyfile(WORKSPACE / selected / 'Dockerfile.dockerignore',
                                    dockerfile.with_name('Dockerfile.dockerignore'))
                dockerfile.write_text('FROM scratch\nCOPY . /\n')
                destination = Path(directory) / 'exported'
                result = subprocess.run(['docker', 'build', '--file', str(dockerfile),
                    '--output', 'type=local,dest=' + str(destination), str(root)],
                    check=False, capture_output=True, timeout=120)
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace')[-1200:])
                self.assertTrue((destination / expected / 'source.txt').is_file())
                exported = [path for path in destination.rglob('*') if path.is_file()]
                self.assertFalse(any(b'private-context-sentinel' in path.read_bytes() for path in exported),
                                 [path.relative_to(destination).as_posix() for path in exported])


if __name__ == '__main__':
    unittest.main()
