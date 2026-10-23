"""Render complete resources for static validation, using ephemeral real generated secrets."""
import argparse
import json
from pathlib import Path
import tempfile
import manifests
import cli as runtime

parser = argparse.ArgumentParser()
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
with tempfile.TemporaryDirectory() as directory:
    state = Path(directory) / 'platform-infra' / '.local'
    for owner in ('identity-service', 'user-notification-service'):
        (Path(directory) / owner).mkdir()
    runtime.create_secrets(state)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.with_name('ca.crt').write_bytes((state / 'ca.crt').read_bytes())
    images = dict(runtime.PINS)
    images.update({target: 'sso-remediation/' + target + ':sha256-' + '0' * 64 for target in ('identity', 'profile', 'notification', 'worker', 'admin', 'frontend')})
    objects = [*manifests.infrastructure(images, state, runtime.ROOT / 'observability'), *manifests.monitoring(images, state), *manifests.applications(images, state)]
    args.output.write_text(json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': objects}))
