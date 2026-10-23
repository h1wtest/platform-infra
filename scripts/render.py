"""Render actual Helm releases for static validation with ephemeral real credentials."""
import argparse
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace

import cli
import helm_release
from release_values import release_specs


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    mask = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'platform-infra' / '.local'
            for owner in ('identity-service', 'user-notification-service'):
                (Path(directory) / owner).mkdir()
            cli.create_secrets(state)
            runtime = SimpleNamespace(ROOT=cli.ROOT, STATE=state, CONTEXT=cli.CONTEXT,
                                      NS=cli.NS, run=cli.run, kube=cli.kube)
            images = dict(cli.PINS)
            images.update({target: 'sso-remediation/' + target + ':sha256-' + '0' * 64
                           for target in ('identity', 'profile', 'notification', 'worker', 'admin', 'frontend')})
            specs = release_specs(images, state, cli.ROOT)
            specs['platform-config']['values']['apiNetworkPolicy'] = {'spec': {'egress': [
                {'to': [{'ipBlock': {'cidr': '10.43.0.1/32'}}], 'ports': [{'protocol': 'TCP', 'port': 443}]},
                {'to': [{'ipBlock': {'cidr': '172.18.0.2/32'}}], 'ports': [{'protocol': 'TCP', 'port': 6443}]},
            ]}}
            objects = [obj for release, spec in specs.items() for obj in helm_release.render(runtime, release, spec)]
            args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            args.output.with_name('ca.crt').write_bytes((state / 'ca.crt').read_bytes())
            args.output.write_text(json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': objects}))
            args.output.chmod(0o600)
    finally:
        os.umask(mask)


if __name__ == '__main__':
    main()
