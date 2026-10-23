#!/usr/bin/env python3
"""Verify actual Kubernetes NetworkPolicy denial with disposable untrusted pod.

Does not delete existing pods or touch application data. Requires an explicit
cluster context, namespace and pinned probe image; never uses current context.
"""
import argparse
import json
import subprocess
import uuid


def run(args, *command, data=None, check=True):
    result = subprocess.run(['kubectl', '--context', args.context, '-n', args.namespace, *command],
                            input=data, text=True, capture_output=True, timeout=90)
    if check and result.returncode:
        raise AssertionError(f'kubectl {command[0]} failed: {result.stderr[:500]}')
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--context', required=True)
    parser.add_argument('--namespace', default='sso-remediation')
    parser.add_argument('--image', required=True)
    args = parser.parse_args()
    if args.context != 'k3d-sso-remediation' or args.namespace != 'sso-remediation':
        parser.error('Probe restricted to explicitly isolated remediation cluster and namespace')
    name = 'acceptance-untrusted-' + uuid.uuid4().hex[:10]
    spec = {'apiVersion': 'v1', 'kind': 'Pod',
            'metadata': {'name': name, 'namespace': args.namespace, 'labels': {'app': 'acceptance-untrusted'}},
            'spec': {'automountServiceAccountToken': False, 'restartPolicy': 'Never',
                     'securityContext': {'runAsNonRoot': True, 'runAsUser': 10001, 'runAsGroup': 10001,
                                         'seccompProfile': {'type': 'RuntimeDefault'}},
                     'containers': [{'name': 'probe', 'image': args.image, 'command': ['sleep', '180'],
                                     'resources': {'requests': {'cpu': '5m', 'memory': '8Mi'},
                                                   'limits': {'cpu': '50m', 'memory': '32Mi'}},
                                     'securityContext': {'allowPrivilegeEscalation': False,
                                                         'readOnlyRootFilesystem': True,
                                                         'capabilities': {'drop': ['ALL']}}}]}}
    try:
        run(args, 'create', '-f', '-', data=json.dumps(spec))
        run(args, 'wait', '--for=condition=Ready', 'pod/' + name, '--timeout=60s')
        # Resolve via service API to avoid confusing blocked DNS with TCP denial.
        for service, port in [('identity-service', 8001), ('profile-service', 8002), ('postgres-rw', 5432)]:
            address = run(args, 'get', 'service', service, '-o', 'jsonpath={.spec.clusterIP}').stdout.strip()
            assert address and address != 'None', f'{service} requires ClusterIP probe target'
            result = run(args, 'exec', name, '--', 'nc', '-z', '-w', '3', address, str(port), check=False)
            assert result.returncode != 0, f'UNTRUSTED pod unexpectedly reached {service}:{port}'
            # An unavailable nc binary is not proof of network denial.
            assert not any(term in (result.stderr + result.stdout).lower()
                           for term in ('not found', 'no such file', 'unknown option', 'executable file')), 'Probe command unavailable'
            print(f'PASS untrusted pod denied TCP {service}:{port}')
    finally:
        run(args, 'delete', 'pod', name, '--ignore-not-found', '--wait=false', check=False)


if __name__ == '__main__':
    main()
