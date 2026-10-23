"""Trivy must detect and evaluate generated Kubernetes resources, not merely exit successfully."""
import json
from pathlib import Path
import sys
import tempfile
import cli

IMAGE = 'docker.io/aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c'


def scan(path):
    document = json.loads(Path(path).read_text())
    objects = document['items']
    if not objects:
        raise RuntimeError('No rendered Kubernetes resources to scan')
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory)
        # JSON is a YAML subset; .yaml forces Kubernetes discovery without adding a parser dependency.
        # Separate resources avoid scanners treating Kubernetes List as an unrecognized envelope.
        for index, resource in enumerate(objects):
            (source / f'{index:03}-{resource["kind"]}.yaml').write_text(json.dumps(resource))
        result = cli.run(['docker', 'run', '--rm', '-v', str(source) + ':/resources:ro', IMAGE, 'config', '--format', 'json', '--severity', 'HIGH,CRITICAL', '/resources'], timeout=600)
        report = json.loads(result.stdout)
        scanned = [entry for entry in report.get('Results', []) if entry.get('Type') == 'kubernetes']
        evaluated = sum(entry.get('MisconfSummary', {}).get('Successes', 0) + entry.get('MisconfSummary', {}).get('Failures', 0) + entry.get('MisconfSummary', {}).get('Exceptions', 0) for entry in scanned)
        if not scanned or evaluated == 0:
            raise RuntimeError('Trivy evaluated zero Kubernetes resources/checks; not a successful security scan')
        findings = [item for entry in scanned for item in entry.get('Misconfigurations', []) if item.get('Status', 'FAIL') == 'FAIL']
        for entry in scanned:
            for item in entry.get('Misconfigurations', []):
                if item.get('Status', 'FAIL') == 'FAIL':
                    print(f"{entry['Target']}: {item.get('ID')} {item.get('Severity')} {item.get('Title')}")
        print(f'Trivy evaluated {len(scanned)} Kubernetes resource files and {evaluated} checks; HIGH/CRITICAL failures={len(findings)}')
        if findings:
            raise RuntimeError('Rendered Kubernetes security findings require correction')


if __name__ == '__main__':
    try:
        scan(Path(sys.argv[1]))
    except (RuntimeError, ValueError, KeyError) as error:
        print('ERROR: ' + str(error), file=sys.stderr)
        sys.exit(1)
