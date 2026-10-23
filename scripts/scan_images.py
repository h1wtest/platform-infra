"""Scan registry pins and the actual content-addressed patched gateway; any finding is fatal."""
import json
import os
from pathlib import Path
import sys
import tempfile
import cli as runtime
from private_files import atomic_json
from image_archive import config_identity

TRIVY = 'docker.io/aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c'
runtime.STATE.mkdir(exist_ok=True, mode=0o700)
cache = runtime.STATE / 'trivy-cache'
cache.mkdir(exist_ok=True, mode=0o700)
reports = runtime.STATE / 'image-scans'
reports.mkdir(exist_ok=True, mode=0o700)
failed = []
gateway = None
if 'gateway' in runtime.PINS:
    if (runtime.STATE / 'images.lock.json').is_file():
        gateway = runtime.load_images()
    else:
        gateway = runtime.build_gateway()
    runtime.verify_local_image('gateway', gateway['gateway'], gateway['gateway_id'])
    print('gateway base=' + runtime.PINS['gateway'] + ', patched artifact=' + gateway['gateway_id'])
for name, image in {'k3s': runtime.K3S, **runtime.PINS}.items():
    # Registry digests are scanned remotely; the patched gateway is exported from its verified local ID.
    if name == 'gateway':
        with tempfile.TemporaryDirectory(dir=runtime.STATE) as directory:
            archive = Path(directory) / 'gateway.tar'
            runtime.run(['docker', 'image', 'save', gateway['gateway_id'], '--output', archive], timeout=600)
            runtime.verify_local_image('gateway', gateway['gateway'], gateway['gateway_id'])
            gateway_config_id = config_identity(archive, gateway['gateway_id'])
            result = runtime.run(['docker', 'run', '--rm', '--user', str(os.getuid()) + ':' + str(os.getgid()), '-e', 'HOME=/cache', '-v', str(cache) + ':/cache', '-v', str(archive) + ':/image.tar:ro', TRIVY, 'image', '--input', '/image.tar', '--scanners', 'vuln', '--cache-dir', '/cache', '--format', 'json'], timeout=1800, check=False)
    else:
        result = runtime.run(['docker', 'run', '--rm', '--user', str(os.getuid()) + ':' + str(os.getgid()), '-e', 'HOME=/cache', '-v', str(cache) + ':/cache', TRIVY, 'image', '--image-src', 'remote', '--platform', 'linux/amd64', '--scanners', 'vuln', '--cache-dir', '/cache', '--format', 'json', image], timeout=1800, check=False)
    if result.returncode:
        failed.append(name + ': scanner execution failed')
        print('FAIL ' + name + ': vulnerability scan execution failed (not a clean result)', file=sys.stderr)
        continue
    report = json.loads(result.stdout)
    if name == 'gateway':
        report['BuildProvenance'] = {'base': image, 'image': gateway['gateway'], 'image_id': gateway['gateway_id'], 'config_id': gateway_config_id, 'recipe_sha256': gateway['gateway_recipe_sha256']}
    atomic_json(reports / (name + '.json'), report)
    evaluated = [entry for entry in report.get('Results', []) if entry.get('Type') and (entry.get('Class') in ('os-pkgs', 'lang-pkgs'))]
    if not evaluated or not any(entry.get('Packages') for entry in evaluated):
        failed.append(name + ': zero evaluated package inventories')
        print('FAIL ' + name + ': scan has no OS/language package inventory', file=sys.stderr)
        continue
    if name == 'gateway':
        if report.get('Metadata', {}).get('ImageID') != gateway_config_id:
            failed.append(name + ': scanned config differs from the verified archive identity')
            print('FAIL gateway: scanned config differs from the verified archive identity', file=sys.stderr)
            continue
    all_vulnerabilities = [v for entry in evaluated for v in entry.get('Vulnerabilities', [])]
    counts = {severity: sum(v.get('Severity', 'UNKNOWN') == severity for v in all_vulnerabilities) for severity in ('UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')}
    print(name + ': evaluated inventories=' + str(len(evaluated)) + ', ' + ', '.join(severity + '=' + str(count) for severity, count in counts.items()))
    for vulnerability in all_vulnerabilities:
        print(name + ': ' + vulnerability.get('Severity', 'UNKNOWN') + ' ' + vulnerability.get('VulnerabilityID', '?') + ' ' + vulnerability.get('PkgName', '?') + ' ' + vulnerability.get('InstalledVersion', '?') + ' -> ' + vulnerability.get('FixedVersion', 'no fixed version reported'))
    if all_vulnerabilities:
        failed.append(name + ': vulnerabilities (all severities)')
if failed:
    raise SystemExit('Infrastructure image acceptance failed: ' + '; '.join(failed))
