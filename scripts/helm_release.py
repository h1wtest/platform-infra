"""Private Helm 4 lifecycle for the original local stand, never cluster bootstrap.

Public APIs accept the existing cli module as ``runtime``. All process output is
captured; Helm values and rendered resources must never be logged by callers.
``adopt(runtime, specs)`` validates the entire inventory before metadata-only
patches. It creates no release records; a subsequent deploy installs them.
``history(runtime, release)`` and ``status(runtime, release)`` return redacted
summaries. ``current_values(runtime, release)`` returns credential-bearing values
for private in-memory edits only. ``rollback(runtime, release, revision,
timeout=240)`` restores a successful application configuration, never migrations.
The caller owns the cluster-identity guard and lifecycle lock.
"""
import base64
import copy
import json
import os
from pathlib import Path
import re
import tempfile
import uuid

from manifests import APPS
from release_control import immutable_image
from security_material import SERVICES

_CONTEXT = 'k3d-sso-remediation'
_NAMESPACE = 'sso-remediation'
_APPLICATIONS = (*APPS, 'frontend', 'gateway')
_MONITORING = ('prometheus', 'tempo', 'otel-collector', 'grafana')
_RELEASE_CHARTS = {'platform-config': 'platform-config', 'postgres': 'platform-postgres',
                   'redpanda': 'platform-redpanda', 'mailpit': 'platform-mailpit',
                   **{name: 'platform-monitoring' for name in _MONITORING},
                   **{name: 'platform-service' for name in _APPLICATIONS}}
_API_VERSIONS = {'Deployment': 'apps/v1', 'StatefulSet': 'apps/v1',
                 'Service': 'v1', 'Secret': 'v1', 'ConfigMap': 'v1',
                 'ServiceAccount': 'v1', 'PersistentVolumeClaim': 'v1',
                 'PodDisruptionBudget': 'policy/v1',
                 'HorizontalPodAutoscaler': 'autoscaling/v2',
                 'NetworkPolicy': 'networking.k8s.io/v1',
                 'Cluster': 'postgresql.cnpg.io/v1'}
_OWNER_NAME = 'meta.helm.sh/release-name'
_OWNER_NAMESPACE = 'meta.helm.sh/release-namespace'
_MANAGED_BY = 'app.kubernetes.io/managed-by'
_LAST_APPLIED = 'kubectl.kubernetes.io/last-applied-configuration'


def configure():
    global _NAMESPACE, _APPLICATIONS, _RELEASE_CHARTS, SERVICES
    import manifests
    import security_material
    _NAMESPACE = manifests.NS
    SERVICES = security_material.SERVICES
    _APPLICATIONS = (*manifests.APPS, 'frontend', 'gateway')
    _RELEASE_CHARTS = {'platform-config': 'platform-config', 'postgres': 'platform-postgres',
                       'redpanda': 'platform-redpanda', 'mailpit': 'platform-mailpit',
                       **{name: 'platform-monitoring' for name in _MONITORING},
                       **{name: 'platform-service' for name in _APPLICATIONS}}


configure()


def _scope(runtime):
    if runtime.CONTEXT != _CONTEXT or runtime.NS != _NAMESPACE:
        raise RuntimeError('Helm lifecycle is restricted to explicit local context and selected namespace')
    if _NAMESPACE == 'generic-subscriptions' and Path(runtime.STATE).name != '.generic-local':
        raise RuntimeError('Generic Helm lifecycle requires isolated .generic-local state')


def _release(runtime, release):
    _scope(runtime)
    if not isinstance(release, str) or release not in _RELEASE_CHARTS:
        raise RuntimeError('Unknown local Helm release')


def _timeout(value):
    if type(value) is not int or not 1 <= value <= 3600:
        raise RuntimeError('Helm timeout must be an integer between 1 and 3600 seconds')
    return value


def _spec(runtime, release, spec):
    _release(runtime, release)
    if not isinstance(spec, dict) or spec.get('chart') != _RELEASE_CHARTS[release]:
        raise RuntimeError('Release does not match a known local chart')
    values = spec.get('values')
    if not isinstance(values, dict) or values.get('name') != release:
        raise RuntimeError('Release values must identify their owning release')
    if release != 'platform-config':
        try:
            immutable_image(values.get('image'))
        except ValueError:
            raise RuntimeError('Release image must be an immutable registry digest or content-addressed local tag') from None
    chart = Path(runtime.ROOT) / 'charts' / spec['chart']
    if not chart.is_dir() or chart.is_symlink():
        raise RuntimeError('Required local Helm chart is unavailable')
    return chart


def _failure_evidence(runtime, *, result=None, error=None):
    # This artifact is credential-bearing: NEVER stdout or stdin/argv snapshots.
    # Only its generated relative path is safe to include in a public exception.
    relative = Path('helm-failures') / (uuid.uuid4().hex + '.json')
    path = Path(runtime.STATE) / relative
    try:
        Path(runtime.STATE).mkdir(parents=True, exist_ok=True, mode=0o700)
        path.parent.mkdir(exist_ok=True, mode=0o700)
        if path.parent.is_symlink() or not path.parent.is_dir():
            raise OSError('invalid private evidence directory')
        os.chmod(path.parent, 0o700)
        if error is not None:
            evidence = {'exception_type': type(error).__name__, 'exception': str(error)}
        else:
            stderr = result.stderr or b''
            if isinstance(stderr, bytes):
                stderr = stderr.decode('utf-8', errors='replace')
            evidence = {'returncode': result.returncode, 'stderr': stderr}
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            json.dump(evidence, stream)
            stream.write('\n')
        return relative.as_posix()
    except Exception:
        return '[private diagnostic evidence unavailable]'


def _execute(runtime, arguments, *, timeout=60, input=None):
    # check=False is essential: cli.run otherwise includes credential-bearing
    # Helm stderr in its exception. Suppress exception chains for the same reason.
    try:
        result = runtime.run(arguments, input=input, timeout=timeout, check=False, capture=True)
    except Exception as error:
        evidence = _failure_evidence(runtime, error=error)
        raise RuntimeError('Helm lifecycle command unavailable or timed out; private diagnostics: ' + evidence) from None
    if result.returncode:
        evidence = _failure_evidence(runtime, result=result)
        raise RuntimeError('Helm lifecycle command failed; private diagnostics: ' + evidence) from None
    return result.stdout or b''


def _helm(runtime, arguments, *, timeout=60):
    _scope(runtime)
    return _execute(runtime, [getattr(runtime, 'HELM', 'helm'), *arguments,
                             '--kube-context', runtime.CONTEXT, '--namespace', runtime.NS], timeout=timeout)


def _json(data):
    try:
        return json.loads(data)
    except (ValueError, TypeError, UnicodeError):
        raise RuntimeError('Invalid private Helm/Kubernetes JSON response; output withheld') from None


def _parse_documents(data):
    try:
        text = data.decode('utf-8') if isinstance(data, bytes) else data
        text = '\n'.join(line for line in text.splitlines()
                         if line.strip() not in ('---', '...') and not line.lstrip().startswith('# Source:'))
        decoder = json.JSONDecoder()
        documents = []
        while text.strip():
            document, offset = decoder.raw_decode(text.lstrip())
            if not isinstance(document, dict):
                raise ValueError('not an object')
            documents.append(document)
            text = text.lstrip()[offset:]
        if not documents:
            raise ValueError('empty render')
        return documents
    except (ValueError, TypeError, AttributeError, UnicodeError):
        raise RuntimeError('Chart must render JSON object documents; private output withheld') from None


def _with_values(runtime, release, spec, operation):
    chart = _spec(runtime, release, spec)
    # TemporaryDirectory is 0700, and values never appear in process arguments.
    # Keep it outside shared state; cleanup occurs even when Helm raises.
    with tempfile.TemporaryDirectory(prefix='platform-helm-') as directory:
        path = Path(directory) / 'values.json'
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
                json.dump(spec['values'], stream)
                stream.write('\n')
        except (ValueError, TypeError):
            raise RuntimeError('Helm values are not JSON serializable; values withheld') from None
        return operation(chart, path)


def _allowed_inventory(release):
    if release == 'platform-config':
        secrets = {name + '-tls' for name in SERVICES} | {
            'platform-ca', 'redpanda-bootstrap', 'identity-signing', 'database-superuser',
            'platform-secrets', 'gateway-identity', 'identity-database', 'profile-database',
            'notification-database', 'audit-database'}
        if _NAMESPACE == 'generic-subscriptions':
            secrets |= {'postgres-ca', 'catalog-database', 'billing-database',
                        'subscription-database', 'referral-database',
                        'catalog-readers', 'subscription-readers'}
        configs = {'redpanda-config', 'gateway-conf', 'prometheus-yml', 'alerts-yml',
                   'otel-yml', 'tempo-yml', 'grafana-datasources-yml',
                   'grafana-dashboards-yml', 'platform-dashboard-json'}
        policies = {'default-deny', 'allow-dns', 'allow-postgres', 'allow-postgres-kubernetes-api',
                    *('allow-' + name for name in (*_APPLICATIONS, 'redpanda', 'mailpit', *_MONITORING))}
        if _NAMESPACE == 'generic-subscriptions':
            policies.add('allow-integration-ingress')
        return {('Secret', name) for name in secrets} | {('ConfigMap', name) for name in configs} | {('NetworkPolicy', name) for name in policies}
    if release == 'postgres':
        if _NAMESPACE == 'generic-subscriptions':
            return {('StatefulSet', 'postgres'), ('Service', 'postgres'),
                    ('Service', 'postgres-rw'), ('Service', 'postgres-ro'),
                    ('ServiceAccount', 'postgres')}
        return {('Cluster', 'postgres')}
    kinds = {'Deployment', 'Service', 'ServiceAccount', 'PodDisruptionBudget', 'HorizontalPodAutoscaler'}
    if release == 'redpanda':
        kinds = {'StatefulSet', 'Service', 'ServiceAccount', 'PodDisruptionBudget'}
    elif release in ('mailpit', *_MONITORING):
        kinds = {'Deployment', 'Service', 'ServiceAccount'}
        if release != 'otel-collector':
            kinds.add('PersistentVolumeClaim')
    result = {(kind, release) for kind in kinds}
    if release in APPS:
        result.add(('Service', release + '-metrics'))
    if release == 'gateway':
        result.add(('Service', 'gateway-public'))
    return result


def _desired(release, objects):
    seen = set()
    allowed = _allowed_inventory(release)
    for obj in objects:
        metadata = obj.get('metadata', {})
        kind, name = obj.get('kind'), metadata.get('name')
        key = (kind, name)
        if key not in allowed or obj.get('apiVersion') != _API_VERSIONS.get(kind):
            raise RuntimeError('Chart contains resources outside its recognized original inventory')
        if metadata.get('namespace') != _NAMESPACE or metadata.get('ownerReferences'):
            raise RuntimeError('Chart contains a foreign namespace or controller-owned resource')
        if key in seen:
            raise RuntimeError('Duplicate resource ownership in desired Helm inventory')
        seen.add(key)
        annotations = metadata.get('annotations', {})
        labels = metadata.get('labels', {})
        if _LAST_APPLIED in annotations:
            raise RuntimeError('Chart must not retain credential-bearing kubectl last-applied metadata')
        if annotations.get(_OWNER_NAME, release) != release or annotations.get(_OWNER_NAMESPACE, _NAMESPACE) != _NAMESPACE or labels.get(_MANAGED_BY, 'Helm') != 'Helm':
            raise RuntimeError('Chart contains foreign Helm ownership metadata')
        if kind in ('PersistentVolumeClaim', 'Cluster') and annotations.get('helm.sh/resource-policy') != 'keep':
            raise RuntimeError('Persistent claims and CNPG operands must retain the Helm keep policy')
        if kind == 'StatefulSet' and obj.get('spec', {}).get('persistentVolumeClaimRetentionPolicy') != {'whenDeleted': 'Retain', 'whenScaled': 'Retain'}:
            raise RuntimeError('Broker volume claim retention must remain Retain')
    return objects


def render(runtime, release, spec):
    """Return private JSON Kubernetes resources rendered by the actual chart."""
    documents = _with_values(runtime, release, spec, lambda chart, path:
        _parse_documents(_helm(runtime, ['template', release, chart, '--values', path], timeout=60)))
    return _desired(release, documents)


def _get(runtime, obj):
    metadata = obj['metadata']
    kind = obj['kind']
    group = obj['apiVersion'].split('/')[0] if '/' in obj['apiVersion'] else ''
    resource = kind + ('.' + group if group else '')
    # --ignore-not-found distinguishes absence (empty success) from RBAC,
    # transport, or parsing errors, which must never grant install permission.
    output = _execute(runtime, ['kubectl', '--context', runtime.CONTEXT, '--namespace', runtime.NS,
                               'get', resource, metadata['name'], '--ignore-not-found', '-o', 'json'])
    return _json(output) if output.strip() else None


def _label_selector(selector):
    # Kubernetes omits empty selector members on read. Do not collapse None
    # (absent) into {} (select-all), or discard any nonempty/unknown constraint.
    if not isinstance(selector, dict):
        return selector
    return {key: value for key, value in selector.items()
            if not (key == 'matchLabels' and value == {})
            and not (key == 'matchExpressions' and value == [])}


def _validate_existing(release, desired, existing, *, adopting):
    dm, em = desired['metadata'], existing.get('metadata', {})
    if existing.get('kind') != desired['kind'] or existing.get('apiVersion') != desired['apiVersion'] or em.get('name') != dm['name'] or em.get('namespace') != _NAMESPACE:
        raise RuntimeError('Existing resource identity or namespace does not match desired local inventory')
    if not em.get('uid') or not em.get('resourceVersion'):
        raise RuntimeError('Existing resource lacks a stable UID/resourceVersion for safe adoption')
    if em.get('ownerReferences') or (desired['kind'] != 'Cluster' and em.get('labels', {}).get('cnpg.io/cluster')):
        raise RuntimeError('Refusing to adopt controller-owned/operator-generated resources')
    labels, annotations = em.get('labels', {}), em.get('annotations', {})
    if annotations.get(_OWNER_NAME, release) != release or annotations.get(_OWNER_NAMESPACE, _NAMESPACE) != _NAMESPACE or labels.get(_MANAGED_BY, 'Helm') != 'Helm':
        raise RuntimeError('Existing resource has a foreign Helm or controller owner')
    owned = annotations.get(_OWNER_NAME) == release and annotations.get(_OWNER_NAMESPACE) == _NAMESPACE and labels.get(_MANAGED_BY) == 'Helm'
    if not adopting and not owned:
        raise RuntimeError('Existing unmanaged resources require explicit helm-adopt before install')
    if not adopting and _LAST_APPLIED in annotations:
        raise RuntimeError('Existing resource retains private kubectl metadata; run explicit helm-adopt to remove it')
    kind = desired['kind']
    ds, es = desired.get('spec', {}), existing.get('spec', {})
    if kind in ('Deployment', 'StatefulSet', 'Service', 'PodDisruptionBudget') and ds.get('selector') != es.get('selector'):
        raise RuntimeError('Existing resource selector differs from the original local workload identity')
    if kind in ('Deployment', 'StatefulSet'):
        expected_app = ds.get('template', {}).get('metadata', {}).get('labels', {}).get('app')
        if not expected_app or es.get('template', {}).get('metadata', {}).get('labels', {}).get('app') != expected_app:
            raise RuntimeError('Existing pod identity differs from the original local workload')
    if kind == 'StatefulSet':
        if ds.get('serviceName') != es.get('serviceName') or [claim['metadata']['name'] for claim in ds.get('volumeClaimTemplates', [])] != [claim['metadata']['name'] for claim in es.get('volumeClaimTemplates', [])]:
            raise RuntimeError('Existing broker storage identity differs from the original inventory')
    if kind == 'HorizontalPodAutoscaler' and ds.get('scaleTargetRef') != es.get('scaleTargetRef'):
        raise RuntimeError('Existing autoscaler targets a different workload')
    if kind == 'NetworkPolicy' and _label_selector(ds.get('podSelector')) != _label_selector(es.get('podSelector')):
        raise RuntimeError('Existing network policy selects different workloads')
    if adopting and kind == 'Secret' and (desired.get('type', 'Opaque') != existing.get('type', 'Opaque') or desired.get('data', {}) != existing.get('data', {})):
        raise RuntimeError('Existing secret differs from protected local credentials; refusing ownership change')
    if kind == 'PersistentVolumeClaim':
        for key in ('storageClassName', 'accessModes', 'volumeMode'):
            if key in ds and ds[key] != es.get(key):
                raise RuntimeError('Existing persistent claim storage identity differs from local inventory')
    return owned


def adopt(runtime, specs):
    """Validate ALL release inventories, then patch only Helm metadata in place.

    JSON Patch tests pin UID and resourceVersion so a replaced or concurrently
    changed resource is not silently claimed. Partial interruption is safe to
    rerun; no rollback/delete/recreation of any object is attempted.
    """
    _scope(runtime)
    if not isinstance(specs, dict) or not specs:
        raise RuntimeError('Adoption requires an explicit nonempty known release inventory')
    inventory, seen = [], set()
    for release, spec in specs.items():
        for desired in render(runtime, release, spec):
            key = (desired['apiVersion'], desired['kind'], desired['metadata']['name'])
            if key in seen:
                raise RuntimeError('Multiple releases claim the same original resource')
            seen.add(key)
            existing = _get(runtime, desired)
            if existing is not None:
                _validate_existing(release, desired, existing, adopting=True)
                inventory.append((release, desired, existing))
    for release, desired, existing in inventory:
        metadata = existing['metadata']
        annotations = dict(metadata.get('annotations', {}))
        annotations.pop(_LAST_APPLIED, None)
        annotations.update({_OWNER_NAME: release, _OWNER_NAMESPACE: runtime.NS})
        if desired['kind'] in ('PersistentVolumeClaim', 'Cluster'):
            annotations['helm.sh/resource-policy'] = 'keep'
        labels = {**metadata.get('labels', {}), _MANAGED_BY: 'Helm'}
        if annotations == metadata.get('annotations', {}) and labels == metadata.get('labels', {}):
            continue
        patch = [{'op': 'test', 'path': '/metadata/uid', 'value': metadata['uid']},
                 {'op': 'test', 'path': '/metadata/resourceVersion', 'value': metadata['resourceVersion']},
                 {'op': 'add', 'path': '/metadata/annotations', 'value': annotations},
                 {'op': 'add', 'path': '/metadata/labels', 'value': labels}]
        kind = desired['kind']
        group = desired['apiVersion'].split('/')[0] if '/' in desired['apiVersion'] else ''
        resource = kind + ('.' + group if group else '')
        _execute(runtime, ['kubectl', '--context', runtime.CONTEXT, '--namespace', runtime.NS,
                           'patch', resource, metadata['name'], '--type=json', '--patch-file', '/dev/stdin'],
                 input=json.dumps(patch).encode())
    return len(inventory)


def _installed(runtime, release):
    result = _json(_helm(runtime, ['list', '--filter', '^' + re.escape(release) + '$', '--output', 'json']))
    if not isinstance(result, list) or len(result) > 1 or any(item.get('name') != release for item in result):
        raise RuntimeError('Unexpected Helm release inventory; output withheld')
    return result[0] if result else None


def _verify_images(runtime, objects):
    images = set()
    for obj in objects:
        kind = obj['kind']
        if kind in ('Deployment', 'StatefulSet'):
            pod = obj.get('spec', {}).get('template', {}).get('spec', {})
            images.update(container.get('image') for key in ('containers', 'initContainers') for container in pod.get(key, []))
        elif kind == 'Cluster':
            images.add(obj.get('spec', {}).get('imageName'))
    for image in images:
        try:
            immutable_image(image)
        except ValueError:
            raise RuntimeError('Rendered workload contains a mutable or invalid image reference') from None
        if image.startswith('sso-remediation/'):
            info = _json(_execute(runtime, ['docker', 'image', 'inspect', image]))
            expected = 'sha256:' + image.rsplit('sha256-', 1)[1]
            if not isinstance(info, list) or len(info) != 1 or info[0].get('Id') != expected:
                raise RuntimeError('Content-addressed local image tag was mutated or is unavailable')


def deploy(runtime, release, spec, *, adopt=False, timeout=240, rollback=False):
    """Install/update one release, returning no secret-bearing Helm output.

    Existing application upgrades always restore the last good configuration on
    readiness failure. First installs NEVER enable rollback-on-failure (Helm may
    uninstall an adopted original inventory). Infrastructure never auto-rolls
    back. Failed/pending records require explicit operator recovery.
    """
    _timeout(timeout)
    _spec(runtime, release, spec)
    if type(adopt) is not bool or type(rollback) is not bool:
        raise RuntimeError('Adoption and rollback options must be booleans')
    if rollback and release not in _APPLICATIONS:
        raise RuntimeError('Automatic rollback is restricted to application releases')
    objects = render(runtime, release, spec)
    _verify_images(runtime, objects)
    installed = _installed(runtime, release)
    if installed is not None and installed.get('status') != 'deployed':
        raise RuntimeError('Release is failed or pending; inspect history and explicitly recover before upgrading')
    previous_revision = None
    if installed and release in _APPLICATIONS:
        successful = [record for record in history(runtime, release) if record['status'] == 'deployed']
        if not successful:
            raise RuntimeError('Application has no recorded deployed revision for safe full-rollout recovery')
        previous_revision = successful[-1]['revision']
    if adopt:
        # Complete single-release inventory validation precedes any patch.
        # Initial multi-release migration must call adopt(runtime, all_specs).
        globals()['adopt'](runtime, {release: spec})
    else:
        for desired in objects:
            existing = _get(runtime, desired)
            if existing is not None:
                _validate_existing(release, desired, existing, adopting=False)
    arguments = ['upgrade' if installed else 'install', release]
    arguments.extend(['--wait=legacy', '--timeout', f'{timeout}s', '--server-side=false'])
    if installed:
        arguments.extend(['--history-max', '20'])
        if release in _APPLICATIONS:
            arguments.append('--rollback-on-failure')
    _with_values(runtime, release, spec, lambda chart, path:
        _helm(runtime, [*arguments[:2], chart, *arguments[2:], '--values', path], timeout=timeout * (2 if installed and release in _APPLICATIONS else 1) + 30))
    if release in _APPLICATIONS:
        try:
            _rollout(runtime, release, timeout)
        except RuntimeError:
            if previous_revision is not None:
                globals()['rollback'](runtime, release, previous_revision, timeout=timeout)
            raise


def _rollout(runtime, release, timeout):
    _execute(runtime, ['kubectl', '--context', runtime.CONTEXT, '--namespace', runtime.NS,
                       'rollout', 'status', 'deployment/' + release, f'--timeout={timeout}s'], timeout=timeout + 15)


def history(runtime, release):
    """Return revision/status/chart timestamps only; never Helm descriptions."""
    _release(runtime, release)
    if _installed(runtime, release) is None:
        return []
    records = _json(_helm(runtime, ['history', release, '--max', '256', '--output', 'json']))
    if not isinstance(records, list):
        raise RuntimeError('Invalid Helm history response; output withheld')
    fields = ('revision', 'updated', 'status', 'chart', 'app_version')
    result = []
    for record in records:
        if not isinstance(record, dict) or type(record.get('revision')) is not int or not isinstance(record.get('status'), str):
            raise RuntimeError('Invalid Helm revision record; output withheld')
        result.append({key: record[key] for key in fields if key in record})
    return sorted(result, key=lambda item: item['revision'])


def status(runtime, release):
    """Return None if absent, otherwise safe name/revision/status fields."""
    _release(runtime, release)
    if _installed(runtime, release) is None:
        return None
    record = _json(_helm(runtime, ['status', release, '--output', 'json']))
    if not isinstance(record, dict) or not isinstance(record.get('info'), dict):
        raise RuntimeError('Invalid Helm status response; output withheld')
    return {'name': release, 'revision': record.get('version'), 'status': record['info'].get('status')}


def current_values(runtime, release):
    """Return private installed user values (NOT safe to print or serialize publicly)."""
    _release(runtime, release)
    if _installed(runtime, release) is None:
        raise RuntimeError('Selected Helm release is not installed')
    values = _json(_helm(runtime, ['get', 'values', release, '--output', 'json']))
    if not isinstance(values, dict) or values.get('name') != release:
        raise RuntimeError('Installed values do not identify the selected local release')
    return values


def rollback(runtime, release, revision, timeout=240):
    """Restore an existing deployed/superseded APPLICATION revision, not data."""
    _release(runtime, release)
    _timeout(timeout)
    if release not in _APPLICATIONS or type(revision) is not int or revision < 1:
        raise RuntimeError('Rollback requires an application and positive integer revision')
    records = history(runtime, release)
    if not any(item['revision'] == revision and item['status'] in ('deployed', 'superseded') for item in records):
        raise RuntimeError('Rollback target is not a recorded successful application revision')
    _helm(runtime, ['rollback', release, str(revision), '--wait=legacy', '--timeout', f'{timeout}s',
                    '--server-side=false', '--history-max', '20'], timeout=timeout + 30)
    _rollout(runtime, release, timeout)
    selection_path = Path(runtime.STATE) / 'release-images.json'
    if selection_path.exists():
        selection = _json(selection_path.read_bytes())
        if not isinstance(selection, dict) or set(selection) - set(_APPLICATIONS):
            raise RuntimeError('Invalid selected release image record after rollback')
        if release in selection:
            image = current_values(runtime, release).get('image')
            try:
                immutable_image(image)
            except ValueError:
                raise RuntimeError('Restored release has an invalid selected image') from None
            from private_files import atomic_json
            selection[release] = image
            atomic_json(selection_path, selection)


def restore_config(runtime, values, timeout=240):
    """Explicit platform-config recovery after a temporary config failure.

    Accept only deployed/failed recorded releases, never pending or absent. This
    is an operator-controlled restoration, not an automatic infra rollback.
    """
    _timeout(timeout)
    spec = {'chart': 'platform-config', 'values': values}
    _spec(runtime, 'platform-config', spec)
    installed = _installed(runtime, 'platform-config')
    if installed is None or installed.get('status') not in ('deployed', 'failed'):
        raise RuntimeError('Explicit config restoration requires a deployed or failed release, never pending/absent')
    objects = render(runtime, 'platform-config', spec)
    _verify_images(runtime, objects)
    for desired in objects:
        existing = _get(runtime, desired)
        if existing is not None:
            _validate_existing('platform-config', desired, existing, adopting=False)
    _with_values(runtime, 'platform-config', spec, lambda chart, path:
        _helm(runtime, ['upgrade', 'platform-config', chart, '--values', path,
                        '--wait=legacy', '--timeout', f'{timeout}s',
                        '--server-side=false', '--history-max', '20'], timeout=timeout + 30))


def _rekey_data(values):
    if not isinstance(values, dict) or not values or any(not isinstance(key, str) or not isinstance(value, str) for key, value in values.items()):
        raise RuntimeError('Rekey publication requires a nonempty private string-value mapping')
    return {key: base64.b64encode(value.encode()).decode() for key, value in values.items()}


def _platform_secret():
    return {'apiVersion': 'v1', 'kind': 'Secret',
            'metadata': {'name': 'platform-secrets', 'namespace': _NAMESPACE}}


def _unmanaged_rekey_secret(existing, data):
    desired = {**_platform_secret(), 'type': 'Opaque', 'data': data}
    if existing is None:
        raise RuntimeError('Original pre-Helm platform-secrets is absent; rekey refused')
    _validate_existing('platform-config', desired, existing, adopting=True)
    metadata = existing['metadata']
    annotations, labels = metadata.get('annotations', {}), metadata.get('labels', {})
    if any(key.startswith('meta.helm.sh/') for key in annotations) or _MANAGED_BY in labels or metadata.get('ownerReferences'):
        raise RuntimeError('Legacy rekey requires an explicitly unmanaged original Secret')


def _rekey_archive(runtime, values, *, complete=False):
    patterns = ('rekey-complete-*.json',) if complete else ('rekey-precommit-*.json', 'rekey-complete-*.json')
    for pattern in patterns:
        for path in Path(runtime.STATE).glob(pattern):
            if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
                continue
            try:
                archive = json.loads(path.read_bytes())
            except (OSError, ValueError, UnicodeError):
                continue
            if isinstance(archive, dict) and archive.get('keys') == values:
                return True
    return False


def _rekey_original_data(runtime, original_values, live):
    expected = _rekey_data(original_values)
    if live == expected:
        return expected
    from env_secrets import PURPOSE_KEYS
    if not isinstance(live, dict):
        raise RuntimeError('Live rekey credentials are not a valid Secret payload')
    # Retry after targets were generated/saved but before publication. Only
    # archived purpose additions may be absent; every live field stays exact.
    missing = set(expected) - set(live)
    if missing and missing <= set(PURPOSE_KEYS) and all(key in expected and expected[key] == value for key, value in live.items()) and _rekey_archive(runtime, original_values):
        return dict(live)
    # Crash after publication but before the owner-env legacy-key removal.
    final = {key: value for key, value in expected.items() if key != 'encryption_key'}
    if 'encryption_key' in expected and live == final and _rekey_archive(runtime, original_values, complete=True):
        return dict(live)
    raise RuntimeError('Live rekey credentials differ from the original or authenticated archived resume state')


def prepare_rekey(runtime, original_values):
    """Preflight BEFORE owner rekeys/write fencing; return a private plan dict.

    Managed plans capture deployed platform-config values. Legacy plans capture
    the exact original unmanaged Secret data/UID/resourceVersion. This sole
    legacy exception publishes a completed rekey before initial Helm adoption.
    Caller must retain the lifecycle lock through publish_rekey.
    """
    _scope(runtime)
    data = _rekey_data(original_values)
    installed = _installed(runtime, 'platform-config')
    if installed is not None:
        if installed.get('status') != 'deployed':
            raise RuntimeError('Rekey requires a deployed platform-config release; recover failed/pending state first')
        configuration = copy.deepcopy(current_values(runtime, 'platform-config'))
        data = _rekey_original_data(runtime, original_values, configuration.get('secrets', {}).get('platform-secrets'))
        objects = render(runtime, 'platform-config', {'chart': 'platform-config', 'values': configuration})
        found = False
        for desired in objects:
            existing = _get(runtime, desired)
            if existing is not None:
                _validate_existing('platform-config', desired, existing, adopting=False)
            if desired['kind'] == 'Secret' and desired['metadata']['name'] == 'platform-secrets':
                if existing is None or existing.get('data') != data:
                    raise RuntimeError('Live managed platform-secrets differs from original rekey credentials')
                found = True
        if not found:
            raise RuntimeError('Managed chart omits original platform-secrets')
        return {'mode': 'managed', 'values': configuration, 'data': data, 'original': dict(original_values)}
    existing = _get(runtime, _platform_secret())
    data = _rekey_original_data(runtime, original_values, existing.get('data') if existing else None)
    _unmanaged_rekey_secret(existing, data)
    return {'mode': 'legacy', 'uid': existing['metadata']['uid'],
            'resourceVersion': existing['metadata']['resourceVersion'], 'data': data, 'original': dict(original_values)}


def publish_rekey(runtime, plan, final_values):
    """Publish completed owner rekeys using only the preflighted ownership path.

    Never fall back from a managed failure to direct patch. The one-time legacy
    patch tests UID/resourceVersion/data and replaces only Secret data; it never
    applies manifests, changes ownership, or writes last-applied credentials.
    """
    _scope(runtime)
    if not isinstance(plan, dict) or plan.get('mode') not in ('managed', 'legacy'):
        raise RuntimeError('Rekey publication requires its explicit preflight plan')
    data = _rekey_data(final_values)
    if 'encryption_key' in final_values:
        raise RuntimeError('Completed rekey publication must remove the legacy shared key')
    from env_secrets import PURPOSE_KEYS
    original = plan.get('original')
    if not isinstance(original, dict):
        raise RuntimeError('Rekey plan lacks its preflighted original credentials')
    preserved = {key: value for key, value in original.items() if key != 'encryption_key'}
    if any(final_values.get(key) != value for key, value in preserved.items()) or set(final_values) - set(preserved) - set(PURPOSE_KEYS):
        raise RuntimeError('Rekey publication cannot remove or rotate unrelated/preexisting credentials')
    added = set(final_values) - set(preserved)
    if added and not _rekey_archive(runtime, {**original, **{key: final_values[key] for key in added}}):
        raise RuntimeError('New rekey purpose keys require the exact protected target archive')
    installed = _installed(runtime, 'platform-config')
    if plan['mode'] == 'managed':
        if installed is None or installed.get('status') != 'deployed':
            raise RuntimeError('Managed rekey ownership changed or release failed/pending; no legacy fallback')
        configuration = copy.deepcopy(plan['values'])
        if current_values(runtime, 'platform-config') != configuration:
            raise RuntimeError('Managed configuration changed after rekey preflight')
        existing = _get(runtime, _platform_secret())
        if existing is None or existing.get('data') != plan['data']:
            raise RuntimeError('Live managed credentials changed after rekey preflight')
        _validate_existing('platform-config', _platform_secret(), existing, adopting=False)
        if data == plan['data']:
            return
        configuration['secrets']['platform-secrets'] = data
        deploy(runtime, 'platform-config', {'chart': 'platform-config', 'values': configuration})
        return
    if installed is not None:
        raise RuntimeError('Legacy rekey cannot publish after a Helm release appeared')
    existing = _get(runtime, _platform_secret())
    _unmanaged_rekey_secret(existing, plan['data'])
    metadata = existing['metadata']
    if metadata['uid'] != plan['uid'] or metadata['resourceVersion'] != plan['resourceVersion']:
        raise RuntimeError('Original legacy Secret changed after rekey preflight')
    if data == plan['data']:
        return
    patch = [{'op': 'test', 'path': '/metadata/uid', 'value': plan['uid']},
             {'op': 'test', 'path': '/metadata/resourceVersion', 'value': plan['resourceVersion']},
             {'op': 'test', 'path': '/data', 'value': plan['data']},
             {'op': 'replace', 'path': '/data', 'value': data}]
    _execute(runtime, ['kubectl', '--context', runtime.CONTEXT, '--namespace', runtime.NS,
                       'patch', 'Secret', 'platform-secrets', '--type=json', '--patch-file', '/dev/stdin'],
             input=json.dumps(patch).encode())


def service_deployment(runtime, name, images):
    """Render just one service Deployment for the existing disposable Job consumers."""
    _release(runtime, name)
    if name not in _APPLICATIONS:
        raise RuntimeError('Selected service has no application Deployment')
    from release_values import release_specs
    specs = release_specs(images, runtime.STATE, runtime.ROOT)
    selected = [obj for obj in render(runtime, name, specs[name])
                if obj['kind'] == 'Deployment' and obj['metadata']['name'] == name]
    if len(selected) != 1:
        raise RuntimeError('Application chart must contain exactly one selected Deployment')
    return selected[0]
