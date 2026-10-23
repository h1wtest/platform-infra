#!/usr/bin/env python3
"""Fail-closed, isolated local Kubernetes lifecycle. Python stdlib + installed CLIs."""
import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import manifests

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parent
STATE = ROOT / '.local'
CLUSTER = 'sso-remediation'
CONTEXT = 'k3d-' + CLUSTER
NS = CLUSTER
K3S = 'docker.io/rancher/k3s:v1.35.9-k3s1@sha256:ec9868c6a38d4e8c1869832fb5fd1eb8473c39794a0b44d2b952e7ba911951bc'
OPERATOR_URL = 'https://github.com/cloudnative-pg/cloudnative-pg/releases/download/v1.30.1/cnpg-1.30.1.yaml'
OPERATOR_SHA256 = '37237f145d8138256ea25ae830f87759255665ff08f8d552fdd8224a5ec032fb'
PINS = {
    'postgres': 'ghcr.io/cloudnative-pg/postgresql:18.6-standard-trixie@sha256:d72ace96f5803b12c341bb5dac48532e8c1f92f69e8a717a59d779bfc038dea9',
    'cnpg-operator': 'ghcr.io/cloudnative-pg/cloudnative-pg:1.30.1@sha256:923c267ec29636db3bee20f993d0ec4973fa22998e1adad37da79e4d32b5bc07',
    'redpanda': 'docker.io/redpandadata/redpanda:v26.2.5@sha256:badca2d958f81da675c3055a9ecb6ebb590325582bcf16936148ffd65e96e920',
    'mailpit': 'docker.io/axllent/mailpit:v1.32.0@sha256:0790692be935ea4420d085694f7985b1f692ca6a8771ab0e0bd8ba75ac180498',
    'gateway': 'docker.io/nginxinc/nginx-unprivileged:1.30-alpine@sha256:f5116ed4606f3eb015dd4a8e28cb9b351476dc0ad4bc6e9f93b19cec130cdf03',
    'prometheus': 'docker.io/prom/prometheus:v3.15.1@sha256:fa3302279710be2f21a8301ec17a8b4f2301fd829bd113839b3b6b02b6f191a2',
    'grafana': 'docker.io/grafana/grafana:13.2.4-distroless-slim@sha256:3838fe4d1cb7fef51a91b9a72011a7a68736b6052785594d437ec65d441acd8b',
    'tempo': 'docker.io/grafana/tempo:3.1.1@sha256:64e2fbd56d9c2b3412a4b430a58ea59e91a670b1e75f920a0c702213ad145044',
    'otel-collector': 'docker.io/otel/opentelemetry-collector-contrib:0.163.2@sha256:7f22d2a6748110ffb6a59bc0df448bccbf501cdb667d610ede4c61d3863d5849',
}

# Only these selected runtimes have organization-owned security extension recipes.
PATCHED_COMPONENTS = {'gateway': 'nginx', 'grafana': 'grafana', 'tempo': 'tempo', 'cnpg-operator': 'cnpg-operator'}
PROFILE = 'default'
PUBLIC_ORIGIN = 'https://localhost:8448'
GENERIC_CONTEXTS = frozenset({'k3d-sso-remediation'})


def configure_profile(profile='default', context=None):
    """Select one fixed namespace/state boundary, never arbitrary cloud contexts."""
    global PROFILE, STATE, NS, CONTEXT, PUBLIC_ORIGIN
    if profile not in ('default', 'generic'):
        raise RuntimeError('Unknown local infrastructure profile')
    if profile == 'generic' and context not in GENERIC_CONTEXTS:
        raise RuntimeError('Generic profile requires explicit allowlisted local context')
    if profile == 'default' and context not in (None, 'k3d-sso-remediation'):
        raise RuntimeError('Default profile requires original local context')
    PROFILE = profile
    NS = 'generic-subscriptions' if profile == 'generic' else CLUSTER
    CONTEXT = context or 'k3d-sso-remediation'
    STATE = ROOT / ('.generic-local' if profile == 'generic' else '.local')
    PUBLIC_ORIGIN = 'https://localhost:' + ('18448' if profile == 'generic' else '8448')
    import env_secrets
    import security_material
    manifests.configure(NS)
    env_secrets.configure(profile == 'generic')
    security_material.configure(NS)
    # Imported modules retain mutable application maps but immutable tuples need refreshing.
    for name in ('release_values', 'credential_guard', 'helm_release'):
        module = sys.modules.get(name)
        if module is not None and hasattr(module, 'configure'):
            module.configure()


def run(args, *, input=None, capture=True, timeout=600, check=True):
    try:
        result = subprocess.run([str(x) for x in args], input=input, stdout=subprocess.PIPE if capture else None, stderr=subprocess.PIPE if capture else None, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError(f'Command unavailable or timed out: {args[0]}') from error
    if check and result.returncode:
        # Never print SQL input, environment, connection strings or bootstrap passwords.
        detail = (result.stderr or b'').decode(errors='replace')[-1800:] if input is None else '[stdin-fed command; inspect protected local service logs]'
        raise RuntimeError(f'Command failed ({result.returncode}): {args[0]} {args[1] if len(args) > 1 else ""}; stderr: {detail}')
    return result


def kube(*args, input=None, timeout=600, check=True):
    return run(['kubectl', '--context', CONTEXT, '-n', NS, *args], input=input, timeout=timeout, check=check)


def apply(objects):
    objects = list(objects)
    if objects:
        kube('apply', '-f', '-', input=json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': objects}).encode())


def require_tools():
    if not shutil.which('k3d'):
        candidate = Path.home() / 'go/bin/k3d'
        if candidate.is_file():
            os.environ['PATH'] += os.pathsep + str(candidate.parent)
    missing = [name for name in ('docker', 'kubectl', 'k3d', 'helm', 'openssl', 'curl') if not shutil.which(name)]
    if missing:
        raise RuntimeError('Install prerequisites before continuing: ' + ', '.join(missing) + '. k3d required version: v5.9.0; kubectl compatible with Kubernetes1.35.')
    version = run(['k3d', 'version']).stdout.decode()
    if 'v5.9.0' not in version:
        raise RuntimeError('Use pinned k3d v5.9.0; unrecognized version is not silently accepted')
    client = json.loads(run(['kubectl', 'version', '--client', '-o', 'json']).stdout)['clientVersion']
    if client.get('major') != '1' or client.get('minor', '').rstrip('+') not in ('34', '35', '36'):
        raise RuntimeError('kubectl minor must be within one of pinned Kubernetes1.35 (use kubectl1.36.1); installed client is unsupported')
    if run(['helm', 'version', '--template', '{{.Version}}']).stdout.decode().strip() != 'v4.3.1':
        raise RuntimeError('Use checksum-pinned Helm v4.3.1; run scripts/bootstrap-tools.sh')


def create_secrets(state):
    import env_secrets
    from security_material import ensure
    state = Path(state)
    if state.is_symlink() or (PROFILE == 'generic' and state.name != '.generic-local'):
        raise RuntimeError('Credential state must be a real directory in the selected isolated profile')
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(state, 0o700)
    if (state / 'secrets.json').exists():
        env_secrets.migrate(state)
    if env_secrets.exists(state):
        values = env_secrets.load(state)
        env_secrets.materialize(state)
        for file in ('ca.crt', 'tls.crt'):
            if not (state / file).is_file():
                raise RuntimeError(f'Existing state incomplete ({file}); restore saved local credentials; never rotate implicitly')
        return ensure(state, values, run)
    configured = env_secrets.initial_values(state)
    values = {name: secrets.token_urlsafe(32) for name in ('postgres_password', 'identity_token', 'profile_token', 'notification_token', 'admin_token', 'gateway_token', 'grafana_password', 'admin_password', 'telegram_webhook_secret')}
    if PROFILE == 'generic':
        values.update({domain + '_token': secrets.token_urlsafe(32)
                       for domain in ('catalog', 'billing', 'subscription', 'referral')})
    values['admin_email'] = os.environ.get('OWNER_EMAIL', 'owner@platform.local')
    values['admin_password'] = os.environ.get('OWNER_PASSWORD', values['admin_password'])
    values['telegram_bot_token'] = os.environ.get('TELEGRAM_BOT_TOKEN', '')
    for db in manifests.DBS:
        for role in ('runtime', 'migration'):
            values[f'{db}_{role}_password'] = secrets.token_urlsafe(32)
    values.update(configured)
    old_mask = os.umask(0o077)
    try:
        run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072', '-out', state / 'ca.key'])
        run(['openssl', 'req', '-x509', '-new', '-sha256', '-days', '365', '-key', state / 'ca.key', '-subj', '/CN=SSO Remediation Local CA', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-addext', 'subjectKeyIdentifier=hash', '-addext', 'authorityKeyIdentifier=keyid:always', '-out', state / 'ca.crt'])
        run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072', '-out', state / 'tls.key'])
        san = ['localhost', *manifests.APPS, 'gateway']
        services = list(san[1:])
        san += [f'{name}.{NS}.svc.cluster.local' for name in services]
        san += [f'{name}.{NS}.svc' for name in services]
        (state / 'tls.ext').write_text('subjectAltName=' + ','.join('DNS:' + name for name in san) + ',IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\nextendedKeyUsage=serverAuth\n')
        run(['openssl', 'req', '-new', '-key', state / 'tls.key', '-subj', '/CN=localhost', '-out', state / 'tls.csr'])
        run(['openssl', 'x509', '-req', '-in', state / 'tls.csr', '-CA', state / 'ca.crt', '-CAkey', state / 'ca.key', '-CAcreateserial', '-days', '90', '-sha256', '-extfile', state / 'tls.ext', '-out', state / 'tls.crt'])
        run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072', '-out', state / 'signing.pem'])
        (state / 'backup.key').write_text(secrets.token_urlsafe(64) + '\n')
        ensure(state, values, run, initialize=True)
        env_secrets.save(state, values)
        env_secrets.capture_private(state)
        env_secrets.initialize(state)
    finally:
        os.umask(old_mask)
    return values


def workspace_hash(workspace=WORKSPACE):
    digest = hashlib.sha256()
    ignored = {'.git', '.local', '.generic-local', 'target', 'node_modules', 'dist', '.venv', '__pycache__', 'docs', '.svelte-kit'}
    directories = ['identity-service', 'user-notification-service', 'frontend', 'platform-contracts', 'platform-infra/components']
    if PROFILE == 'generic':
        directories += list(manifests.GENERIC_APPS)
    for directory in directories:
        for base, dirs, files in os.walk(workspace / directory):
            dirs[:] = sorted(d for d in dirs if d not in ignored)
            for name in sorted(files):
                if name in ignored or name == '.env' or (name.startswith('.env.') and name != '.env.example') or name.endswith(('.key', '.pem', '.pyc')):
                    continue
                path = Path(base) / name
                if path.is_symlink():
                    raise RuntimeError('Build input symlinks are not supported')
                relative = path.relative_to(workspace).as_posix().encode('utf-8')
                content = path.read_bytes()
                digest.update(len(relative).to_bytes(8, 'big'))
                digest.update(relative)
                digest.update(len(content).to_bytes(8, 'big'))
                digest.update(content)
    return digest.hexdigest()


def component_recipe_hash(name):
    directory = ROOT / 'components' / PATCHED_COMPONENTS[name]
    digest = hashlib.sha256()
    for path in sorted(directory.rglob('*')):
        if path.is_symlink():
            raise RuntimeError('Build input symlinks are not supported')
        if path.is_file():
            relative = path.relative_to(directory).as_posix().encode()
            content = path.read_bytes()
            digest.update(len(relative).to_bytes(8, 'big'))
            digest.update(relative)
            digest.update(len(content).to_bytes(8, 'big'))
            digest.update(content)
    return digest.hexdigest()


def build_component(name):
    """Build a genuine patched runtime with content and input provenance."""
    recipe = component_recipe_hash(name)
    staging = f'sso-remediation/{name}:build-' + uuid.uuid4().hex
    command = ['docker', 'build', '--pull', '-t', staging]
    if name == 'gateway':
        command += ['--build-arg', 'GATEWAY_BASE=' + PINS[name]]
    elif name == 'tempo':
        command += ['--build-arg', 'TEMPO_BASE=' + PINS[name]]
    elif name == 'grafana':
        command += ['--build-arg', 'GRAFANA_BASE=' + PINS[name]]
    elif name == 'cnpg-operator':
        command += ['--build-arg', 'CNPG_OPERATOR_BASE=' + PINS[name]]
    command += [ROOT / 'components' / PATCHED_COMPONENTS[name]]
    run(command, timeout=2400)
    info = json.loads(run(['docker', 'image', 'inspect', staging]).stdout)[0]
    image_id = info['Id']
    if not image_id.startswith('sha256:') or len(image_id) != 71 or any(c not in '0123456789abcdef' for c in image_id[7:]):
        raise RuntimeError(f'Build returned an invalid image identity: {name}')
    tag = f'sso-remediation/{name}:sha256-' + image_id.split(':', 1)[1]
    run(['docker', 'tag', staging, tag])
    run(['docker', 'image', 'rm', staging])
    if component_recipe_hash(name) != recipe:
        raise RuntimeError(f'Build inputs changed during image compilation: {name}')
    return {name: tag, name + '_id': image_id, name + '_base': PINS[name], name + '_recipe_sha256': recipe}


def verify_local_image(name, image, image_id):
    expected_tag = f'sso-remediation/{name}:sha256-' + image_id.removeprefix('sha256:')
    if not image_id.startswith('sha256:') or len(image_id) != 71 or any(c not in '0123456789abcdef' for c in image_id[7:]) or image != expected_tag:
        raise RuntimeError(f'Invalid content-addressed image lock: {name}')
    observed = json.loads(run(['docker', 'image', 'inspect', image]).stdout)[0]['Id']
    if observed != image_id:
        raise RuntimeError(f'Image tag was mutated: {name}')


def build_images():
    run(['uv', 'run', '--no-project', 'python', WORKSPACE / 'user-notification-service/scripts/contracts-digest.py', WORKSPACE / 'platform-contracts', '--verify', WORKSPACE / 'user-notification-service/contracts-tree.sha256'], timeout=60)
    STATE.mkdir(exist_ok=True, mode=0o700)
    images = {}
    run(['docker', 'pull', K3S], timeout=900)
    images['k3s'] = K3S
    for name, tag in PINS.items():
        run(['docker', 'pull', tag], timeout=900)
        info = json.loads(run(['docker', 'image', 'inspect', tag]).stdout)[0]
        refs = info.get('RepoDigests', [])
        expected_digest = tag.rsplit('@', 1)[1]
        if not any(ref.rsplit('@', 1)[-1] == expected_digest for ref in refs):
            raise RuntimeError(f'Pulled image differs from pinned registry digest: {name}')
        # CNPG inspects the PostgreSQL major in the tag for upgrade safety; retain tag plus digest.
        images[name] = tag
    source = workspace_hash()
    for name in PATCHED_COMPONENTS:
        images.update(build_component(name))
    applications = [('identity', 'identity-service'), ('profile', 'user-notification-service'), ('notification', 'user-notification-service'), ('worker', 'user-notification-service'), ('admin', 'user-notification-service'), ('frontend', 'frontend')]
    if PROFILE == 'generic':
        applications += [(target, repo) for repo, (target, _, _) in manifests.GENERIC_APPS.items()]
    for name, repo in applications:
        staging = f'sso-remediation/{name}:build-' + uuid.uuid4().hex
        command = ['docker', 'build', '--pull', '-f', str(WORKSPACE / repo / 'Dockerfile'), '-t', staging]
        if repo == 'user-notification-service':
            command += ['--build-arg', 'TARGET=' + name]
        command += [str(WORKSPACE if name != 'frontend' else WORKSPACE / 'frontend')]
        run(command, timeout=2400)
        info = json.loads(run(['docker', 'image', 'inspect', staging]).stdout)[0]
        tag = f"sso-remediation/{name}:sha256-{info['Id'].split(':', 1)[1]}"
        run(['docker', 'tag', staging, tag])
        run(['docker', 'image', 'rm', staging])
        images[name] = tag
        images[name + '_id'] = info['Id']
    with urllib.request.urlopen(OPERATOR_URL, timeout=60) as response:
        operator = response.read()
    if hashlib.sha256(operator).hexdigest() != OPERATOR_SHA256:
        raise RuntimeError('CNPG release artifact does not match authenticated GitHub release digest')
    (STATE / 'cnpg-operator.yaml').write_bytes(operator)
    images['operator_sha256'] = hashlib.sha256(operator).hexdigest()
    if workspace_hash() != source:
        raise RuntimeError('Build inputs changed during image compilation; immutable lock not published. Stabilize source and rebuild.')
    images['source_sha256'] = source
    (STATE / 'images.lock.json').write_text(json.dumps(images, indent=2) + '\n')
    print('Built content-addressed application/gateway tags and locked registry bases in ' + str(STATE / 'images.lock.json'))


def load_images(state=None):
    path = (STATE if state is None else state) / 'images.lock.json'
    if not path.is_file():
        raise RuntimeError('No immutable image lock. Run make build first.')
    images = json.loads(path.read_text())
    if images.get('k3s') != K3S:
        raise RuntimeError('K3s image pin changed; run make build')
    for key in PINS:
        if key in PATCHED_COMPONENTS:
            image_id = images.get(key + '_id', '')
            if images.get(key + '_base') != PINS[key] or images.get(key + '_recipe_sha256') != component_recipe_hash(key):
                raise RuntimeError(f'Patched component build inputs changed; run make build: {key}')
            if not image_id.startswith('sha256:') or len(image_id) != 71 or any(c not in '0123456789abcdef' for c in image_id[7:]) or images.get(key) != f'sso-remediation/{key}:sha256-' + image_id.removeprefix('sha256:'):
                raise RuntimeError(f'Component requires a content-addressed patched image lock; run make build: {key}')
            continue
        if images.get(key) != PINS[key]:
            raise RuntimeError(f'Infrastructure image pin changed; run make build: {key}')
    return images


def cluster():
    if PROFILE == 'generic':
        raise RuntimeError('Generic profile is namespace-only; cluster creation is forbidden')
    from cluster_identity import guard
    clusters = json.loads(run(['k3d', 'cluster', 'list', '-o', 'json']).stdout)
    created = not any(item['name'] == CLUSTER for item in clusters)
    if created:
        if (STATE / 'cluster-identity.json').exists():
            raise RuntimeError('Retained cluster identity exists but cluster is missing; refuse recreation over existing identity')
        run(['k3d', 'cluster', 'create', CLUSTER, '--subnet', 'auto', '--image', load_images()['k3s'], '--servers', '3', '--agents', '0', '--port', '8448:443@loadbalancer', '--port', '8089:80@loadbalancer', '--k3s-arg', '--disable=traefik@server:*', '--wait', '--timeout', '240s'], timeout=300)
        kube('wait', '--for=condition=Ready', 'nodes', '--all', '--timeout=120s', timeout=130)
    guard(sys.modules[__name__], initialize=created)
    nodes = json.loads(kube('get', 'nodes', '-o', 'json').stdout)['items']
    expected = 'v1.35.9+k3s1'
    actual = sorted({node['status']['nodeInfo']['kubeletVersion'] for node in nodes})
    if actual != [expected]:
        print('OPEN MAINTENANCE GATE: existing Kubernetes nodes ' + ', '.join(actual) + ' differ from configured ' + expected + '; existing data/cluster not upgraded or deleted implicitly.', file=sys.stderr)



def start_cluster(timeout='180s', k3d='k3d'):
    if PROFILE == 'generic':
        raise RuntimeError('Generic profile is namespace-only; cluster start is forbidden')
    from cluster_identity import guard
    guard(sys.modules[__name__], live=False)
    run([k3d, 'cluster', 'start', CLUSTER, '--wait', '--timeout', timeout], timeout=240)
    kube('wait', '--for=condition=Ready', 'nodes', '--all', '--timeout=120s', timeout=130)
    guard(sys.modules[__name__])

def install_operator(images):
    from cnpg_operator import install
    verify_local_image('cnpg-operator', images['cnpg-operator'], images['cnpg-operator_id'])
    install(sys.modules[__name__], images)




def primary():
    if PROFILE == 'generic':
        return 'postgres-0'
    value = json.loads(kube('get', 'cluster.postgresql.cnpg.io', 'postgres', '-o', 'json').stdout)
    name = value.get('status', {}).get('currentPrimary')
    if not name:
        raise RuntimeError('PostgreSQL primary not known')
    return name


def dbsql(statement, database='postgres', snapshot=None):
    if snapshot:
        statement = f"BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET TRANSACTION SNAPSHOT '{snapshot}';\n" + statement + ';\nCOMMIT;'
    return kube('exec', '-i', primary(), '--', 'psql', '-U', 'postgres', '-d', database, '-v', 'ON_ERROR_STOP=1', '-X', '-q', '-t', '-A', input=statement.encode()).stdout.decode().strip()


def provision_databases(values):
    for db in manifests.DBS:
        statements = []
        for role in ('migration', 'runtime'):
            username = f'{db}_{role}'
            password = "'" + values[f'{username}_password'].replace("'", "''") + "'"
            command = f'CREATE ROLE {username} LOGIN PASSWORD {password}'
            literal = "'" + command.replace("'", "''") + "'"
            statements.append(f"SELECT {literal} WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname='{username}')\\gexec")
        statements += [f"SELECT 'CREATE DATABASE {db}_db OWNER {db}_migration' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname='{db}_db')\\gexec", f'REVOKE CONNECT ON DATABASE {db}_db FROM PUBLIC;', f'GRANT CONNECT ON DATABASE {db}_db TO {db}_runtime;']
        dbsql('\n'.join(statements) + '\n')
        dbsql(f'REVOKE CREATE ON SCHEMA public FROM PUBLIC; GRANT ALL ON SCHEMA public TO {db}_migration; CREATE EXTENSION IF NOT EXISTS "uuid-ossp"; ALTER DEFAULT PRIVILEGES FOR ROLE {db}_migration IN SCHEMA public GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO {db}_runtime; ALTER DEFAULT PRIVILEGES FOR ROLE {db}_migration IN SCHEMA public GRANT USAGE,SELECT ON SEQUENCES TO {db}_runtime;', f'{db}_db')


def migration_jobs(images, selected=None):
    for name, (target, _, db) in manifests.APPS.items():
        if target == 'worker' or (selected is not None and name != selected):
            continue
        job_name = 'migrate-' + target + '-' + uuid.uuid4().hex[:8]
        migration_env = {'DATABASE_URL': (db + '-database', 'MIGRATION_DATABASE_URL')}
        if target == 'identity':
            migration_env['MFA_ENCRYPTION_KEY'] = ('platform-secrets', 'mfa_encryption_key')
        if name in manifests.GENERIC_APPS:
            migration_env.update(HTTP_PORT=str(manifests.APPS[name][1]), PUBLIC_ORIGIN=PUBLIC_ORIGIN,
                INTERNAL_SERVICE_TOKEN=('platform-secrets', target + '_token'),
                IDENTITY_URL='https://identity-service:8001', TLS_CERT_FILE='/run/tls/tls.crt',
                TLS_KEY_FILE='/run/tls/tls.key', INTERNAL_CA_FILE='/run/tls/ca.crt',
                KAFKA_BROKERS=','.join(f'redpanda-{index}.redpanda:29092' for index in range(3)),
                KAFKA_TLS_CA_FILE='/run/tls/ca.crt', KAFKA_SASL_USERNAME=target,
                KAFKA_SASL_PASSWORD=('platform-secrets', 'kafka_' + target + '_password'),
                QUARANTINE_ENCRYPTION_KEY=('platform-secrets', target + '_quarantine_key'))
        spec = manifests.pod(name, images[target], env=migration_env, args=['migrate'])
        if name in manifests.GENERIC_APPS:
            spec['volumes'].append({'name': 'tls', 'secret': {'secretName': name + '-tls', 'defaultMode': 0o440}})
            spec['containers'][0]['volumeMounts'].append({'name': 'tls', 'mountPath': '/run/tls', 'readOnly': True})
        spec['restartPolicy'] = 'Never'
        # Migration precedes application release installation; use the namespace
        # default account with token automount disabled, not a not-yet-created SA.
        spec['serviceAccountName'] = 'default'
        spec['volumes'].append({'name': 'postgres-ca', 'secret': {'secretName': 'postgres-ca'}})
        spec['containers'][0]['volumeMounts'].append({'name': 'postgres-ca', 'mountPath': '/run/postgres', 'readOnly': True})
        from database_gate import attach
        attach(spec, images)
        apply([manifests.resource('Job', job_name, {'backoffLimit': 0, 'activeDeadlineSeconds': 180, 'ttlSecondsAfterFinished': 86400, 'template': {'metadata': {'labels': {'app': name}}, 'spec': spec}})])
        kube('wait', '--for=condition=complete', 'job/' + job_name, '--timeout=200s')
        dbsql(f'GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO {db}_runtime; GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO {db}_runtime;', db + '_db')


def configure_brokers():
    from security_material import broker_cluster_config
    # Bootstrap applies only to a fresh cluster. Persist the policy on retained clusters too.
    expected_config = broker_cluster_config()
    for property_name, expected in expected_config.items():
        value = expected if isinstance(expected, str) else json.dumps(expected)
        kube('exec', 'redpanda-0', '--', 'rpk', 'cluster', 'config', 'set', property_name, value)
    # rpk config get returns YAML, including bare strings and block lists, not JSON.
    # Feed curl credentials via stdin config: no secret enters the process arguments or output.
    command = 'printf \'user = "%s:%s"\\n\' "$RPK_USER" "$RPK_PASS" | exec curl --config - --fail --silent --show-error --max-time 10 --url "http://127.0.0.1:9645/v1/cluster_config?include_defaults=true"'
    actual_config = json.loads(kube('exec', 'redpanda-0', '--', 'sh', '-ec', command).stdout)
    for property_name, expected in expected_config.items():
        actual = actual_config.get(property_name)
        if type(actual) is not type(expected) or actual != expected:
            raise RuntimeError('Broker cluster configuration did not persist: ' + property_name)


def topics():
    configure_brokers()
    from broker_security import topic_inventory
    for name, retention in topic_inventory(PROFILE == 'generic'):
        current = kube('exec', 'redpanda-0', '--', 'rpk', '-X', 'brokers=localhost:29092', 'topic', 'list', '--format', 'json').stdout
        records = json.loads(current)
        if not any(item['name'] == name for item in records):
            kube('exec', 'redpanda-0', '--', 'rpk', '-X', 'brokers=localhost:29092', 'topic', 'create', name, '-p', '6', '-r', '3', '-c', 'retention.ms=' + retention)
        kube('exec', 'redpanda-0', '--', 'rpk', '-X', 'brokers=localhost:29092', 'topic', 'describe', name)


def up():
    values = create_secrets(STATE)
    images = load_images()
    if images['source_sha256'] != workspace_hash():
        raise RuntimeError('Build inputs changed since image lock; run make build')
    if PROFILE == 'generic':
        from cluster_identity import guard
        guard(sys.modules[__name__], initialize=True)
    else:
        cluster()
    from release_control import selected_images
    images = selected_images(sys.modules[__name__], images, reconcile=True)
    from credential_guard import verify
    verify(sys.modules[__name__], values)
    for name in (*[item[0] for item in manifests.APPS.values()], 'frontend', *PATCHED_COMPONENTS):
        if images[name].startswith('sso-remediation/'):
            verify_local_image(name, images[name], images[name + '_id'])
        else:
            run(['docker', 'pull', images[name]], timeout=900)
        run(['k3d', 'image', 'import', images[name], '-c', CLUSTER], timeout=600)
    if PROFILE != 'generic':
        install_operator(images)
    import helm_release
    from release_control import specs
    desired = specs(sys.modules[__name__], images)
    if PROFILE != 'generic':
        apply([{'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': NS, 'labels': {'pod-security.kubernetes.io/enforce': 'restricted', 'pod-security.kubernetes.io/enforce-version': 'v1.33'}}}])
    for release in ('platform-config', 'postgres', 'redpanda', 'mailpit'):
        helm_release.deploy(sys.modules[__name__], release, desired[release], timeout=360)
    if PROFILE == 'generic':
        kube('rollout', 'status', 'statefulset/postgres', '--timeout=300s')
        ca_secret = json.loads(kube('get', 'secret', 'platform-ca', '-o', 'json').stdout)
    else:
        kube('wait', '--for=condition=Ready', 'cluster.postgresql.cnpg.io/postgres', '--timeout=300s')
        from cnpg_operator import wait_instances
        wait_instances(sys.modules[__name__], images['cnpg-operator'])
        ca_secret = json.loads(kube('get', 'secret', 'postgres-ca', '-o', 'json').stdout)
    # Both profiles expose verified PostgreSQL CA material through owner-specific state.
    (STATE / 'postgres-ca.crt').write_bytes(base64.b64decode(ca_secret['data']['ca.crt']))
    kube('rollout', 'status', 'statefulset/redpanda', '--timeout=300s')
    from broker_health import wait_healthy
    wait_healthy(sys.modules[__name__])
    provision_databases(values)
    migration_jobs(images)
    topics()
    from broker_security import provision
    provision(sys.modules[__name__], values)
    from release_values import APPLICATION_RELEASES
    for release in ('prometheus', 'tempo', 'otel-collector', 'grafana', *APPLICATION_RELEASES):
        helm_release.deploy(sys.modules[__name__], release, desired[release], timeout=240)
    for name in [*manifests.APPS, 'frontend', 'gateway', 'mailpit', 'tempo', 'prometheus', 'grafana', 'otel-collector']:
        kube('rollout', 'status', 'deployment/' + name, '--timeout=240s')
    print('Local environment deployed in ' + NS + '; access ' + PUBLIC_ORIGIN + ' using explicit loopback forwards. Trust ' + str(STATE / 'ca.crt') + ' only for this stand.')


def bootstrap_owner():
    images = load_images()
    from helm_release import service_deployment
    app = service_deployment(sys.modules[__name__], 'identity-service', images)
    spec = app['spec']['template']['spec']
    spec['restartPolicy'] = 'Never'
    c = spec['containers'][0]
    c.pop('readinessProbe', None); c.pop('livenessProbe', None); c.pop('startupProbe', None)
    c['args'] = ['bootstrap-owner']
    c['env'] += [{'name': 'OWNER_EMAIL', 'valueFrom': {'secretKeyRef': {'name': 'platform-secrets', 'key': 'admin_email'}}}, {'name': 'OWNER_PASSWORD', 'valueFrom': {'secretKeyRef': {'name': 'platform-secrets', 'key': 'admin_password'}}}]
    name = 'bootstrap-owner-' + uuid.uuid4().hex[:8]
    apply([manifests.resource('Job', name, {'backoffLimit': 0, 'activeDeadlineSeconds': 120, 'ttlSecondsAfterFinished': 86400, 'template': {'metadata': {'labels': {'app': 'identity-service'}}, 'spec': spec}})])
    kube('wait', '--for=condition=complete', 'job/' + name, '--timeout=150s')
    owner_env = STATE / 'owners' / 'identity-service' / '.env' if PROFILE == 'generic' else WORKSPACE / 'identity-service' / '.env'
    print('Owner bootstrapped; credentials remain in ' + str(owner_env) + '. Complete MFA before privileged commands.')


def encrypt_file(source, destination, key):
    # Encrypt-then-MAC: OpenSSL AES-256-CBC with random salt + PBKDF2, SHA256 HMAC authenticates header+ciphertext.
    with tempfile.TemporaryDirectory() as directory:
        cipher = Path(directory) / 'cipher'
        run(['openssl', 'enc', '-aes-256-cbc', '-pbkdf2', '-iter', '600000', '-salt', '-in', source, '-out', cipher, '-pass', 'file:' + str(key)])
        payload = cipher.read_bytes()
        mac_key = hashlib.pbkdf2_hmac('sha256', key.read_bytes(), b'sso-backup-authentication-v1', 600000)
        destination.write_bytes(b'SSOBK1' + hmac.digest(mac_key, payload, 'sha256') + payload)
        os.chmod(destination, 0o600)


def decrypt_file(source, destination, key):
    content = source.read_bytes()
    mac_key = hashlib.pbkdf2_hmac('sha256', key.read_bytes(), b'sso-backup-authentication-v1', 600000)
    if len(content) < 54 or content[:6] != b'SSOBK1' or not hmac.compare_digest(content[6:38], hmac.digest(mac_key, content[38:], 'sha256')):
        raise RuntimeError('Backup authentication failed; restore refused')
    with tempfile.TemporaryDirectory() as directory:
        cipher = Path(directory) / 'cipher'; cipher.write_bytes(content[38:])
        run(['openssl', 'enc', '-d', '-aes-256-cbc', '-pbkdf2', '-iter', '600000', '-in', cipher, '-out', destination, '-pass', 'file:' + str(key)])


def wait_writable():
    if PROFILE == 'generic':
        kube('rollout', 'status', 'statefulset/postgres', '--timeout=300s')
        if dbsql('SELECT NOT pg_is_in_recovery()') != 't':
            raise RuntimeError('Generic local PostgreSQL is not writable')
    else:
        from fault_lifecycle import wait_writable as wait
        wait(sys.modules[__name__])


def backup():
    import env_secrets
    env_secrets.materialize(STATE)
    wait_writable()
    backup_dir = STATE / 'backups' / (time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + uuid.uuid4().hex[:8])
    backup_dir.mkdir(parents=True, mode=0o700)
    started = time.time()
    for db in manifests.DBS:
        keeper = subprocess.Popen(['kubectl', '--context', CONTEXT, '-n', NS, 'exec', '-i', primary(), '--', 'psql', '-U', 'postgres', '-d', db + '_db', '-v', 'ON_ERROR_STOP=1', '-X', '-q', '-t', '-A'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            keeper.stdin.write(b'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;\nSELECT pg_export_snapshot();\n'); keeper.stdin.flush()
            import select
            if not select.select([keeper.stdout], [], [], 30)[0]:
                raise RuntimeError('Exported backup snapshot timed out')
            snapshot = keeper.stdout.readline().decode().strip()
            if not snapshot or any(c not in '0123456789ABCDEF-' for c in snapshot):
                raise RuntimeError('Invalid PostgreSQL exported snapshot')
            with tempfile.TemporaryDirectory() as directory:
                plain = Path(directory) / 'dump'
                result = kube('exec', primary(), '--', 'pg_dump', '-U', 'postgres', '-Fc', '--no-owner', '--snapshot=' + snapshot, db + '_db', timeout=300)
                plain.write_bytes(result.stdout)
                fingerprints = logical_fingerprint(db + '_db', snapshot)
                encrypt_file(plain, backup_dir / (db + '.dump.enc'), STATE / 'backup.key')
                source = Path(directory) / 'source.json'; source.write_text(json.dumps(fingerprints))
                encrypt_file(source, backup_dir / (db + '.source.enc'), STATE / 'backup.key')
        finally:
            original_error = sys.exc_info()[1]
            try:
                keeper.communicate(b'ROLLBACK;\n', timeout=20)
            except (BrokenPipeError, OSError, subprocess.TimeoutExpired):
                keeper.terminate()
                keeper.wait(timeout=10)
                if original_error is None:
                    raise RuntimeError('Backup snapshot keeper failed during transaction cleanup')
    manifest = {'created_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'elapsed_seconds': round(time.time() - started, 3), 'databases': list(manifests.DBS), 'scope': 'separate consistent per-database snapshots; not a distributed atomic snapshot', 'images_sha256': hashlib.sha256((STATE / 'images.lock.json').read_bytes()).hexdigest()}
    (backup_dir / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(backup_dir)


def logical_fingerprint(database, snapshot=None):
    tables = dbsql("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename", database, snapshot).splitlines()
    result = {}
    for table in tables:
        quoted = '"' + table.replace('"', '""') + '"'
        # Canonical JSON rows sorted as strings: compares values, not row estimates or counts alone.
        rows = dbsql(f'SELECT row_to_json(t)::text FROM {quoted} AS t ORDER BY row_to_json(t)::text', database, snapshot)
        result[table] = hashlib.sha256(rows.encode()).hexdigest()
    return result


def restore_verify(path):
    if not (path / 'manifest.json').is_file():
        raise RuntimeError('Select one complete backup directory')
    import env_secrets
    env_secrets.materialize(STATE)
    results = {}
    for db in manifests.DBS:
        restore_db = 'restore_' + uuid.uuid4().hex
        started = time.time()
        with tempfile.TemporaryDirectory() as directory:
            plain = Path(directory) / 'dump'
            decrypt_file(path / (db + '.dump.enc'), plain, STATE / 'backup.key')
            dbsql(f'CREATE DATABASE {restore_db}')
            try:
                kube('exec', '-i', primary(), '--', 'pg_restore', '-U', 'postgres', '--no-owner', '--no-privileges', '--exit-on-error', '-d', restore_db, input=plain.read_bytes(), timeout=300)
                dump_rows = logical_fingerprint(restore_db)
                source = Path(directory) / 'source.json'
                decrypt_file(path / (db + '.source.enc'), source, STATE / 'backup.key')
                if not dump_rows or dump_rows != json.loads(source.read_text()):
                    raise RuntimeError('Restored values differ from source database snapshot')
                results[db] = {'tables': dump_rows, 'restore_seconds': round(time.time() - started, 3)}
            finally:
                dbsql(f'DROP DATABASE {restore_db}')
    (path / 'restore-verification.json').write_text(json.dumps(results, indent=2) + '\n')
    print('Authenticated backups restored into unique disposable databases; row-content hashes match. RTO measurements recorded in restore-verification.json.')


def port_forward(service, port):
    target = 'gateway' if service in ('gateway', 'gateway-http') else service
    remote = {'mailpit': '8025', 'prometheus': '9090', 'grafana': '3000', 'tempo': '3200', 'gateway': '443', 'gateway-http': '80'}[service]
    print(f'Forwarding only loopback 127.0.0.1:{port} to {target}; Ctrl-C stops access', flush=True)
    run(['kubectl', '--context', CONTEXT, '-n', NS, 'port-forward', '--address=127.0.0.1', 'service/' + target, f'{port}:' + remote], capture=False, timeout=86400)


def check():
    pods = json.loads(kube('get', 'pods', '-o', 'json').stdout)['items']
    historical = [p['metadata']['name'] for p in pods if p['status'].get('phase') == 'Failed' and any(o.get('kind') == 'Job' for o in p['metadata'].get('ownerReferences', []))]
    if historical:
        print('Historical failed Jobs retained for diagnostics (not current controller readiness): ' + ', '.join(historical), file=sys.stderr)
    deployments = [*manifests.APPS, 'frontend', 'gateway', 'mailpit', 'tempo', 'prometheus', 'grafana', 'otel-collector']
    for name in deployments:
        controller = json.loads(kube('get', 'deployment', name, '-o', 'json').stdout)
        desired = controller['spec']['replicas']
        status = controller.get('status', {})
        if desired < 1 or status.get('observedGeneration', 0) < controller['metadata']['generation'] or status.get('updatedReplicas', 0) != desired or status.get('availableReplicas', 0) != desired or status.get('readyReplicas', 0) != desired:
            raise RuntimeError('Required deployment is not fully current/Ready: ' + name)
        replica_sets = json.loads(kube('get', 'replicasets', '-l', 'app=' + name, '-o', 'json').stdout)['items']
        owner_uids = {r['metadata']['uid'] for r in replica_sets if any(o.get('uid') == controller['metadata']['uid'] for o in r['metadata'].get('ownerReferences', [])) and r['spec'].get('replicas', 0) > 0}
        active = [p for p in pods if not p['metadata'].get('deletionTimestamp') and any(o.get('uid') in owner_uids for o in p['metadata'].get('ownerReferences', []))]
        if len(active) != desired or any(p['status'].get('phase') != 'Running' or not any(c['type'] == 'Ready' and c['status'] == 'True' for c in p['status'].get('conditions', [])) for p in active):
            raise RuntimeError('Required deployment pods not Ready: ' + name)
    broker = json.loads(kube('get', 'statefulset', 'redpanda', '-o', 'json').stdout)
    desired = broker['spec']['replicas']
    if broker.get('status', {}).get('readyReplicas', 0) != desired or broker.get('status', {}).get('currentRevision') != broker.get('status', {}).get('updateRevision'):
        raise RuntimeError('Redpanda stateful controller is not fully updated/Ready')
    from broker_health import wait_healthy
    wait_healthy(sys.modules[__name__], timeout=30)
    if PROFILE == 'generic':
        postgres = json.loads(kube('get', 'statefulset', 'postgres', '-o', 'json').stdout)
        if postgres.get('status', {}).get('readyReplicas') != 1:
            raise RuntimeError('Local single PostgreSQL instance is not Ready (generic profile is not HA)')
    else:
        cluster = json.loads(kube('get', 'cluster.postgresql.cnpg.io', 'postgres', '-o', 'json').stdout)
        if cluster.get('status', {}).get('readyInstances') != cluster['spec']['instances'] or not any(c['type'] == 'Ready' and c['status'] == 'True' for c in cluster.get('status', {}).get('conditions', [])):
            raise RuntimeError('PostgreSQL required instances are not all Ready')
    run(['curl', '--fail', '--silent', '--show-error', '--max-time', '10', '--cacert', STATE / 'ca.crt', PUBLIC_ORIGIN + '/.well-known/openid-configuration'])
    print('All current required controllers/pods and broker quorum Ready; verified-certificate discovery succeeded. Historical Jobs preserved; business acceptance remains separate.')


def wait_replacement(selector, before, victim_uid, desired, controller=None):
    before_uids = {p['metadata']['uid'] for p in before}
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        current = json.loads(kube('get', 'pods', '-l', selector, '-o', 'json').stdout)['items']
        current = [p for p in current if not p['metadata'].get('deletionTimestamp') and p['status'].get('phase') not in ('Succeeded', 'Failed') and not any(owner.get('kind') == 'Job' for owner in p['metadata'].get('ownerReferences', []))]
        if controller:
            desired = json.loads(kube('get', controller[0], controller[1], '-o', 'json').stdout)['spec']['replicas']
        uids = {p['metadata']['uid'] for p in current}
        all_ready = all(any(c['type'] == 'Ready' and c['status'] == 'True' for c in p['status'].get('conditions', [])) for p in current)
        if victim_uid not in uids and uids - before_uids and len(current) == desired and all_ready:
            return current
        time.sleep(2)
    raise RuntimeError('Desired replacement replicas did not all become Ready with at least one new UID')


def chaos(target, probe):
    if not probe:
        raise RuntimeError('Chaos requires --probe real business command; infrastructure health is not business recovery')
    command = shlex.split(probe)
    run(command, timeout=180)
    selector = 'cnpg.io/cluster=postgres' if target == 'postgres' else 'app=' + target
    before = json.loads(kube('get', 'pods', '-l', selector, '-o', 'json').stdout)['items']
    before = [p for p in before if not p['metadata'].get('deletionTimestamp') and p['status'].get('phase') == 'Running' and any(c['type'] == 'Ready' and c['status'] == 'True' for c in p['status'].get('conditions', [])) and not any(owner.get('kind') == 'Job' for owner in p['metadata'].get('ownerReferences', []))]
    if not before:
        raise RuntimeError('Fault target does not exist; no chaos success')
    victim = next((p for p in before if p['metadata']['name'] == primary()), before[0]) if target == 'postgres' else before[0]
    uid = victim['metadata']['uid']; name = victim['metadata']['name']
    started = time.time()
    if target == 'postgres':
        desired = json.loads(kube('get', 'cluster.postgresql.cnpg.io', 'postgres', '-o', 'json').stdout)['spec']['instances']
    else:
        kind = 'statefulset' if target == 'redpanda' else 'deployment'
        desired = json.loads(kube('get', kind, target, '-o', 'json').stdout)['spec']['replicas']
    kube('delete', 'pod', name, '--wait=false')
    remaining = wait_replacement(selector, before, uid, desired, None if target == 'postgres' else (kind, target))
    if target != 'postgres':
        desired = json.loads(kube('get', kind, target, '-o', 'json').stdout)['spec']['replicas']
    if target == 'postgres':
        kube('wait', '--for=condition=Ready', 'cluster.postgresql.cnpg.io/postgres', '--timeout=240s')
    broker_report = None
    if target == 'redpanda':
        from broker_health import wait_healthy
        broker_report = wait_healthy(sys.modules[__name__])
    run(command, timeout=180)
    evidence = {'target': target, 'deleted_pod': name, 'deleted_uid': uid, 'before_uids': [p['metadata']['uid'] for p in before], 'after_uids': [p['metadata']['uid'] for p in remaining], 'desired_replicas': desired, 'ready_replicas_after': len(remaining), 'elapsed_seconds': round(time.time() - started, 3), 'business_probe_before_and_after': True, 'outage_expectation': 'HA pod replacement may have no externally visible outage; injection proven by old UID removal and fully Ready new UID', 'scope': 'pod replacement, not host/zone failure'}
    if broker_report is not None:
        evidence['broker_health'] = broker_report
    path = STATE / ('chaos-' + time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '.json')
    path.write_text(json.dumps(evidence, indent=2) + '\n')
    print('Confirmed pod replacement and real business recovery: ' + str(path))


def persistence():
    from fault_lifecycle import wait_writable
    wait_writable(sys.modules[__name__])
    database = 'persistence_' + uuid.uuid4().hex
    token = secrets.token_hex(32)
    started = time.time()
    from private_files import atomic_json
    marker = STATE / ('persistence-active-' + database + '.json')
    atomic_json(marker, {'database': database, 'value_sha256': hashlib.sha256(token.encode()).hexdigest(), 'created_at': started})
    dbsql(f'CREATE DATABASE {database}')
    try:
        dbsql(f"CREATE TABLE durable_probe (value text PRIMARY KEY); INSERT INTO durable_probe VALUES ('{token}')", database)
        victim = primary()
        old_uid = json.loads(kube('get', 'pod', victim, '-o', 'json').stdout)['metadata']['uid']
        before = json.loads(kube('get', 'pods', '-l', 'cnpg.io/cluster=postgres', '-o', 'json').stdout)['items']
        kube('delete', 'pod', victim, '--wait=false')
        kube('wait', '--for=condition=Ready', 'cluster.postgresql.cnpg.io/postgres', '--timeout=300s')
        current = wait_replacement('cnpg.io/cluster=postgres', before, old_uid, 3)
        actual = dbsql('SELECT value FROM durable_probe', database)
        if actual != token:
            raise RuntimeError('PostgreSQL primary replacement lost committed disposable data')
        evidence = {'deleted_primary': victim, 'old_uid': old_uid, 'before_uids': [p['metadata']['uid'] for p in before], 'after_uids': [p['metadata']['uid'] for p in current], 'desired_replicas': 3, 'ready_replicas_after': len(current), 'new_primary': primary(), 'committed_value_preserved': True, 'value_sha256': hashlib.sha256(token.encode()).hexdigest(), 'elapsed_seconds': round(time.time() - started, 3), 'scope': 'same-host pod replacement; not host/zone failure'}
        atomic_json(STATE / 'persistence-verification.json', evidence)
        print('Confirmed committed disposable data survives PostgreSQL primary pod replacement.')
    finally:
        original_error = sys.exc_info()[1]
        try:
            wait_writable(sys.modules[__name__])
            dbsql(f'DROP DATABASE {database}')
            marker.unlink()
        except Exception as cleanup_error:
            if original_error is None:
                raise
            original_error.add_note('Owned disposable DB cleanup deferred until primary recovery: ' + database)


def wait_port_forward(process, local_port, remote_port, timeout=15):
    """Require this process's exact kubectl readiness, never another listener."""
    import select
    expected = f'Forwarding from 127.0.0.1:{local_port} -> {remote_port}'.encode()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError('Owned port forward exited before readiness')
        if select.select([process.stdout], [], [], min(0.2, max(0, deadline - time.monotonic())))[0]:
            line = process.stdout.readline().strip()
            if line == expected:
                return
    raise RuntimeError('Owned port forward readiness deadline exceeded')


def alerts():
    rules = '  - name: acceptance\n    rules:\n      - alert: AcceptanceProbe\n        expr: vector(1)\n        for: 0s\n        labels:\n          severity: test\n'
    import copy
    import helm_release
    configuration = helm_release.current_values(sys.modules[__name__], 'platform-config')
    temporary = copy.deepcopy(configuration)
    temporary['configMaps']['alerts-yml']['alerts.yml'] += '\n' + rules
    process = None
    local_port = 39090 if PROFILE == 'generic' else 29090
    try:
        helm_release.deploy(sys.modules[__name__], 'platform-config', {'chart': 'platform-config', 'values': temporary})
        kube('rollout', 'restart', 'deployment/prometheus')
        kube('rollout', 'status', 'deployment/prometheus', '--timeout=180s')
        process = subprocess.Popen(['kubectl', '--context', CONTEXT, '-n', NS, 'port-forward', '--address=127.0.0.1', 'service/prometheus', f'{local_port}:9090'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        wait_port_forward(process, local_port, 9090)
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError('Owned Prometheus port forward exited; refusing another listener')
            try:
                with urllib.request.urlopen(f'http://127.0.0.1:{local_port}/api/v1/alerts', timeout=3) as response:
                    data = json.load(response)
                if any(a['labels'].get('alertname') == 'AcceptanceProbe' and a['state'] == 'firing' for a in data['data']['alerts']):
                    (STATE / 'alert-verification.json').write_text(json.dumps(data, indent=2) + '\n')
                    print('Prometheus API observed actual AcceptanceProbe firing; evidence saved.')
                    return
            except (OSError, ValueError):
                pass
            time.sleep(2)
        raise RuntimeError('Acceptance alert did not reach firing state')
    finally:
        if process is not None:
            try:
                process.terminate()
                process.wait(timeout=10)
            finally:
                process.stdout.close()
        helm_release.restore_config(sys.modules[__name__], configuration)
        kube('rollout', 'restart', 'deployment/prometheus')
        kube('rollout', 'status', 'deployment/prometheus', '--timeout=180s')


def parse_arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=('default', 'generic'), default='default')
    parser.add_argument('--context', help='Required explicit allowlisted local context for generic mode')
    # Parse only profile flags first: release choices must not depend on a
    # previous invocation's mutable module configuration.
    selector = argparse.ArgumentParser(add_help=False)
    selector.add_argument('--profile', choices=('default', 'generic'), default='default')
    selected, _ = selector.parse_known_args(argv)
    services = [*manifests.DEFAULT_APPS]
    if selected.profile == 'generic':
        services.extend(manifests.GENERIC_APPS)
    services.extend(('frontend', 'gateway'))
    commands = parser.add_subparsers(dest='command', required=True)
    for command in ('secrets', 'build', 'up', 'check', 'status', 'stop', 'start', 'cluster-identity', 'bootstrap-owner', 'backup', 'schedule-backups', 'schema-gate', 'persistence', 'repair-certificates', 'alerts', 'mailpit', 'prometheus', 'grafana', 'tempo', 'gateway', 'gateway-http', 'helm-adopt', 'releases'):
        commands.add_parser(command)

    def backup_path(value):
        if not value.strip():
            raise argparse.ArgumentTypeError('backup directory must not be empty')
        return Path(value)

    def business_probe(value):
        try:
            command = shlex.split(value)
        except ValueError as error:
            raise argparse.ArgumentTypeError(str(error)) from error
        if not command or not command[0]:
            raise argparse.ArgumentTypeError('business probe command must not be empty')
        return value

    restore = commands.add_parser('restore-verify')
    restore.add_argument('--backup', type=backup_path, required=True, help='One complete encrypted backup directory')
    fault = commands.add_parser('chaos')
    fault.add_argument('--target', choices=['postgres', 'redpanda', 'identity-service', 'mailpit'], default='identity-service')
    fault.add_argument('--probe', type=business_probe, required=True, help='Real business command executed without a shell before and after injection')
    rekey = commands.add_parser('rekey')
    rekey.add_argument('--unused', action='store_true', help='Explicitly archive unused bootstrap legacy key; requires no isolated namespace or retained data volumes')
    from release_control import immutable_image
    def image_reference(value):
        try:
            return immutable_image(value)
        except ValueError as error:
            raise argparse.ArgumentTypeError(str(error)) from error
    def release_timeout(value):
        try:
            seconds = int(value)
        except ValueError as error:
            raise argparse.ArgumentTypeError('timeout must be integer seconds') from error
        if not 1 <= seconds <= 3600:
            raise argparse.ArgumentTypeError('timeout must be between 1 and 3600 seconds')
        return seconds
    release = commands.add_parser('release')
    release.add_argument('--service', choices=services, required=True)
    release.add_argument('--image', type=image_reference, required=True)
    release.add_argument('--probe', type=business_probe, required=True)
    release.add_argument('--timeout', type=release_timeout, default=240)
    rollback = commands.add_parser('release-rollback')
    rollback.add_argument('--service', choices=services, required=True)
    rollback.add_argument('--revision', type=release_timeout, required=True)
    rollback.add_argument('--probe', type=business_probe, required=True)
    rollback.add_argument('--timeout', type=release_timeout, default=240)
    return parser.parse_args(argv)


def main():
    args = parse_arguments()
    configure_profile(args.profile, args.context)
    if PROFILE == 'generic' and args.command in ('stop', 'start', 'cluster-identity', 'helm-adopt', 'schedule-backups', 'schema-gate', 'persistence', 'chaos', 'repair-certificates', 'rekey'):
        raise RuntimeError('Generic namespace-only profile forbids cluster/global/legacy maintenance commands')
    if PROFILE == 'generic' and args.command not in ('secrets', 'build', 'up'):
        from cluster_identity import guard
        guard(sys.modules[__name__])
    require_tools()
    if args.command == 'secrets': create_secrets(STATE); print('Local secrets generated or retained; no global trust installation.')
    elif args.command == 'build': build_images()
    elif args.command in ('up', 'helm-adopt', 'release', 'release-rollback'):
        from fault_lifecycle import exclusive
        with exclusive(STATE, timeout=300):
            if args.command == 'up':
                up()
            else:
                import release_control
                if args.command == 'helm-adopt':
                    release_control.adopt(sys.modules[__name__])
                elif args.command == 'release-rollback':
                    release_control.rollback(sys.modules[__name__], args.service, args.revision, args.probe, args.timeout)
                else:
                    release_control.update(sys.modules[__name__], args.service, args.image, args.probe, args.timeout)
    elif args.command == 'releases':
        from release_control import status
        status(sys.modules[__name__])
    elif args.command == 'check': check()
    elif args.command == 'status': run(['kubectl', '--context', CONTEXT, '-n', NS, 'get', 'pods,pvc,svc,hpa,pdb', '-o', 'wide'], capture=False)
    elif args.command == 'stop': run(['k3d', 'cluster', 'stop', CLUSTER])
    elif args.command == 'start': start_cluster()
    elif args.command == 'cluster-identity':
        from cluster_identity import guard
        guard(sys.modules[__name__], initialize=True)
        print('PASS original Kubernetes/etcd peer identity matches static Docker reservations; private baseline retained')
    elif args.command == 'bootstrap-owner': bootstrap_owner()
    elif args.command == 'backup':
        from fault_lifecycle import exclusive
        with exclusive(STATE, timeout=300):
            backup()
    elif args.command == 'restore-verify':
        from fault_lifecycle import exclusive
        with exclusive(STATE):
            wait_writable()
            restore_verify(args.backup)
    elif args.command == 'chaos':
        from fault_lifecycle import exclusive, wait_writable as wait_fault_writable
        with exclusive(STATE):
            try:
                chaos(args.target, args.probe)
            except BaseException:
                if args.target == 'postgres':
                    try:
                        wait_fault_writable(sys.modules[__name__])
                    except Exception as recovery_error:
                        print('PostgreSQL recovery still pending; no further injection allowed until Ready writable primary.', file=sys.stderr)
                raise
    elif args.command == 'alerts':
        from fault_lifecycle import exclusive
        with exclusive(STATE, timeout=300):
            alerts()
    elif args.command == 'persistence':
        from fault_lifecycle import exclusive
        with exclusive(STATE):
            persistence()
    elif args.command == 'repair-certificates':
        import env_secrets
        env_secrets.materialize(STATE)
        from certificate_repair import repair
        repair(sys.modules[__name__])
    elif args.command == 'rekey':
        from fault_lifecycle import exclusive
        from rekey import execute
        with exclusive(STATE, timeout=300):
            execute(sys.modules[__name__], unused=args.unused)
    elif args.command == 'schema-gate':
        from schema_gate import verify
        verify()
    elif args.command == 'schedule-backups':
        from backup_schedule import install
        install()
    else:
        ports = {'mailpit': 38026 if PROFILE == 'generic' else 28026,
                 'prometheus': 39090 if PROFILE == 'generic' else 29090,
                 'grafana': 33000 if PROFILE == 'generic' else 23000,
                 'tempo': 33200 if PROFILE == 'generic' else 23200,
                 'gateway': 18448 if PROFILE == 'generic' else 8448,
                 'gateway-http': 18089 if PROFILE == 'generic' else 8089}
        port_forward(args.command, ports[args.command])


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, ValueError, KeyError) as error:
        print('ERROR: ' + str(error), file=sys.stderr)
        sys.exit(1)
