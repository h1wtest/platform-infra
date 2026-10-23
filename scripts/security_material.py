"""Per-purpose encryption keys and private TLS identities; existing credentials are never rotated."""
import base64
import os
import secrets

SERVICES = ('identity-service', 'profile-service', 'notification-service', 'notification-worker', 'admin-audit-service', 'gateway', 'redpanda')


def ensure(state, values, run, *, initialize=False):
    if 'encryption_key' in values:
        raise RuntimeError('Legacy shared encryption_key detected: startup refused. Explicit backup and transactional per-owner rekey are required before deleting the legacy key; never auto-generate replacements for existing ciphertext.')
    for key in ('mfa_encryption_key', 'delivery_encryption_key', 'profile_quarantine_key', 'notification_quarantine_key', 'admin_quarantine_key'):
        if key not in values:
            if not initialize:
                raise RuntimeError('Missing existing encryption key: ' + key)
            values[key] = base64.b64encode(secrets.token_bytes(32)).decode()
    for role in ('bootstrap', 'identity', 'profile', 'notification', 'admin'):
        key = 'kafka_' + role + '_password'
        if key not in values:
            if not initialize:
                raise RuntimeError('Missing existing broker password: ' + key)
            values[key] = secrets.token_urlsafe(32)
    mask = os.umask(0o077)
    try:
        for service in SERVICES:
            directory = state / 'certificates' / service
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            if (directory / 'tls.crt').exists():
                if not (directory / 'tls.key').exists():
                    raise RuntimeError('Missing existing private service key: ' + service)
                continue
            if not initialize:
                raise RuntimeError('Missing existing service certificate: ' + service)
            names = [service, service + '.sso-remediation.svc', service + '.sso-remediation.svc.cluster.local']
            if service == 'gateway': names += ['localhost']
            if service == 'redpanda':
                names += ['localhost']
                for ordinal in range(3):
                    names += [f'redpanda-{ordinal}.redpanda', f'redpanda-{ordinal}.redpanda.sso-remediation.svc.cluster.local']
            (directory / 'extensions').write_text('subjectAltName=' + ','.join('DNS:' + name for name in names) + (',IP:127.0.0.1' if service == 'gateway' else '') + '\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\nextendedKeyUsage=serverAuth\n')
            run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072', '-out', directory / 'tls.key'])
            run(['openssl', 'req', '-new', '-key', directory / 'tls.key', '-subj', '/CN=' + service, '-out', directory / 'tls.csr'])
            run(['openssl', 'x509', '-req', '-in', directory / 'tls.csr', '-CA', state / 'ca.crt', '-CAkey', state / 'ca.key', '-CAcreateserial', '-days', '90', '-sha256', '-extfile', directory / 'extensions', '-out', directory / 'tls.crt'])
    finally:
        os.umask(mask)
    return values


def broker_config(index):
    host = f'redpanda-{index}.redpanda.sso-remediation.svc.cluster.local'
    tls = {'enabled': True, 'cert_file': '/run/tls/tls.crt', 'key_file': '/run/tls/tls.key', 'truststore_file': '/run/tls/ca.crt', 'require_client_auth': False}
    # Node-only properties: centralized cluster properties belong in .bootstrap.yaml.
    return {'redpanda': {
        'node_id': index,
        'data_directory': '/var/lib/redpanda/data',
        'developer_mode': False,
        'rpc_server': {'address': '0.0.0.0', 'port': 33145},
        'advertised_rpc_api': {'address': host, 'port': 33145},
        'rpc_server_tls': tls,
        'seed_servers': [{'host': {'address': f'redpanda-{n}.redpanda.sso-remediation.svc.cluster.local', 'port': 33145}} for n in range(3)],
        'kafka_api': [{'name': 'internal', 'address': '0.0.0.0', 'port': 29092, 'authentication_method': 'sasl'}],
        'advertised_kafka_api': [{'name': 'internal', 'address': host, 'port': 29092}],
        'kafka_api_tls': [{'name': 'internal', **tls}],
        'admin': [{'address': '127.0.0.1', 'port': 9645}, {'name': 'metrics', 'address': '0.0.0.0', 'port': 9644}],
    }, 'rpk': {'kafka_api': {'brokers': ['localhost:29092'], 'tls': {'ca_file': '/run/tls/ca.crt'}}}}


def broker_cluster_config():
    # `disabled`, unlike `false`, prevents a topic override from re-enabling write caching.
    # The production default free-space threshold is 5GiB, larger than our 4GiB PVC.
    return {
        'admin_api_require_auth': True,
        'kafka_enable_authorization': True,
        'superusers': ['bootstrap'],
        'default_topic_replications': 3,
        'internal_topic_replication_factor': 3,
        'auto_create_topics_enabled': False,
        'write_caching_default': 'disabled',
        'group_topic_partitions': 3,
        'storage_min_free_bytes': 268435456,
    }
