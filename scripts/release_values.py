"""Read-only Helm values assembly; charts alone define persistent Kubernetes objects."""
import base64
import hashlib
import json
from pathlib import Path

import database_gate
import env_secrets
from manifests import APPS, DBS, database_url
from security_material import SERVICES, broker_cluster_config, broker_config

APPLICATION_RELEASES = (*APPS, 'frontend', 'gateway')
RELEASE_ORDER = ('platform-config', 'postgres', 'redpanda', 'mailpit',
                 'prometheus', 'tempo', 'otel-collector', 'grafana', *APPLICATION_RELEASES)
CONFIG_FILES = ('gateway.conf', 'prometheus.yml', 'alerts.yml', 'otel.yml', 'tempo.yml',
                'grafana-datasources.yml', 'grafana-dashboards.yml', 'platform-dashboard.json')


def configure():
    global DBS, SERVICES, APPLICATION_RELEASES, RELEASE_ORDER
    import manifests
    import security_material
    DBS, SERVICES = manifests.DBS, security_material.SERVICES
    APPLICATION_RELEASES = (*APPS, 'frontend', 'gateway')
    RELEASE_ORDER = ('platform-config', 'postgres', 'redpanda', 'mailpit',
                     'prometheus', 'tempo', 'otel-collector', 'grafana', *APPLICATION_RELEASES)


configure()


def _revision(values):
    return hashlib.sha256(json.dumps(values, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _env(values):
    return [{'name': name, **({'valueFrom': {'secretKeyRef': {'name': value[0], 'key': value[1]}}}
                             if isinstance(value, tuple) else {'value': str(value)})}
            for name, value in values.items()]


def _secret_volume(name, secret, path, *, mode=None):
    source = {'secretName': secret}
    if mode is not None:
        source['defaultMode'] = mode
    return ({'name': name, 'secret': source}, {'name': name, 'mountPath': path, 'readOnly': True})


def prometheus_config(base, namespace):
    """Discover every Ready application pod via owner-scoped headless DNS.

    Fixed per-owner TLS names verify certificates when addresses are pod IPs;
    DNS needs no Kubernetes token, API permissions or discovery egress.
    """
    configuration = json.loads(base)
    jobs = []
    for name, (owner, port, _) in APPS.items():
        jobs.append({'job_name': 'platform/' + name, 'scheme': 'https',
            'tls_config': {'ca_file': '/run/tls/ca.crt', 'server_name': name},
            'dns_sd_configs': [{'names': [f'{name}-metrics.{namespace}.svc.cluster.local'],
                                'type': 'A', 'port': port, 'refresh_interval': '5s'}],
            'relabel_configs': [{'target_label': key, 'replacement': value}
                for key, value in {'job': 'platform', 'app': name, 'service': name,
                                  'owner': 'notification' if owner == 'worker' else owner}.items()]})
    configuration['scrape_configs'] = jobs + configuration['scrape_configs']
    return json.dumps(configuration, indent=2) + '\n'


def _base(name, image, ports, *, uid=10001, ready='/health/ready', tls=True):
    return {'name': name, 'image': image, 'ports': ports, 'uid': uid, 'readinessPath': ready,
            'livePath': '/health/live', 'tls': tls, 'env': [], 'volumes': [], 'mounts': [],
            'command': [], 'args': [], 'replicas': 1, 'autoscaling': False, 'pdb': False,
            'credentialRevision': '', 'configRevision': '', 'databaseGate': False,
            'cpu': '100m', 'memory': '192Mi', 'cpuLimit': '2', 'memoryLimit': '768Mi'}


def release_specs(images, state, root):
    """Return release -> {'chart': basename, 'values': mapping}, without state mutation.

    The caller must supply platform-config.values.apiNetworkPolicy from exact API
    discovery before deployment. Static validation supplies explicit fixture rules.
    """
    state, root = Path(state), Path(root)
    import manifests
    generic = manifests.NS == 'generic-subscriptions'
    origin = 'https://localhost:' + ('18448' if generic else '8448')
    secrets = env_secrets.load(state)
    ca = (state / 'ca.crt').read_bytes()
    material = {'platform-ca': {'ca.crt': ca},
                'redpanda-bootstrap': {'bootstrap_user': 'bootstrap:' + secrets['kafka_bootstrap_password'] + ':SCRAM-SHA-256',
                                      'password': secrets['kafka_bootstrap_password']},
                'identity-signing': {'private.pem': (state / 'signing.pem').read_bytes()},
                'database-superuser': {'username': 'postgres', 'password': secrets['postgres_password']},
                'platform-secrets': secrets,
                'gateway-identity': {'trusted-headers.conf': 'map $proxy_host $gateway_identity_token { default ""; "identity-service:8001" "' + secrets['gateway_token'] + '"; }\nproxy_set_header X-Gateway-Token $gateway_identity_token;\n'}}
    for name in SERVICES:
        directory = state / 'certificates' / name
        material[name + '-tls'] = {'tls.crt': (directory / 'tls.crt').read_bytes(),
                                  'tls.key': (directory / 'tls.key').read_bytes(), 'ca.crt': ca}
    if generic:
        material['postgres-ca'] = {'ca.crt': ca}
    for database in DBS:
        material[database + '-database'] = {
            'DATABASE_URL': database_url(database + '_runtime', secrets[database + '_runtime_password'], database + '_db'),
            'MIGRATION_DATABASE_URL': database_url(database + '_migration', secrets[database + '_migration_password'], database + '_db')}
    encoded = {name: {key: base64.b64encode(value.encode() if isinstance(value, str) else value).decode()
                      for key, value in entries.items()} for name, entries in material.items()}
    configs = {filename.replace('.', '-'): {filename: (root / 'observability' / filename).read_text()}
               for filename in CONFIG_FILES}
    if generic:
        configs['gateway-conf']['gateway.conf'] = configs['gateway-conf']['gateway.conf'].replace(
            'https://localhost:8448', origin)
    else:
        # nginx resolves static proxy upstreams at startup: absent generic owners
        # must not make the original default stand unbootable.
        config = configs['gateway-conf']['gateway.conf']
        configs['gateway-conf']['gateway.conf'] = '\n'.join(
            line for line in config.splitlines()
            if not any(owner in line for owner in manifests.GENERIC_APPS)) + '\n'
    configs['prometheus-yml']['prometheus.yml'] = prometheus_config(
        configs['prometheus-yml']['prometheus.yml'], manifests.NS)
    configs['redpanda-config'] = {**{str(index) + '.json': json.dumps(broker_config(index)) for index in range(3)},
                                 'bootstrap.json': json.dumps(broker_cluster_config())}
    result = {'platform-config': {'chart': 'platform-config', 'values': {
        'name': 'platform-config', 'secrets': encoded, 'configMaps': configs,
        'applications': [{'name': name, 'port': port} for name, (_, port, _) in APPS.items()]}}, 
        'postgres': {'chart': 'platform-postgres', 'values': {'name': 'postgres', 'image': images['postgres'], **({'localAcceptance': True} if generic else {})}},
        'redpanda': {'chart': 'platform-redpanda', 'values': {'name': 'redpanda', 'image': images['redpanda'], **({'localEpoll': True} if generic else {})}},
        'mailpit': {'chart': 'platform-mailpit', 'values': {'name': 'mailpit', 'image': images['mailpit']}}}
    mailpit = _base('mailpit', images['mailpit'], [1025, 8025], ready='/readyz', tls=False)
    mailpit.update(env=_env({'MP_SMTP_BIND_ADDR': '0.0.0.0:1025', 'MP_DATABASE': '/data/mailpit.db'}),
                   persistent=True, storage='1Gi', probePort=8025, livePath='/livez',
                   servicePorts=[{'name': 'p1025', 'port': 1025, 'targetPort': 1025},
                                 {'name': 'p8025', 'port': 8025, 'targetPort': 8025}])
    for key in ('pdb', 'databaseGate'):
        mailpit.pop(key)
    result['mailpit']['values'] = mailpit
    for name, (target, port, database) in APPS.items():
        role = 'notification' if target == 'worker' else target
        env = {'DATABASE_URL': (database + '-database', 'DATABASE_URL'), 'HTTP_PORT': port,
               'PUBLIC_ORIGIN': origin, 'OAUTH_ISSUER': origin,
               'TLS_CERT_FILE': '/run/tls/tls.crt', 'TLS_KEY_FILE': '/run/tls/tls.key', 'INTERNAL_CA_FILE': '/run/tls/ca.crt',
               'KAFKA_BROKERS': ','.join(f'redpanda-{index}.redpanda:29092' for index in range(3)),
               'KAFKA_TLS_CA_FILE': '/run/tls/ca.crt', 'KAFKA_SASL_USERNAME': role,
               'KAFKA_SASL_PASSWORD': ('platform-secrets', 'kafka_' + role + '_password'),
               'OTEL_EXPORTER_OTLP_ENDPOINT': 'http://otel-collector:4318', 'OTEL_SERVICE_NAME': name,
               'IDENTITY_URL': 'https://identity-service:8001', 'PROFILE_URL': 'https://profile-service:8002',
               'NOTIFICATION_URL': 'https://notification-service:8003',
               'INTERNAL_SERVICE_TOKEN': ('platform-secrets', role + '_token'),
               'SMTP_HOST': 'mailpit', 'SMTP_PORT': '1025', 'SMTP_FROM': 'no-reply@sso.local',
               'SMTP_ALLOW_INSECURE': 'true', 'LOG_LEVEL': 'info', 'RUST_LOG': 'info'}
        env['MFA_ENCRYPTION_KEY' if target == 'identity' else 'QUARANTINE_ENCRYPTION_KEY'] = (
            'platform-secrets', 'mfa_encryption_key' if target == 'identity' else role + '_quarantine_key')
        if target in ('identity', 'notification', 'worker'):
            env['DELIVERY_ENCRYPTION_KEY'] = ('platform-secrets', 'delivery_encryption_key')
        if target == 'identity':
            env.update(SIGNING_KEY_FILE='/run/signing/private.pem', SIGNING_KID='local-remediation-v1',
                       PROFILE_INTERNAL_TOKEN=('platform-secrets', 'profile_token'),
                       NOTIFICATION_INTERNAL_TOKEN=('platform-secrets', 'notification_token'),
                       ADMIN_INTERNAL_TOKEN=('platform-secrets', 'admin_token'),
                       GATEWAY_INTERNAL_TOKEN=('platform-secrets', 'gateway_token'))
        if target == 'profile':
            env['NOTIFICATION_INTERNAL_TOKEN'] = ('platform-secrets', 'notification_token')
        if target in ('profile', 'notification'):
            env['ADMIN_INTERNAL_TOKEN'] = ('platform-secrets', 'admin_token')
        if target in ('profile', 'notification', 'worker'):
            env.update(TELEGRAM_BOT_TOKEN=('platform-secrets', 'telegram_bot_token'),
                       TELEGRAM_WEBHOOK_SECRET=('platform-secrets', 'telegram_webhook_secret'))
        if generic:
            env.update(CATALOG_URL='https://catalog-service:8006',
                       BILLING_URL='https://billing-service:8007',
                       SUBSCRIPTION_URL='https://subscription-service:8008',
                       REFERRAL_URL='https://referral-service:8009')
            if target == 'profile' and secrets.get('external_event_integrations'):
                env['EXTERNAL_EVENT_INTEGRATIONS'] = ('platform-secrets', 'external_event_integrations')
            if target == 'identity':
                env['IDENTITY_INTERNAL_TOKEN'] = ('platform-secrets', 'identity_token')
                for owner in ('catalog', 'billing', 'subscription', 'referral'):
                    env[owner.upper() + '_INTERNAL_TOKEN'] = ('platform-secrets', owner + '_token')
            if target == 'catalog':
                material['catalog-readers'] = {'tokens': json.dumps({
                    owner: secrets[owner + '_token'] for owner in ('billing', 'subscription')})}
                encoded['catalog-readers'] = {'tokens': base64.b64encode(material['catalog-readers']['tokens'].encode()).decode()}
                env['CATALOG_READER_TOKENS'] = ('catalog-readers', 'tokens')
            if target == 'subscription':
                env['BILLING_SERVICE_TOKEN'] = ('platform-secrets', 'billing_token')
                material['subscription-readers'] = {'tokens': json.dumps({
                    owner: secrets[owner + '_token'] for owner in ('profile', 'notification')})}
                encoded['subscription-readers'] = {'tokens': base64.b64encode(material['subscription-readers']['tokens'].encode()).decode()}
                env['SUBSCRIPTION_READER_TOKENS'] = ('subscription-readers', 'tokens')
            if target == 'billing':
                env.update(BILLING_SUBSCRIPTION_TOKEN=('platform-secrets', 'subscription_token'),
                           NOWPAYMENTS_BASE_URL='https://api.nowpayments.io/v1',
                           NOWPAYMENTS_NETWORKS='USDTTRC20,USDTBSC', BILLING_ENV='production')
                for key in ('nowpayments_api_key', 'nowpayments_ipn_secret'):
                    if secrets.get(key):
                        env[key.upper()] = ('platform-secrets', key)
            if target == 'referral':
                env.update(REFERRAL_IDENTITY_TOKEN=('platform-secrets', 'identity_token'),
                           REFERRAL_BILLING_TOKEN=('platform-secrets', 'billing_token'),
                           REFERRAL_PROFILE_TOKEN=('platform-secrets', 'profile_token'),
                           REFERRAL_PUBLIC_ORIGIN=origin, REFERRAL_PAYOUT_NETWORKS='bsc,tron')
        values = _base(name, images[target], [port])
        values.update(env=_env(env), replicas=1 if target == 'worker' else 2,
                      autoscaling=target != 'worker', pdb=True, databaseGate=True,
                      metricsDiscovery=True,
                      postgresImage=images['postgres'], databaseGateScript=database_gate.SCRIPT,
                      databaseSecret=database + '-database')
        for volume in [_secret_volume('tls', name + '-tls', '/run/tls', mode=0o440),
                       _secret_volume('postgres-ca', 'postgres-ca', '/run/postgres')]:
            values['volumes'].append(volume[0]); values['mounts'].append(volume[1])
        used = {entry[1] for entry in env.values() if isinstance(entry, tuple) and entry[0] == 'platform-secrets'}
        revision = {key: secrets[key] for key in used}
        revision['database'] = material[database + '-database']['DATABASE_URL']
        revision['tls'] = encoded[name + '-tls']
        if target == 'identity':
            volume, mount = _secret_volume('signing', 'identity-signing', '/run/signing', mode=0o440)
            values['volumes'].append(volume); values['mounts'].append(mount)
            revision['signing'] = encoded['identity-signing']
        values['credentialRevision'] = _revision(revision)
        values['servicePorts'] = [{'name': f'p{port}', 'port': port, 'targetPort': port}]
        result[name] = {'chart': 'platform-service', 'values': values}
    frontend = _base('frontend', images['frontend'], [8080], uid=101, ready='/', tls=False)
    frontend.update(replicas=2, livePath='/', servicePorts=[{'name': 'p80', 'port': 80, 'targetPort': 8080}])
    result['frontend'] = {'chart': 'platform-service', 'values': frontend}
    gateway = _base('gateway', images['gateway'], [8443, 8080], uid=101, ready='/health/live')
    gateway.update(replicas=2, pdb=True, publicService=not generic, command=['nginx', '-g', 'daemon off;'],
                   servicePorts=[{'name': 'p443', 'port': 443, 'targetPort': 8443}, {'name': 'p80', 'port': 80, 'targetPort': 8080}],
                   credentialRevision=_revision({'identity': encoded['gateway-identity'], 'tls': encoded['gateway-tls']}),
                   configRevision=_revision(configs['gateway-conf']))
    if generic:
        gateway['ports'].append(9443)
        gateway['servicePorts'].append({'name': 'integration', 'port': 9443, 'targetPort': 9443})
    for volume, mount in [_secret_volume('tls', 'gateway-tls', '/run/tls', mode=0o440),
                          _secret_volume('trusted-headers', 'gateway-identity', '/run/gateway', mode=0o440)]:
        gateway['volumes'].append(volume); gateway['mounts'].append(mount)
    gateway['volumes'].append({'name': 'config', 'configMap': {'name': 'gateway-conf'}})
    gateway['mounts'].append({'name': 'config', 'mountPath': '/etc/nginx/nginx.conf', 'subPath': 'gateway.conf', 'readOnly': True})
    result['gateway'] = {'chart': 'platform-service', 'values': gateway}
    monitoring = [('prometheus', 9090, ['/bin/prometheus', '--config.file=/etc/platform/prometheus.yml', '--storage.tsdb.path=/data', '--storage.tsdb.retention.time=7d'], [('prometheus.yml', '/etc/platform/prometheus.yml'), ('alerts.yml', '/etc/platform/alerts.yml')], 65534, '/-/ready'),
                  ('tempo', 3200, ['/tempo', '-config.file=/etc/platform/tempo.yml'], [('tempo.yml', '/etc/platform/tempo.yml')], 10001, '/ready'),
                  ('otel-collector', 4318, ['/otelcol-contrib', '--config=/etc/platform/otel.yml'], [('otel.yml', '/etc/platform/otel.yml')], 10001, ''),
                  ('grafana', 3000, [], [('grafana-datasources.yml', '/etc/grafana/provisioning/datasources/platform.yml'), ('grafana-dashboards.yml', '/etc/grafana/provisioning/dashboards/platform.yml'), ('platform-dashboard.json', '/var/lib/grafana/dashboards/platform.json')], 472, '/api/health')]
    for name, port, command, files, uid, ready in monitoring:
        values = _base(name, images[name], [port], uid=uid, ready=ready, tls=False)
        values.update(command=command, livePath=ready, persistent=name != 'otel-collector',
                      configRevision=_revision({file: configs[file.replace('.', '-')] for file, _ in files}),
                      servicePorts=[{'name': f'p{port}', 'port': port, 'targetPort': port}])
        for key in ('pdb', 'databaseGate'):
            values.pop(key)
        for index, (filename, path) in enumerate(files):
            values['volumes'].append({'name': f'config-{index}', 'configMap': {'name': filename.replace('.', '-')}})
            values['mounts'].append({'name': f'config-{index}', 'mountPath': path, 'subPath': filename, 'readOnly': True})
        if name == 'prometheus':
            volume, mount = _secret_volume('tls', 'platform-ca', '/run/tls')
            values['volumes'].append(volume); values['mounts'].append(mount)
        if name == 'grafana':
            values['env'] = _env({'GF_SECURITY_ADMIN_PASSWORD': ('platform-secrets', 'grafana_password'),
                                  'GF_USERS_ALLOW_SIGN_UP': 'false', 'GF_AUTH_ANONYMOUS_ENABLED': 'false', 'GF_SERVER_HTTP_PORT': '3000'})
            values['credentialRevision'] = _revision({'grafana_password': secrets['grafana_password']})
        if name == 'tempo':
            values.update(cpu='500m', memory='1Gi', cpuLimit='4', memoryLimit='4Gi')
            values['servicePorts'].append({'name': 'p4317', 'port': 4317, 'targetPort': 4317})
        result[name] = {'chart': 'platform-monitoring', 'values': values}
    # Token-map Secrets contribute to the owning workload restart revision without
    # leaking their credential values into Deployment annotations.
    for owner, secret_name in (('catalog', 'catalog-readers'), ('subscription', 'subscription-readers')):
        if generic:
            values = result[owner + '-service']['values']
            values['credentialRevision'] = _revision([values['credentialRevision'], encoded[secret_name]])
    return {name: result[name] for name in RELEASE_ORDER}
