"""Local k3d resources. Stateful controllers retain PVCs; no teardown deletes data."""
import base64
import hashlib
import json
from urllib.parse import quote
import env_secrets

NS = 'sso-remediation'
APPS = {'identity-service': ('identity', 8001, 'identity'), 'profile-service': ('profile', 8002, 'profile'), 'notification-service': ('notification', 8003, 'notification'), 'notification-worker': ('worker', 8005, 'notification'), 'admin-audit-service': ('admin', 8004, 'audit')}
DBS = ('identity', 'profile', 'notification', 'audit')


def database_url(username, password, database):
    """Keep literal credentials inside URI components and require verified TLS."""
    return (f'postgresql://{quote(username, safe="")}:{quote(password, safe="")}'
            f'@postgres-rw.sso-remediation.svc:5432/{quote(database, safe="")}'
            '?sslmode=verify-full&sslrootcert=/run/postgres/ca.crt')


def resource(kind, name, spec=None, **fields):
    api = {'Deployment': 'apps/v1', 'StatefulSet': 'apps/v1', 'Job': 'batch/v1', 'PodDisruptionBudget': 'policy/v1', 'NetworkPolicy': 'networking.k8s.io/v1', 'HorizontalPodAutoscaler': 'autoscaling/v2', 'Cluster': 'postgresql.cnpg.io/v1'}.get(kind, 'v1')
    obj = {'apiVersion': api, 'kind': kind, 'metadata': {'name': name, 'namespace': NS}}
    if spec is not None:
        obj['spec'] = spec
    obj.update(fields)
    return obj


def secret(name, values):
    return resource('Secret', name, type='Opaque', data={key: base64.b64encode(value.encode() if isinstance(value, str) else value).decode() for key, value in values.items()})


def service(name, ports, selector=None, headless=False):
    spec = {'selector': {'app': selector or name}, 'ports': [{'name': f'p{port}', 'port': port, 'targetPort': target} for port, target in ports]}
    if headless:
        spec['clusterIP'] = 'None'
    return resource('Service', name, spec)


def pod(name, image, ports=(), env=None, args=None, volumes=None, mounts=None, uid=10001, cpu='100m', memory='192Mi', ready='/health/ready', tls=True, read_only=True):
    container = {'name': name, 'image': image, 'imagePullPolicy': 'IfNotPresent', 'ports': [{'containerPort': p} for p in ports], 'resources': {'requests': {'cpu': cpu, 'memory': memory}, 'limits': {'cpu': '2', 'memory': '768Mi'}}, 'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': read_only, 'capabilities': {'drop': ['ALL']}}, 'volumeMounts': [{'name': 'tmp', 'mountPath': '/tmp'}] + (mounts or [])}
    if env:
        container['env'] = [{'name': k, **({'valueFrom': {'secretKeyRef': {'name': v[0], 'key': v[1]}}} if isinstance(v, tuple) else {'value': str(v)})} for k, v in env.items()]
    if args:
        container['args'] = args
    if ports and ready:
        container['readinessProbe'] = {'httpGet': {'path': ready, 'port': ports[0], 'scheme': 'HTTPS' if tls else 'HTTP'}, 'periodSeconds': 5, 'timeoutSeconds': 3, 'failureThreshold': 3}
        container['livenessProbe'] = {'httpGet': {'path': '/health/live', 'port': ports[0], 'scheme': 'HTTPS' if tls else 'HTTP'}, 'periodSeconds': 15, 'timeoutSeconds': 3, 'failureThreshold': 4}
        container['startupProbe'] = {'httpGet': {'path': ready, 'port': ports[0], 'scheme': 'HTTPS' if tls else 'HTTP'}, 'periodSeconds': 5, 'failureThreshold': 60}
    return {'serviceAccountName': name, 'automountServiceAccountToken': False, 'terminationGracePeriodSeconds': 40, 'securityContext': {'runAsNonRoot': True, 'runAsUser': uid, 'runAsGroup': uid, 'fsGroup': uid, 'seccompProfile': {'type': 'RuntimeDefault'}}, 'containers': [container], 'volumes': [{'name': 'tmp', 'emptyDir': {'sizeLimit': '128Mi'}}] + (volumes or []), 'topologySpreadConstraints': [{'maxSkew': 1, 'topologyKey': 'kubernetes.io/hostname', 'whenUnsatisfiable': 'ScheduleAnyway', 'labelSelector': {'matchLabels': {'app': name}}}]}


def deployment(name, spec, replicas=1):
    return resource('Deployment', name, {'replicas': replicas, 'selector': {'matchLabels': {'app': name}}, 'strategy': {'type': 'RollingUpdate', 'rollingUpdate': {'maxSurge': 1, 'maxUnavailable': 0}}, 'template': {'metadata': {'labels': {'app': name}}, 'spec': spec}})


def infrastructure(images, state, config_dir):
    s = env_secrets.load(state)
    yield {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': NS, 'labels': {'pod-security.kubernetes.io/enforce': 'restricted', 'pod-security.kubernetes.io/enforce-version': 'v1.33'}}}
    from security_material import SERVICES, broker_cluster_config, broker_config
    for service_name in SERVICES:
        directory = state / 'certificates' / service_name
        yield secret(service_name + '-tls', {'tls.crt': (directory / 'tls.crt').read_bytes(), 'tls.key': (directory / 'tls.key').read_bytes(), 'ca.crt': (state / 'ca.crt').read_bytes()})
    yield secret('platform-ca', {'ca.crt': (state / 'ca.crt').read_bytes()})
    yield secret('redpanda-bootstrap', {'bootstrap_user': 'bootstrap:' + s['kafka_bootstrap_password'] + ':SCRAM-SHA-256', 'password': s['kafka_bootstrap_password']})
    yield resource('ConfigMap', 'redpanda-config', data={**{str(i) + '.json': json.dumps(broker_config(i)) for i in range(3)}, 'bootstrap.json': json.dumps(broker_cluster_config())})
    yield secret('identity-signing', {'private.pem': (state / 'signing.pem').read_bytes()})
    yield secret('database-superuser', {'username': 'postgres', 'password': s['postgres_password']})
    yield secret('platform-secrets', s)
    yield secret('gateway-identity', {'trusted-headers.conf': 'map $proxy_host $gateway_identity_token { default ""; "identity-service:8001" "' + s['gateway_token'] + '"; }\nproxy_set_header X-Gateway-Token $gateway_identity_token;\n'})
    for db in DBS:
        yield secret(f'{db}-database', {
            'DATABASE_URL': database_url(db + '_runtime', s[db + '_runtime_password'], db + '_db'),
            'MIGRATION_DATABASE_URL': database_url(db + '_migration', s[db + '_migration_password'], db + '_db'),
        })
    # CNPG performs synchronous streaming replication, fencing and automatic primary failover.
    yield resource('Cluster', 'postgres', {'instances': 3, 'imageName': images['postgres'], 'smartShutdownTimeout': 30, 'stopDelay': 60, 'enableSuperuserAccess': True, 'superuserSecret': {'name': 'database-superuser'}, 'storage': {'size': '4Gi', 'storageClass': 'local-path'}, 'walStorage': {'size': '2Gi', 'storageClass': 'local-path'}, 'postgresql': {'parameters': {'max_connections': '200', 'synchronous_commit': 'on'}, 'synchronous': {'method': 'any', 'number': 1, 'dataDurability': 'required'}}, 'affinity': {'enablePodAntiAffinity': True, 'topologyKey': 'kubernetes.io/hostname', 'podAntiAffinityType': 'preferred'}, 'resources': {'requests': {'cpu': '200m', 'memory': '256Mi'}, 'limits': {'cpu': '2', 'memory': '1Gi'}}, 'monitoring': {'enablePodMonitor': False}, 'bootstrap': {'initdb': {'database': 'platform', 'owner': 'platform_owner'}}})
    names = ['redpanda', 'mailpit', 'gateway', 'frontend', 'prometheus', 'grafana', 'tempo', 'otel-collector', *APPS]
    for name in names:
        yield resource('ServiceAccount', name, automountServiceAccountToken=False)
    # Three replicated Kafka brokers, replication factor three, six bounded consumer partitions.
    rp = pod('redpanda', images['redpanda'], (29092, 9644, 33145), mounts=[{'name': 'data', 'mountPath': '/var/lib/redpanda/data'}], uid=101, cpu='200m', memory='512Mi', ready=None)
    rp['containers'][0]['env'] = [{'name': 'POD_NAME', 'valueFrom': {'fieldRef': {'fieldPath': 'metadata.name'}}}, {'name': 'POD_INDEX', 'valueFrom': {'fieldRef': {'fieldPath': "metadata.labels['apps.kubernetes.io/pod-index']"}}}]
    rp['volumes'] += [{'name': 'tls', 'secret': {'secretName': 'redpanda-tls', 'defaultMode': 0o440}}, {'name': 'broker-config', 'configMap': {'name': 'redpanda-config'}}]
    rp['containers'][0]['volumeMounts'] += [{'name': 'tls', 'mountPath': '/run/tls', 'readOnly': True}, {'name': 'broker-config', 'mountPath': '/run/broker-config', 'readOnly': True}]
    rp['containers'][0]['env'] += [{'name': 'RP_BOOTSTRAP_USER', 'valueFrom': {'secretKeyRef': {'name': 'redpanda-bootstrap', 'key': 'bootstrap_user'}}}, {'name': 'RPK_USER', 'value': 'bootstrap'}, {'name': 'RPK_PASS', 'valueFrom': {'secretKeyRef': {'name': 'redpanda-bootstrap', 'key': 'password'}}}, {'name': 'RPK_SASL_MECHANISM', 'value': 'SCRAM-SHA-256'}, {'name': 'RPK_TLS_ENABLED', 'value': 'true'}, {'name': 'RPK_TLS_CA', 'value': '/run/tls/ca.crt'}, {'name': 'RPK_ADMIN_HOSTS', 'value': '127.0.0.1:9645'}]
    rp['containers'][0]['command'] = ['/bin/sh', '-ec']
    # Overprovisioning changes CPU scheduling only; production broker checks and real fsync remain enabled.
    # rpk start has no production --mode: developer_mode=false avoids its implicit dev-container preset.
    rp['containers'][0]['args'] = ['cp /run/broker-config/"$POD_INDEX".json /tmp/redpanda.yaml; cp /run/broker-config/bootstrap.json /tmp/.bootstrap.yaml; exec /usr/bin/rpk redpanda start --config=/tmp/redpanda.yaml --smp=1 --memory=512M --reserve-memory=0M --overprovisioned --unsafe-bypass-fsync=false --check=false']
    rp['containers'][0]['readinessProbe'] = {'tcpSocket': {'port': 29092}, 'initialDelaySeconds': 5, 'periodSeconds': 5}
    rp['containers'][0]['livenessProbe'] = {'tcpSocket': {'port': 29092}, 'periodSeconds': 15}
    rp['containers'][0]['resources']['limits']['memory'] = '1Gi'
    yield resource('StatefulSet', 'redpanda', {'serviceName': 'redpanda', 'replicas': 3, 'podManagementPolicy': 'Parallel', 'persistentVolumeClaimRetentionPolicy': {'whenDeleted': 'Retain', 'whenScaled': 'Retain'}, 'selector': {'matchLabels': {'app': 'redpanda'}}, 'template': {'metadata': {'labels': {'app': 'redpanda'}}, 'spec': rp}, 'volumeClaimTemplates': [{'metadata': {'name': 'data'}, 'spec': {'accessModes': ['ReadWriteOnce'], 'storageClassName': 'local-path', 'resources': {'requests': {'storage': '4Gi'}}}}]})
    broker_service = service('redpanda', [(29092, 29092), (9644, 9644), (33145, 33145)], headless=True)
    broker_service['spec']['publishNotReadyAddresses'] = True
    yield broker_service
    mp = pod('mailpit', images['mailpit'], (1025, 8025), env={'MP_SMTP_BIND_ADDR': '0.0.0.0:1025', 'MP_DATABASE': '/data/mailpit.db'}, uid=10001, ready='/readyz', tls=False, volumes=[{'name': 'data', 'persistentVolumeClaim': {'claimName': 'mailpit'}}], mounts=[{'name': 'data', 'mountPath': '/data'}])
    mp['containers'][0]['readinessProbe']['httpGet']['port'] = 8025
    mp['containers'][0]['livenessProbe']['httpGet'] = {'path': '/livez', 'port': 8025}
    mp['containers'][0]['startupProbe']['httpGet']['port'] = 8025
    yield resource('PersistentVolumeClaim', 'mailpit', {'accessModes': ['ReadWriteOnce'], 'resources': {'requests': {'storage': '1Gi'}}})
    mp_deploy = deployment('mailpit', mp); mp_deploy['spec']['strategy'] = {'type': 'Recreate'}
    yield mp_deploy
    yield service('mailpit', [(1025, 1025), (8025, 8025)])
    for name, minimum in [('redpanda', 2), *[(n, 1) for n in APPS], ('gateway', 1)]:
        yield resource('PodDisruptionBudget', name, {'minAvailable': minimum, 'selector': {'matchLabels': {'app': name}}})
    for filename in ('gateway.conf', 'prometheus.yml', 'alerts.yml', 'otel.yml', 'tempo.yml', 'grafana-datasources.yml', 'grafana-dashboards.yml', 'platform-dashboard.json'):
        yield resource('ConfigMap', filename.replace('.', '-'), data={filename: (config_dir / filename).read_text()})
    yield from network_policies()


def credential_revision(state):
    """Restart credential consumers on owner env edits without exposing values."""
    values = env_secrets.load(state)
    return hashlib.sha256(json.dumps(values, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def credential_deployment(name, spec, revision, replicas=1):
    result = deployment(name, spec, replicas)
    result['spec']['template']['metadata']['annotations'] = {'sso.local/credential-revision': revision}
    return result


def applications(images, state):
    revision = credential_revision(state)
    for name, (target, port, db) in APPS.items():
        role = 'notification' if target == 'worker' else target
        env = {'DATABASE_URL': (f'{db}-database', 'DATABASE_URL'), 'HTTP_PORT': port, 'PUBLIC_ORIGIN': 'https://localhost:8448', 'OAUTH_ISSUER': 'https://localhost:8448', 'TLS_CERT_FILE': '/run/tls/tls.crt', 'TLS_KEY_FILE': '/run/tls/tls.key', 'INTERNAL_CA_FILE': '/run/tls/ca.crt', 'KAFKA_BROKERS': ','.join(f'redpanda-{i}.redpanda:29092' for i in range(3)), 'KAFKA_TLS_CA_FILE': '/run/tls/ca.crt', 'KAFKA_SASL_USERNAME': role, 'KAFKA_SASL_PASSWORD': ('platform-secrets', 'kafka_' + role + '_password'), 'OTEL_EXPORTER_OTLP_ENDPOINT': 'http://otel-collector:4318', 'OTEL_SERVICE_NAME': name, 'IDENTITY_URL': 'https://identity-service:8001', 'PROFILE_URL': 'https://profile-service:8002', 'NOTIFICATION_URL': 'https://notification-service:8003', 'INTERNAL_SERVICE_TOKEN': ('platform-secrets', role + '_token'), 'SMTP_HOST': 'mailpit', 'SMTP_PORT': '1025', 'SMTP_FROM': 'no-reply@sso.local', 'SMTP_ALLOW_INSECURE': 'true', 'LOG_LEVEL': 'info', 'RUST_LOG': 'info'}
        if target == 'identity':
            env['MFA_ENCRYPTION_KEY'] = ('platform-secrets', 'mfa_encryption_key')
        else:
            env['QUARANTINE_ENCRYPTION_KEY'] = ('platform-secrets', role + '_quarantine_key')
        if target in ('identity', 'notification', 'worker'):
            env['DELIVERY_ENCRYPTION_KEY'] = ('platform-secrets', 'delivery_encryption_key')
        if target == 'identity':
            env.update({'SIGNING_KEY_FILE': '/run/signing/private.pem', 'SIGNING_KID': 'local-remediation-v1', 'PROFILE_INTERNAL_TOKEN': ('platform-secrets', 'profile_token'), 'NOTIFICATION_INTERNAL_TOKEN': ('platform-secrets', 'notification_token'), 'ADMIN_INTERNAL_TOKEN': ('platform-secrets', 'admin_token')})
            env['GATEWAY_INTERNAL_TOKEN'] = ('platform-secrets', 'gateway_token')
        if target == 'profile':
            env['NOTIFICATION_INTERNAL_TOKEN'] = ('platform-secrets', 'notification_token')
        if target in ('profile', 'notification'):
            env['ADMIN_INTERNAL_TOKEN'] = ('platform-secrets', 'admin_token')
        if target in ('profile', 'notification', 'worker'):
            env.update({'TELEGRAM_BOT_TOKEN': ('platform-secrets', 'telegram_bot_token'), 'TELEGRAM_WEBHOOK_SECRET': ('platform-secrets', 'telegram_webhook_secret')})
        volumes = [{'name': 'tls', 'secret': {'secretName': name + '-tls', 'defaultMode': 0o440}}]
        mounts = [{'name': 'tls', 'mountPath': '/run/tls', 'readOnly': True}]
        volumes.append({'name': 'postgres-ca', 'secret': {'secretName': 'postgres-ca'}})
        mounts.append({'name': 'postgres-ca', 'mountPath': '/run/postgres', 'readOnly': True})
        if target == 'identity':
            volumes.append({'name': 'signing', 'secret': {'secretName': 'identity-signing', 'defaultMode': 0o440}})
            mounts.append({'name': 'signing', 'mountPath': '/run/signing', 'readOnly': True})
        application = pod(name, images[target], (port,), env, volumes=volumes, mounts=mounts)
        from database_gate import attach
        attach(application, images)
        yield credential_deployment(name, application, revision, replicas=2 if target != 'worker' else 1)
        yield service(name, [(port, port)])
        if target in ('identity', 'profile', 'notification', 'admin'):
            yield resource('HorizontalPodAutoscaler', name, {'scaleTargetRef': {'apiVersion': 'apps/v1', 'kind': 'Deployment', 'name': name}, 'minReplicas': 2, 'maxReplicas': 4, 'metrics': [{'type': 'Resource', 'resource': {'name': 'cpu', 'target': {'type': 'Utilization', 'averageUtilization': 70}}}], 'behavior': {'scaleDown': {'stabilizationWindowSeconds': 120}}})
    frontend = pod('frontend', images['frontend'], (8080,), uid=101, ready='/', tls=False)
    frontend['containers'][0]['livenessProbe']['httpGet']['path'] = '/'
    yield deployment('frontend', frontend, 2)
    yield service('frontend', [(80, 8080)])
    gateway = pod('gateway', images['gateway'], (8443, 8080), uid=101, ready='/health/live', tls=True, volumes=[{'name': 'tls', 'secret': {'secretName': 'gateway-tls', 'defaultMode': 0o440}}, {'name': 'config', 'configMap': {'name': 'gateway-conf'}}], mounts=[{'name': 'tls', 'mountPath': '/run/tls', 'readOnly': True}, {'name': 'config', 'mountPath': '/etc/nginx/nginx.conf', 'subPath': 'gateway.conf', 'readOnly': True}])
    gateway['volumes'].append({'name': 'trusted-headers', 'secret': {'secretName': 'gateway-identity', 'defaultMode': 0o440}})
    gateway['containers'][0]['volumeMounts'].append({'name': 'trusted-headers', 'mountPath': '/run/gateway', 'readOnly': True})
    gateway['containers'][0]['command'] = ['nginx', '-g', 'daemon off;']
    yield credential_deployment('gateway', gateway, revision, 2)
    yield service('gateway', [(443, 8443), (80, 8080)])


def network_policies():
    yield resource('NetworkPolicy', 'default-deny', {'podSelector': {}, 'policyTypes': ['Ingress', 'Egress']})
    # Namespace selectors prevent an arbitrary namespace from impersonating service labels.
    local = {'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': NS}}}
    def peers(names):
        return [{**local, 'podSelector': {'matchLabels': {'app': n}}} for n in names]
    def allow(name, ingress=None, egress=None, selector=None):
        spec = {'podSelector': selector or {'matchLabels': {'app': name}}, 'policyTypes': []}
        for key, value in [('ingress', ingress), ('egress', egress)]:
            if value is not None:
                spec['policyTypes'].append(key.title()); spec[key] = value
        return resource('NetworkPolicy', 'allow-' + name, spec)
    yield allow('dns', egress=[{'to': [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'kube-system'}}, 'podSelector': {'matchLabels': {'k8s-app': 'kube-dns'}}}], 'ports': [{'protocol': 'UDP', 'port': 53}, {'protocol': 'TCP', 'port': 53}]}], selector={'matchLabels': {}})
    for name, (_, port, _) in APPS.items():
        sources = ['gateway', 'prometheus', *APPS]
        destinations = ['redpanda', 'otel-collector', 'identity-service', 'profile-service', 'notification-service', 'mailpit']
        egress = [{'to': peers(destinations), 'ports': [{'protocol': 'TCP', 'port': p} for p in (29092, 4318, 8001, 8002, 8003, 1025)]}, {'to': [{**local, 'podSelector': {'matchLabels': {'cnpg.io/cluster': 'postgres'}}}], 'ports': [{'port': 5432}]}]
        if name in ('profile-service', 'notification-worker'):
            egress.append({'to': [{'ipBlock': {'cidr': '0.0.0.0/0', 'except': ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']}}], 'ports': [{'port': 443}]})
        yield allow(name, [{'from': peers(sources), 'ports': [{'port': port}]}], egress)
    database_peers = peers(list(APPS)) + [{**local, 'podSelector': {'matchLabels': {'cnpg.io/cluster': 'postgres'}}}, {'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'cnpg-system'}}}]
    yield allow('postgres', ingress=[{'from': database_peers, 'ports': [{'port': p} for p in (5432, 8000, 9187)]}], egress=[{'to': [{**local, 'podSelector': {'matchLabels': {'cnpg.io/cluster': 'postgres'}}}], 'ports': [{'port': 5432}]}], selector={'matchLabels': {'cnpg.io/cluster': 'postgres'}})
    yield allow('redpanda', [{'from': peers(['identity-service', 'profile-service', 'notification-service', 'admin-audit-service', 'redpanda']), 'ports': [{'port': 29092}]}, {'from': peers(['redpanda']), 'ports': [{'port': 33145}]}, {'from': peers(['prometheus']), 'ports': [{'port': 9644}]}], [{'to': peers(['redpanda']), 'ports': [{'port': 33145}]}])
    yield allow('mailpit', [{'from': peers(['notification-worker']), 'ports': [{'port': 1025}]}], [])
    yield allow('frontend', [{'from': peers(['gateway']), 'ports': [{'port': 8080}]}], [])
    yield allow('gateway', [{'from': [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'kube-system'}}}, {'ipBlock': {'cidr': '0.0.0.0/0'}}], 'ports': [{'port': p} for p in (8443, 8080)]}], [{'to': peers(list(APPS)), 'ports': [{'port': p} for p in (8001, 8002, 8003, 8004)]}, {'to': peers(['frontend']), 'ports': [{'port': 8080}]}])
    for name in ('prometheus', 'grafana', 'tempo', 'otel-collector'):
        yield allow(name, [{'from': [{**local, 'podSelector': {}}]}], [{'to': [{**local, 'podSelector': {}}]}])


def monitoring(images, state):
    revision = credential_revision(state)
    specs = [('prometheus', 9090, ['/bin/prometheus', '--config.file=/etc/platform/prometheus.yml', '--storage.tsdb.path=/data', '--storage.tsdb.retention.time=7d'], [('prometheus.yml', '/etc/platform/prometheus.yml'), ('alerts.yml', '/etc/platform/alerts.yml')], 65534, '/-/ready'), ('tempo', 3200, ['/tempo', '-config.file=/etc/platform/tempo.yml'], [('tempo.yml', '/etc/platform/tempo.yml')], 10001, '/ready'), ('otel-collector', 4318, ['/otelcol-contrib', '--config=/etc/platform/otel.yml'], [('otel.yml', '/etc/platform/otel.yml')], 10001, None), ('grafana', 3000, None, [('grafana-datasources.yml', '/etc/grafana/provisioning/datasources/platform.yml'), ('grafana-dashboards.yml', '/etc/grafana/provisioning/dashboards/platform.yml'), ('platform-dashboard.json', '/var/lib/grafana/dashboards/platform.json')], 472, '/api/health')]
    for name, port, command, configs, uid, ready in specs:
        volumes = [{'name': f'config-{i}', 'configMap': {'name': file.replace('.', '-')}} for i, (file, _) in enumerate(configs)]
        mounts = [{'name': f'config-{i}', 'mountPath': path, 'subPath': file, 'readOnly': True} for i, (file, path) in enumerate(configs)]
        if name == 'prometheus':
            volumes.append({'name': 'tls', 'secret': {'secretName': 'platform-ca'}})
            mounts.append({'name': 'tls', 'mountPath': '/run/tls', 'readOnly': True})
        env = {}
        if name != 'otel-collector':
            yield resource('PersistentVolumeClaim', name, {'accessModes': ['ReadWriteOnce'], 'resources': {'requests': {'storage': '2Gi'}}})
            volumes.append({'name': 'data', 'persistentVolumeClaim': {'claimName': name}})
            mounts.append({'name': 'data', 'mountPath': '/var/lib/grafana' if name == 'grafana' else '/data'})
        if name == 'grafana':
            env = {'GF_SECURITY_ADMIN_PASSWORD': ('platform-secrets', 'grafana_password'), 'GF_USERS_ALLOW_SIGN_UP': 'false', 'GF_AUTH_ANONYMOUS_ENABLED': 'false', 'GF_SERVER_HTTP_PORT': '3000'}
        obj = pod(name, images[name], (port,), env=env, uid=uid, ready=ready, tls=False, volumes=volumes, mounts=mounts)
        if name == 'otel-collector':
            obj['containers'][0]['readinessProbe'] = {'httpGet': {'path': '/', 'port': 13133}, 'periodSeconds': 5}
            obj['containers'][0]['livenessProbe'] = {'httpGet': {'path': '/', 'port': 13133}, 'periodSeconds': 15}
        if name == 'tempo':
            obj['containers'][0]['volumeMounts'].append({'name': 'data', 'mountPath': '/var/tempo'})
            obj['containers'][0]['resources'] = {'requests': {'cpu': '500m', 'memory': '1Gi'}, 'limits': {'cpu': '4', 'memory': '4Gi'}}
        if command:
            obj['containers'][0]['command'] = command
        if ready:
            obj['containers'][0]['livenessProbe']['httpGet']['path'] = ready
        deploy = credential_deployment(name, obj, revision); deploy['spec']['strategy'] = {'type': 'Recreate'}
        yield deploy
        ports = [(port, port)] + ([(4317, 4317)] if name == 'tempo' else [])
        yield service(name, ports)
