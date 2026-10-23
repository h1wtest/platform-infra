"""Constants and disposable operational Job helpers; Helm owns persistent resources."""
import base64
from urllib.parse import quote

NS = 'sso-remediation'
APPS = {'identity-service': ('identity', 8001, 'identity'), 'profile-service': ('profile', 8002, 'profile'), 'notification-service': ('notification', 8003, 'notification'), 'notification-worker': ('worker', 8005, 'notification'), 'admin-audit-service': ('admin', 8004, 'audit')}
DBS = ('identity', 'profile', 'notification', 'audit')
GENERIC_APPS = {'catalog-service': ('catalog', 8006, 'catalog'),
                'billing-service': ('billing', 8007, 'billing'),
                'subscription-service': ('subscription', 8008, 'subscription'),
                'referral-service': ('referral', 8009, 'referral')}
DEFAULT_APPS = dict(APPS)
DEFAULT_DBS = DBS


def configure(namespace):
    global NS, DBS
    NS = namespace
    APPS.clear()
    APPS.update(DEFAULT_APPS)
    if namespace == 'generic-subscriptions':
        APPS.update(GENERIC_APPS)
    DBS = DEFAULT_DBS + (('catalog', 'billing', 'subscription', 'referral')
                         if namespace == 'generic-subscriptions' else ())


def database_url(username, password, database):
    """Keep literal credentials inside URI components and require verified TLS."""
    return (f'postgresql://{quote(username, safe="")}:{quote(password, safe="")}'
            f'@postgres-rw.{NS}.svc:5432/{quote(database, safe="")}'
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


