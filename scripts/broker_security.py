"""Leader-aware admin mutations stay on explicit loopback port forwards; redirects never carry secrets."""
import base64
import json
import subprocess
import time
import urllib.error
import urllib.request


def topic_inventory(generic=False):
    legacy = [('identity.events.v1', '604800000'), ('notification.commands.v1', '86400000'),
              ('platform.dlq.v1', '604800000')]
    return legacy + [(topic, '86400000' if topic == 'notification.commands.v2' else '604800000')
                     for topic in ('identity.events.v2', 'profile.events.v2', 'catalog.events.v1',
                                   'billing.events.v1', 'subscription.events.v1', 'referral.events.v1',
                                   'external.events.v1', 'notification.commands.v2',
                                   'notification.events.v2', 'platform.dlq.v2')]


def owner_acls():
    """Explicit v2/live and legacy drain readers; no wildcard topic/group grants."""
    producers = {
        'identity': ('identity.events.v2', 'notification.commands.v2'),
        'profile': ('profile.events.v2', 'external.events.v1'),
        'notification': ('notification.events.v2',), 'admin': (),
        'catalog': ('catalog.events.v1',), 'billing': ('billing.events.v1',),
        'subscription': ('subscription.events.v1',), 'referral': ('referral.events.v1',)}
    readers = {
        'profile': ('profile-v1', ('identity.events.v1', 'identity.events.v2')),
        'notification': ('notification-v1', ('identity.events.v1', 'notification.commands.v1',
                          'identity.events.v2', 'notification.commands.v2', 'billing.events.v1',
                          'subscription.events.v1', 'referral.events.v1', 'external.events.v1')),
        'admin': ('audit-v1', ('identity.events.v1', 'identity.events.v2', 'profile.events.v2',
                  'catalog.events.v1', 'billing.events.v1', 'subscription.events.v1',
                  'referral.events.v1', 'notification.events.v2', 'external.events.v1')),
        'billing': ('billing-fulfillment-v1', ('subscription.events.v1',)),
        'subscription': ('subscription-service-v2', ('billing.events.v1',)),
        'referral': ('referral-v2', ('identity.events.v2', 'billing.events.v1'))}
    rules = []
    for role, topics in producers.items():
        for topic in (*topics, 'platform.dlq.v2'):
            rules.append((role, 'write,describe', 'topic', topic))
    for role, (group, topics) in readers.items():
        rules.append((role, 'read,describe', 'group', group))
        rules.extend((role, 'read,describe', 'topic', topic) for topic in topics)
    for role in ('profile', 'notification', 'admin'):
        rules.append((role, 'write,describe', 'topic', 'platform.dlq.v1'))
    return rules


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def provision(runtime, values):
    processes = []
    generic = runtime.NS == 'generic-subscriptions'
    base_port = 39645 if generic else 29645
    opener = urllib.request.build_opener(NoRedirect())
    credential = base64.b64encode(('bootstrap:' + values['kafka_bootstrap_password']).encode()).decode()
    try:
        # The admin listener is loopback-only on every broker. Only these three owned pods can receive auth.
        for index in range(3):
            processes.append(subprocess.Popen(['kubectl', '--context', runtime.CONTEXT, '-n', runtime.NS, 'port-forward', '--address=127.0.0.1', 'pod/redpanda-' + str(index), str(base_port + index) + ':9645'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        def request(index, path, method='GET', payload=None):
            if index not in (0, 1, 2):
                raise RuntimeError('Controller leader is outside declared broker pod identities')
            headers = {'Authorization': 'Basic ' + credential}
            if payload is not None:
                headers['Content-Type'] = 'application/json'
            req = urllib.request.Request('http://127.0.0.1:' + str(base_port + index) + path, data=json.dumps(payload).encode() if payload is not None else None, headers=headers, method=method)
            with opener.open(req, timeout=5) as response:
                body = response.read()
                return json.loads(body) if body else None
        def leader():
            state = request(0, '/v1/partitions/redpanda/controller/0')
            node_id = state.get('leader_id')
            if type(node_id) is not int or node_id not in (0, 1, 2):
                raise RuntimeError('Controller leader is not an expected Redpanda node id')
            # Independently verify the selected pod has the advertised node identity.
            config = request(node_id, '/v1/node_config')
            if config.get('node_id') != node_id:
                raise RuntimeError('Controller node id differs from selected broker pod')
            return node_id
        deadline = time.monotonic() + 60
        while True:
            try:
                current_leader = leader()
                existing = request(current_leader, '/v1/security/users')
                break
            except (OSError, ValueError):
                if time.monotonic() >= deadline:
                    raise RuntimeError('Broker controller admin bootstrap unavailable')
                time.sleep(1)
        roles = ('identity', 'profile', 'notification', 'admin') + (('catalog', 'billing', 'subscription', 'referral') if generic else ())
        for role in roles:
            payload = {'username': role, 'password': values['kafka_' + role + '_password'], 'algorithm': 'SCRAM-SHA-256'}
            current_leader = leader()
            # A leadership change between lookup and mutation fails closed (307), never follows Location.
            request(current_leader, '/v1/security/users/' + role if role in existing else '/v1/security/users', 'PUT' if role in existing else 'POST', payload)
        # Kafka idempotent producers need this cluster operation; exact topic
        # WRITE grants below remain the owner authorization boundary.
        for role in roles:
            runtime.kube('exec', 'redpanda-0', '--', 'rpk', '-X', 'brokers=localhost:29092',
                         'security', 'acl', 'create', '--allow-principal', role,
                         '--operation', 'idempotent-write', '--cluster')
        def acl(role, operations, resource, name):
            runtime.kube('exec', 'redpanda-0', '--', 'rpk', '-X', 'brokers=localhost:29092', 'security', 'acl', 'create', '--allow-principal', role, '--operation', operations, '--' + resource, name)
        if generic:
            for rule in owner_acls():
                acl(*rule)
            return
        for topic in ('identity.events.v1', 'notification.commands.v1'):
            acl('identity', 'write,describe', 'topic', topic)
        for role, group in (('profile', 'profile-v1'), ('notification', 'notification-v1'), ('admin', 'audit-v1')):
            acl(role, 'read,describe', 'topic', 'identity.events.v1')
            acl(role, 'read,describe', 'group', group)
            acl(role, 'write,describe', 'topic', 'platform.dlq.v1')
        acl('notification', 'read,describe', 'topic', 'notification.commands.v1')
        for rule in owner_acls():
            if rule[0] in ('identity', 'profile', 'notification', 'admin'):
                acl(*rule)
    finally:
        for process in processes:
            process.terminate()
        for process in processes:
            process.wait(timeout=10)
