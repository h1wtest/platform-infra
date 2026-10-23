"""Leader-aware admin mutations stay on explicit loopback port forwards; redirects never carry secrets."""
import base64
import json
import subprocess
import time
import urllib.error
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def provision(runtime, values):
    processes = []
    opener = urllib.request.build_opener(NoRedirect())
    credential = base64.b64encode(('bootstrap:' + values['kafka_bootstrap_password']).encode()).decode()
    try:
        # The admin listener is loopback-only on every broker. Only these three owned pods can receive auth.
        for index in range(3):
            processes.append(subprocess.Popen(['kubectl', '--context', runtime.CONTEXT, '-n', runtime.NS, 'port-forward', '--address=127.0.0.1', 'pod/redpanda-' + str(index), str(29645 + index) + ':9645'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        def request(index, path, method='GET', payload=None):
            if index not in (0, 1, 2):
                raise RuntimeError('Controller leader is outside declared broker pod identities')
            headers = {'Authorization': 'Basic ' + credential}
            if payload is not None:
                headers['Content-Type'] = 'application/json'
            req = urllib.request.Request('http://127.0.0.1:' + str(29645 + index) + path, data=json.dumps(payload).encode() if payload is not None else None, headers=headers, method=method)
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
        for role in ('identity', 'profile', 'notification', 'admin'):
            payload = {'username': role, 'password': values['kafka_' + role + '_password'], 'algorithm': 'SCRAM-SHA-256'}
            current_leader = leader()
            # A leadership change between lookup and mutation fails closed (307), never follows Location.
            request(current_leader, '/v1/security/users/' + role if role in existing else '/v1/security/users', 'PUT' if role in existing else 'POST', payload)
        def acl(role, operations, resource, name):
            runtime.kube('exec', 'redpanda-0', '--', 'rpk', '-X', 'brokers=localhost:29092', 'security', 'acl', 'create', '--allow-principal', role, '--operation', operations, '--' + resource, name)
        for topic in ('identity.events.v1', 'notification.commands.v1'):
            acl('identity', 'write,describe', 'topic', topic)
        for role, group in (('profile', 'profile-v1'), ('notification', 'notification-v1'), ('admin', 'audit-v1')):
            acl(role, 'read,describe', 'topic', 'identity.events.v1')
            acl(role, 'read,describe', 'group', group)
            acl(role, 'write,describe', 'topic', 'platform.dlq.v1')
        acl('notification', 'read,describe', 'topic', 'notification.commands.v1')
    finally:
        for process in processes:
            process.terminate()
        for process in processes:
            process.wait(timeout=10)
