"""Fail-closed local peer identity; never reset data or alter Docker endpoints."""
import hashlib
import hmac
import ipaddress
import json
import os

CLUSTER = 'sso-remediation'
NETWORK = 'k3d-' + CLUSTER
SERVERS = tuple(NETWORK + '-server-' + str(index) for index in range(3))
LOADBALANCER = NETWORK + '-serverlb'
TOOLS = NETWORK + '-tools'
CONTAINERS = (*SERVERS, LOADBALANCER)
FILENAME = 'cluster-identity.json'


def fail(detail):
    raise RuntimeError('CLUSTER_IDENTITY_GATE: ' + detail + '; no automatic reset or network reassignment. See README network identity maintenance runbook.')


def ipv4(value):
    try:
        address = ipaddress.ip_address(value)
    except (ValueError, TypeError):
        fail('invalid IPv4 identity')
    if address.version != 4 or address.is_unspecified or address.is_multicast or address.is_loopback:
        fail('invalid IPv4 identity')
    return address


def snapshot(network, containers, nodes=None):
    """Derive peers from persisted K8s/etcd identity, never from Docker ordering."""
    try:
        return _snapshot(network, containers, nodes)
    except (KeyError, TypeError, ValueError, AttributeError):
        fail('incomplete or malformed Docker/Kubernetes identity')


def _snapshot(network, containers, nodes):
    if network['Name'] != NETWORK or network['Driver'] != 'bridge' or not network['Id']:
        fail('wrong Docker network')
    configs = network['IPAM']['Config']
    if len(configs) != 1:
        fail('expected one IPv4 network subnet')
    subnet = ipaddress.ip_network(configs[0]['Subnet'], strict=True)
    gateway = ipv4(configs[0]['Gateway'])
    if subnet.version != 4 or gateway not in subnet:
        fail('wrong Docker subnet/gateway')
    by_name = {item['Name'].lstrip('/'): item for item in containers}
    expected_names = set(CONTAINERS) | ({TOOLS} if TOOLS in by_name else set())
    if len(containers) != len(expected_names) or set(by_name) != expected_names:
        fail('expected three servers, owned loadbalancer and optional owned k3d tools')
    ids = [item['Id'] for item in containers]
    if len(set(ids)) != len(containers) or not all(ids):
        fail('duplicate or missing container identity')
    members = network.get('Containers') or {}
    if set(members) - set(ids):
        fail('foreign container on dedicated cluster network')
    addresses = set()
    peers = {}
    lb = None
    for name, item in by_name.items():
        labels = item['Config']['Labels']
        if labels.get('app') != 'k3d' or labels.get('k3d.cluster') != CLUSTER:
            fail('wrong container ownership')
        expected_role = 'server' if name in SERVERS else ('noRole' if name == TOOLS else 'loadbalancer')
        if labels.get('k3d.role') != expected_role:
            fail('wrong container role')
        if name == TOOLS and labels.get('k3d.version') != 'v5.9.0':
            fail('unrecognized k3d tools owner/version')
        endpoints = item['NetworkSettings']['Networks']
        if set(endpoints) != {NETWORK}:
            fail('wrong or additional Docker network')
        endpoint = endpoints[NETWORK]
        if endpoint['NetworkID'] != network['Id']:
            fail('wrong Docker network ID')
        static = (endpoint.get('IPAMConfig') or {}).get('IPv4Address')
        if name in SERVERS and not static:
            fail('peer lacks explicit static IPAM reservation')
        running = item['State']['Running']
        actual = endpoint.get('IPAddress')
        if running and not actual:
            fail('running endpoint has no address')
        if static and actual and static != actual:
            fail('endpoint differs from static IPAM reservation')
        value = static or actual
        if value:
            address = ipv4(value)
            if address not in subnet or address in (subnet.network_address, subnet.broadcast_address, gateway):
                fail('endpoint outside usable cluster subnet')
            if address in addresses:
                fail('duplicate endpoint IP')
            addresses.add(address)
        if actual and endpoint.get('IPPrefixLen') != subnet.prefixlen:
            fail('endpoint prefix differs from network subnet')
        if running:
            member = members.get(item['Id'])
            if not member or member['Name'] != name or str(ipaddress.ip_interface(member['IPv4Address']).ip) != actual:
                fail('network/container endpoint inventory differs')
        if name in SERVERS:
            peers[name] = {'container_id': item['Id'], 'ip': str(ipv4(static))}
        elif name == LOADBALANCER:
            # k3d v5.9 managed IPAM pins servers, not its DNS-addressed proxy.
            lb = {'container_id': item['Id'], 'static_ip': static}
    if nodes is not None:
        items = nodes['items']
        by_node = {item['metadata']['name']: item for item in items}
        if len(items) != 3 or set(by_node) != set(SERVERS):
            fail('expected exactly three Kubernetes nodes')
        uids = set()
        member_names = set()
        for name in SERVERS:
            node = by_node[name]
            if not by_name[name]['State']['Running']:
                fail('baseline/live verification requires running peers')
            conditions = node['status']['conditions']
            if not any(row['type'] == 'Ready' and row['status'] == 'True' for row in conditions):
                fail('all Kubernetes nodes must be Ready')
            internal = [row['address'] for row in node['status']['addresses'] if row['type'] == 'InternalIP']
            annotations = node['metadata']['annotations']
            original = annotations.get('etcd.k3s.cattle.io/node-address')
            member_name = annotations.get('etcd.k3s.cattle.io/node-name')
            if internal != [peers[name]['ip']] or original != peers[name]['ip'] or not member_name:
                fail('Docker static address differs from original Kubernetes/etcd peer identity')
            uid = node['metadata']['uid']
            if not uid or uid in uids or member_name in member_names:
                fail('duplicate or missing Kubernetes/etcd identity')
            uids.add(uid)
            member_names.add(member_name)
            pod_cidrs = node.get('spec', {}).get('podCIDRs') or [node.get('spec', {}).get('podCIDR')]
            if not pod_cidrs or not all(pod_cidrs):
                fail('missing Kubernetes pod subnet identity')
            for cidr in pod_cidrs:
                pod_subnet = ipaddress.ip_network(cidr, strict=True)
                if pod_subnet.version == 4 and pod_subnet.overlaps(subnet):
                    fail('Docker peer subnet overlaps pod subnet')
            peers[name].update(node_uid=uid, etcd_member_name=member_name)
    return {'schema': 1, 'cluster': CLUSTER, 'network': {
        'name': NETWORK, 'id': network['Id'], 'subnet': str(subnet), 'gateway': str(gateway)},
        'nodes': peers, 'loadbalancer': lb}


def validate(baseline, network, containers, nodes=None):
    actual = snapshot(network, containers, nodes)
    expected = baseline
    if nodes is None:
        try:
            expected = {**baseline, 'nodes': {name: {'container_id': value['container_id'], 'ip': value['ip']}
                                            for name, value in baseline['nodes'].items()}}
        except (KeyError, TypeError):
            fail('malformed baseline')
    if actual != expected:
        fail('current network/container/Kubernetes identity differs from immutable baseline')
    return baseline


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def load(path):
    try:
        if path.is_symlink() or (os.name != 'nt' and path.stat().st_mode & 0o377):
            fail('baseline must be a private read-only regular file')
        envelope = json.loads(path.read_text(encoding='utf-8'))
        value = envelope['identity']
        if not hmac.compare_digest(envelope['sha256'], digest(value)):
            fail('baseline integrity mismatch')
        if value['schema'] != 1 or value['cluster'] != CLUSTER or set(value['nodes']) != set(SERVERS):
            fail('unsupported baseline identity')
        return value
    except FileNotFoundError:
        fail('missing baseline; explicitly run cli.py cluster-identity on healthy static original peers first')
    except (KeyError, TypeError, ValueError, OSError):
        fail('unreadable or malformed baseline')


def record(path, value):
    """Exclusive create, never rebaseline; 0400 and checksum are not root-proof signing."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    content = (json.dumps({'identity': value, 'sha256': digest(value)}, indent=2) + '\n').encode()
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    except FileExistsError:
        fail('baseline already exists; replacement is not allowed')
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    if os.name != 'nt':
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def inspect(cli):
    networks = json.loads(cli.run(['docker', 'network', 'inspect', NETWORK], timeout=15).stdout)
    if not isinstance(networks, list) or len(networks) != 1:
        fail('ambiguous Docker network inventory')
    containers = json.loads(cli.run(['docker', 'inspect', *CONTAINERS], timeout=15).stdout)
    extras = [(container_id, row) for container_id, row in (networks[0].get('Containers') or {}).items()
              if container_id not in {container['Id'] for container in containers}]
    for container_id, row in extras:
        if row.get('Name') != TOOLS:
            fail('foreign container on dedicated cluster network')
        inspected = json.loads(cli.run(['docker', 'inspect', container_id], timeout=15).stdout)
        if not isinstance(inspected, list) or len(inspected) != 1 or inspected[0].get('Id') != container_id:
            fail('ambiguous tools container identity')
        containers.extend(inspected)
    return networks[0], containers


def guard(cli, *, live=True, initialize=False):
    path = cli.STATE / FILENAME
    # A missing manifest blocks start before any mutation, even when K8s is down.
    baseline = None if initialize and not path.exists() else load(path)
    network, containers = inspect(cli)
    nodes = json.loads(cli.kube('get', 'nodes', '-o', 'json', timeout=20).stdout) if live else None
    if baseline is None:
        if not live:
            fail('baseline creation requires live original Kubernetes peer identity')
        baseline = snapshot(network, containers, nodes)
        record(path, baseline)
    else:
        validate(baseline, network, containers, nodes)
    return baseline


if __name__ == '__main__':
    import argparse
    import cli
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['verify', 'prestart'])
    arguments = parser.parse_args()
    try:
        guard(cli, live=arguments.mode == 'verify')
    except (RuntimeError, ValueError, OSError) as error:
        parser.exit(1, str(error) + '\n')
    print('PASS immutable cluster network/peer identity (' + arguments.mode + ')')
