"""Allow CNPG instance-manager API access only to discovered exact API addresses/ports."""
import ipaddress
import json
import manifests


def discover(runtime):
    def get(namespace, *args):
        return json.loads(runtime.run(['kubectl', '--context', runtime.CONTEXT, '-n', namespace, *args, '-o', 'json']).stdout)
    service = get('default', 'get', 'service', 'kubernetes')
    slices = get('default', 'get', 'endpointslices', '-l', 'kubernetes.io/service-name=kubernetes')
    destinations = {}
    for address in service['spec'].get('clusterIPs', [service['spec']['clusterIP']]):
        destinations.setdefault(443, set()).add(address)
    for item in slices['items']:
        ports = [entry['port'] for entry in item.get('ports', []) if entry.get('port')]
        for endpoint in item.get('endpoints', []):
            if endpoint.get('conditions', {}).get('ready') is False:
                continue
            for address in endpoint.get('addresses', []):
                for port in ports:
                    destinations.setdefault(port, set()).add(address)
    if not any(port != 443 for port in destinations):
        raise RuntimeError('Kubernetes API endpoint discovery yielded no DNAT endpoint port; CNPG API access cannot be safely configured')
    rules = []
    for port, addresses in sorted(destinations.items()):
        if port not in (443, 6443):
            raise RuntimeError('Unexpected Kubernetes API port: ' + str(port))
        peers = []
        for address in sorted(addresses):
            parsed = ipaddress.ip_address(address)
            peers.append({'ipBlock': {'cidr': str(parsed) + ('/32' if parsed.version == 4 else '/128')}})
        rules.append({'to': peers, 'ports': [{'protocol': 'TCP', 'port': port}]})
    return manifests.resource('NetworkPolicy', 'allow-postgres-kubernetes-api', {'podSelector': {'matchLabels': {'cnpg.io/cluster': 'postgres'}}, 'policyTypes': ['Egress'], 'egress': rules})
