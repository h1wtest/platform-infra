"""No Docker/Kubernetes processes: realistic inspect documents exercise fail-closed identity."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cluster_identity as identity
import cli


def fixture():
    names = ['k3d-sso-remediation-server-' + str(i) for i in range(3)]
    addresses = ['10.81.0.3', '10.81.0.4', '10.81.0.5']
    network = {'Name': 'k3d-sso-remediation', 'Id': 'a' * 64, 'Driver': 'bridge',
               'IPAM': {'Config': [{'Subnet': '10.81.0.0/24', 'Gateway': '10.81.0.1'}]}, 'Containers': {}}
    containers = []
    nodes = []
    for index, (name, address) in enumerate(zip(names + ['k3d-sso-remediation-serverlb'], addresses + ['10.81.0.2'])):
        container_id = str(index + 1) * 64
        endpoint = {'NetworkID': network['Id'], 'IPAddress': address, 'IPPrefixLen': 24,
                    'IPAMConfig': {'IPv4Address': address} if index < 3 else None}
        containers.append({'Name': '/' + name, 'Id': container_id, 'Config': {'Labels': {
            'app': 'k3d', 'k3d.cluster': 'sso-remediation', 'k3d.role': 'server' if index < 3 else 'loadbalancer'}},
            'State': {'Running': True}, 'NetworkSettings': {'Networks': {network['Name']: endpoint}}})
        network['Containers'][container_id] = {'Name': name, 'IPv4Address': address + '/24'}
        if index < 3:
            nodes.append({'metadata': {'name': name, 'uid': 'node-' + str(index), 'annotations': {
                'etcd.k3s.cattle.io/node-address': address, 'etcd.k3s.cattle.io/node-name': name + '-member'}},
                'spec': {'podCIDRs': ['10.42.' + str(index) + '.0/24']},
                'status': {'addresses': [{'type': 'InternalIP', 'address': address}],
                           'conditions': [{'type': 'Ready', 'status': 'True'}]}})
    return network, containers, {'items': nodes}


class ClusterIdentityTests(unittest.TestCase):
    def test_matching_static_peers_pass_with_discovered_non172_subnet(self):
        network, containers, nodes = fixture()
        result = identity.snapshot(network, containers, nodes)
        identity.validate(result, network, containers, nodes)
        self.assertEqual(result['nodes']['k3d-sso-remediation-server-0']['ip'], '10.81.0.3')
        self.assertEqual(result['network']['subnet'], '10.81.0.0/24')
        self.assertNotIn('Config', result)
        self.assertNotIn('annotations', result['nodes']['k3d-sso-remediation-server-0'])

    def test_dynamic_peer_rejected_even_when_current_ip_matches_kubernetes(self):
        network, containers, nodes = fixture()
        containers[1]['NetworkSettings']['Networks'][network['Name']]['IPAMConfig'] = None
        with self.assertRaisesRegex(RuntimeError, 'static'):
            identity.snapshot(network, containers, nodes)

    def test_permuted_docker_addresses_cannot_establish_first_baseline(self):
        network, containers, nodes = fixture()
        for index, address in enumerate(['10.81.0.4', '10.81.0.3']):
            endpoint = containers[index]['NetworkSettings']['Networks'][network['Name']]
            endpoint.update(IPAddress=address, IPAMConfig={'IPv4Address': address})
            network['Containers'][containers[index]['Id']]['IPv4Address'] = address + '/24'
        with self.assertRaisesRegex(RuntimeError, 'peer identity'):
            identity.snapshot(network, containers, nodes)

    def test_kubernetes_internalip_cannot_replace_original_etcd_identity(self):
        network, containers, nodes = fixture()
        nodes['items'][0]['metadata']['annotations']['etcd.k3s.cattle.io/node-address'] = '10.81.0.90'
        with self.assertRaisesRegex(RuntimeError, 'peer identity'):
            identity.snapshot(network, containers, nodes)

    def test_duplicate_wrong_network_foreign_endpoint_and_outside_subnet_fail(self):
        for mutation in ('duplicate', 'network', 'foreign', 'subnet', 'pod-overlap'):
            network, containers, nodes = fixture()
            endpoint = containers[1]['NetworkSettings']['Networks'][network['Name']]
            if mutation == 'duplicate':
                endpoint.update(IPAddress='10.81.0.3', IPAMConfig={'IPv4Address': '10.81.0.3'})
            elif mutation == 'network':
                endpoint['NetworkID'] = 'b' * 64
            elif mutation == 'foreign':
                network['Containers']['foreign'] = {'Name': 'outside-workload', 'IPv4Address': '10.81.0.7/24'}
            elif mutation == 'subnet':
                endpoint.update(IPAddress='10.82.0.4', IPAMConfig={'IPv4Address': '10.82.0.4'})
            else:
                nodes['items'][0]['spec']['podCIDRs'] = ['10.81.0.0/24']
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                identity.snapshot(network, containers, nodes)

    def test_missing_notready_or_extra_kubernetes_node_cannot_be_baseline(self):
        for mutation in ('missing', 'notready', 'extra'):
            network, containers, nodes = fixture()
            if mutation == 'missing':
                nodes['items'].pop()
            elif mutation == 'notready':
                nodes['items'][0]['status']['conditions'][0]['status'] = 'False'
            else:
                nodes['items'].append(copy.deepcopy(nodes['items'][0]))
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                identity.snapshot(network, containers, nodes)

    def test_stopped_container_configuration_can_be_checked_without_kubernetes(self):
        network, containers, nodes = fixture()
        baseline = identity.snapshot(network, containers, nodes)
        network['Containers'] = {}
        for container in containers:
            container['State']['Running'] = False
            container['NetworkSettings']['Networks'][network['Name']]['IPAddress'] = ''
        identity.validate(baseline, network, containers)

    def test_manifest_is_create_once_private_and_tampered_content_fails(self):
        baseline = identity.snapshot(*fixture())
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'cluster-identity.json'
            identity.record(path, baseline)
            original = path.read_bytes()
            self.assertEqual(identity.load(path), baseline)
            if os.name != 'nt':
                self.assertEqual(path.stat().st_mode & 0o777, 0o400)
            with self.assertRaisesRegex(RuntimeError, 'exists'):
                identity.record(path, baseline)
            self.assertEqual(path.read_bytes(), original)
            path.chmod(0o600)
            value = json.loads(path.read_text())
            value['identity']['nodes']['k3d-sso-remediation-server-0']['ip'] = '10.81.0.9'
            path.write_text(json.dumps(value))
            path.chmod(0o400)
            with self.assertRaisesRegex(RuntimeError, 'integrity'):
                identity.load(path)

    def test_matching_snapshot_does_not_mask_replaced_container_or_node_uid(self):
        network, containers, nodes = fixture()
        baseline = identity.snapshot(network, containers, nodes)
        containers[0]['Id'] = 'f' * 64
        with self.assertRaises(RuntimeError):
            identity.validate(baseline, network, containers, nodes)
        network, containers, nodes = fixture()
        nodes['items'][0]['metadata']['uid'] = 'recreated'
        with self.assertRaisesRegex(RuntimeError, 'baseline'):
            identity.validate(baseline, network, containers, nodes)

    def test_start_guard_blocks_before_k3d_start_with_real_inspect_validation(self):
        network, containers, nodes = fixture()
        baseline = identity.snapshot(network, containers, nodes)
        containers[0]['NetworkSettings']['Networks'][network['Name']]['IPAMConfig'] = None
        calls = []
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            identity.record(state / 'cluster-identity.json', baseline)

            def run(arguments, **kwargs):
                calls.append(arguments)
                if arguments[:3] == ['docker', 'network', 'inspect']:
                    return subprocess.CompletedProcess(arguments, 0, json.dumps([network]).encode(), b'')
                if arguments[:2] == ['docker', 'inspect']:
                    return subprocess.CompletedProcess(arguments, 0, json.dumps(containers).encode(), b'')
                raise AssertionError('Unexpected process (including forbidden start): ' + repr(arguments))

            with patch.object(cli, 'STATE', state), patch.object(cli, 'run', side_effect=run):
                with self.assertRaisesRegex(RuntimeError, 'static'):
                    cli.start_cluster()
            self.assertTrue(calls)
            self.assertTrue(all(arguments[0] == 'docker' for arguments in calls))

    def test_baseline_network_id_change_is_rejected_even_with_matching_endpoint_documents(self):
        network, containers, nodes = fixture()
        baseline = identity.snapshot(network, containers, nodes)
        network['Id'] = 'b' * 64
        for container in containers:
            container['NetworkSettings']['Networks'][network['Name']]['NetworkID'] = network['Id']
        with self.assertRaisesRegex(RuntimeError, 'baseline'):
            identity.validate(baseline, network, containers, nodes)

    def test_dynamic_first_record_is_refused_without_creating_manifest(self):
        network, containers, nodes = fixture()
        containers[0]['NetworkSettings']['Networks'][network['Name']]['IPAMConfig'] = {}
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            with patch.object(cli, 'STATE', state), patch.object(identity, 'inspect', return_value=(network, containers)), patch.object(cli, 'kube', return_value=subprocess.CompletedProcess([], 0, json.dumps(nodes).encode(), b'')):
                with self.assertRaisesRegex(RuntimeError, 'static'):
                    identity.guard(cli, initialize=True)
            self.assertFalse((state / 'cluster-identity.json').exists())

    def test_record_verify_never_overwrites_existing_baseline(self):
        network, containers, nodes = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            with patch.object(cli, 'STATE', state), patch.object(identity, 'inspect', return_value=(network, containers)), patch.object(cli, 'kube', return_value=subprocess.CompletedProcess([], 0, json.dumps(nodes).encode(), b'')):
                identity.guard(cli, initialize=True)
                path = state / 'cluster-identity.json'
                original = path.read_bytes()
                identity.guard(cli, initialize=True)
                self.assertEqual(path.read_bytes(), original)
                containers[0]['NetworkSettings']['Networks'][network['Name']]['IPAMConfig'] = None
                with self.assertRaisesRegex(RuntimeError, 'static'):
                    identity.guard(cli, initialize=True)
                self.assertEqual(path.read_bytes(), original)

    def test_start_rechecks_live_kubernetes_identity_before_returning_success(self):
        network, containers, nodes = fixture()
        baseline = identity.snapshot(network, containers, nodes)
        nodes['items'][0]['metadata']['uid'] = 'unexpected-new-uid'
        started = []
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            identity.record(state / 'cluster-identity.json', baseline)

            def run(arguments, **kwargs):
                if arguments[:3] == ['docker', 'network', 'inspect']:
                    return subprocess.CompletedProcess(arguments, 0, json.dumps([network]).encode(), b'')
                if arguments[:2] == ['docker', 'inspect']:
                    return subprocess.CompletedProcess(arguments, 0, json.dumps(containers).encode(), b'')
                if arguments[:3] == ['k3d', 'cluster', 'start']:
                    started.append(True)
                    return subprocess.CompletedProcess(arguments, 0, b'', b'')
                raise AssertionError('Unexpected process: ' + repr(arguments))

            def kube(*arguments, **kwargs):
                return subprocess.CompletedProcess([], 0, json.dumps(nodes).encode() if arguments[0] == 'get' else b'', b'')

            with patch.object(cli, 'STATE', state), patch.object(cli, 'run', side_effect=run), patch.object(cli, 'kube', side_effect=kube):
                with self.assertRaisesRegex(RuntimeError, 'baseline'):
                    cli.start_cluster()
            self.assertEqual(started, [True])

    def test_owned_k3d_tools_is_transient_but_foreign_owner_or_duplicate_ip_is_rejected(self):
        network, containers, nodes = fixture()
        baseline = identity.snapshot(network, containers, nodes)
        helper = copy.deepcopy(containers[-1])
        helper['Name'] = '/k3d-sso-remediation-tools'
        helper['Id'] = 'e' * 64
        helper['Config']['Labels'].update({'k3d.role': 'noRole', 'k3d.version': 'v5.9.0'})
        helper['NetworkSettings']['Networks'][network['Name']].update(IPAddress='10.81.0.6', IPAMConfig=None)
        network['Containers'][helper['Id']] = {'Name': 'k3d-sso-remediation-tools', 'IPv4Address': '10.81.0.6/24'}
        identity.validate(baseline, network, containers + [helper], nodes)
        def docker(arguments, **kwargs):
            if arguments[:3] == ['docker', 'network', 'inspect']:
                return subprocess.CompletedProcess(arguments, 0, json.dumps([network]).encode(), b'')
            if arguments == ['docker', 'inspect', helper['Id']]:
                return subprocess.CompletedProcess(arguments, 0, json.dumps([helper]).encode(), b'')
            if arguments == ['docker', 'inspect', *identity.CONTAINERS]:
                return subprocess.CompletedProcess(arguments, 0, json.dumps(containers).encode(), b'')
            raise AssertionError('Unexpected operation: ' + repr(arguments))

        with patch.object(cli, 'run', side_effect=docker):
            observed_network, observed_containers = identity.inspect(cli)
        identity.validate(baseline, observed_network, observed_containers, nodes)
        helper['Config']['Labels']['k3d.cluster'] = 'foreign'
        with self.assertRaisesRegex(RuntimeError, 'ownership'):
            identity.validate(baseline, network, containers + [helper], nodes)
        helper['Config']['Labels']['k3d.cluster'] = 'sso-remediation'
        helper['NetworkSettings']['Networks'][network['Name']]['IPAddress'] = '10.81.0.3'
        with self.assertRaisesRegex(RuntimeError, 'duplicate'):
            identity.validate(baseline, network, containers + [helper], nodes)

    def test_fresh_creation_selects_managed_auto_ipam_and_records_observed_identity(self):
        network, containers, nodes = fixture()
        created = []
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)

            def run(arguments, **kwargs):
                if arguments[:3] == ['k3d', 'cluster', 'list']:
                    return subprocess.CompletedProcess(arguments, 0, b'[]', b'')
                if arguments[:3] == ['k3d', 'cluster', 'create']:
                    # Boundary simulation refuses dynamic peer creation, mirroring pinned k3d IPAM.
                    if '--subnet' not in arguments or arguments[arguments.index('--subnet') + 1] != 'auto':
                        for container in containers[:3]:
                            container['NetworkSettings']['Networks'][network['Name']]['IPAMConfig'] = None
                    created.append(arguments[3])
                    return subprocess.CompletedProcess(arguments, 0, b'', b'')
                if arguments[:3] == ['docker', 'network', 'inspect']:
                    return subprocess.CompletedProcess(arguments, 0, json.dumps([network]).encode(), b'')
                if arguments[:2] == ['docker', 'inspect']:
                    return subprocess.CompletedProcess(arguments, 0, json.dumps(containers).encode(), b'')
                raise AssertionError('Unexpected process: ' + repr(arguments))

            for node in nodes['items']:
                node['status']['nodeInfo'] = {'kubeletVersion': 'v1.35.9+k3s1'}
            with patch.object(cli, 'STATE', state), patch.object(cli, 'run', side_effect=run), patch.object(cli, 'load_images', return_value={'k3s': 'pinned-image'}), patch.object(cli, 'kube', return_value=subprocess.CompletedProcess([], 0, json.dumps(nodes).encode(), b'')):
                cli.cluster()
            self.assertEqual(created, ['sso-remediation'])
            self.assertEqual(identity.load(state / 'cluster-identity.json')['nodes']['k3d-sso-remediation-server-2']['ip'], '10.81.0.5')

    def test_existing_cluster_requires_explicit_baseline_instead_of_silent_adoption(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            result = subprocess.CompletedProcess([], 0, b'[{"name":"sso-remediation"}]', b'')
            with patch.object(cli, 'STATE', state), patch.object(cli, 'run', return_value=result) as process, patch.object(cli, 'kube', side_effect=AssertionError('missing baseline must fail first')):
                with self.assertRaisesRegex(RuntimeError, 'missing baseline'):
                    cli.cluster()
            self.assertEqual(process.call_count, 1)
            self.assertFalse((state / 'cluster-identity.json').exists())


if __name__ == '__main__':
    unittest.main()
