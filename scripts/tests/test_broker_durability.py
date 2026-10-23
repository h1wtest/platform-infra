"""Broker durability boundaries; the opt-in smoke launches the pinned image, never a retained PVC."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cli
import security_material
import helm_release
from release_values import release_specs
from test_helm_charts import fixture


def broker_resources(directory):
    runtime, images = fixture(directory)
    specs = release_specs(images, runtime.STATE, runtime.ROOT)
    return {(item['kind'], item['metadata']['name']): item
            for release in ('platform-config', 'redpanda')
            for item in helm_release.render(runtime, release, specs[release])}




class BrokerProvisioning(unittest.TestCase):
    def test_cluster_bootstrap_is_separate_from_node_config_and_retains_quorum_security(self):
        with tempfile.TemporaryDirectory() as directory:
            resources = broker_resources(directory)
        config = resources[('ConfigMap', 'redpanda-config')]['data']
        cluster = json.loads(config['bootstrap.json'])
        self.assertEqual(cluster['write_caching_default'], 'disabled')
        self.assertEqual(cluster['default_topic_replications'], 3)
        self.assertEqual(cluster['admin_api_require_auth'], True)
        self.assertEqual(cluster['kafka_enable_authorization'], True)
        self.assertEqual(cluster['superusers'], ['bootstrap'])
        self.assertEqual(cluster['storage_min_free_bytes'], 268435456)
        for index in range(3):
            node = json.loads(config[str(index) + '.json'])['redpanda']
            self.assertFalse(node['developer_mode'])
            self.assertTrue(set(node).isdisjoint(cluster))
            self.assertTrue(node['rpc_server_tls']['enabled'])
            self.assertTrue(node['kafka_api_tls'][0]['enabled'])
            self.assertEqual(node['kafka_api'][0]['authentication_method'], 'sasl')
            self.assertEqual(node['admin'][0]['address'], '127.0.0.1')
        broker = resources[('StatefulSet', 'redpanda')]['spec']
        self.assertEqual(broker['replicas'], 3)
        self.assertEqual(broker['persistentVolumeClaimRetentionPolicy'], {'whenDeleted': 'Retain', 'whenScaled': 'Retain'})
        self.assertEqual(broker['volumeClaimTemplates'][0]['spec']['resources']['requests']['storage'], '4Gi')

    def test_existing_cluster_receives_centrally_validated_durability_and_security_before_topics(self):
        applied = {}
        def kube(*args, **kwargs):
            if 'rpk' not in args:
                # Actual Admin GET uses typed JSON: unlike rpk get's YAML list/string output.
                return subprocess.CompletedProcess(args, 0, json.dumps(applied).encode())
            command = args[args.index('rpk') + 1:]
            if command[:3] == ('cluster', 'config', 'set'):
                name, value = command[3:]
                applied[name] = value if name == 'write_caching_default' else json.loads(value)
                return subprocess.CompletedProcess(args, 0, b'')
            if command[:3] == ('cluster', 'config', 'get'):
                raise AssertionError('YAML rpk getter is not a JSON interface')
            if 'create' in command:
                self.assertEqual(applied['write_caching_default'], 'disabled')
                self.assertTrue(applied['admin_api_require_auth'])
                self.assertTrue(applied['kafka_enable_authorization'])
            return subprocess.CompletedProcess(args, 0, b'[]')
        with patch.object(cli, 'kube', side_effect=kube):
            cli.topics()
        self.assertEqual(applied['default_topic_replications'], 3)
        self.assertFalse(applied['auto_create_topics_enabled'])

    def test_unpersisted_or_wrongly_typed_policy_blocks_topic_creation(self):
        for missing, wrong in (('write_caching_default', None), ('admin_api_require_auth', 'true'), ('superusers', 'bootstrap')):
            current = security_material.broker_cluster_config()
            if wrong is None:
                del current[missing]
            else:
                current[missing] = wrong
            def kube(*args, **kwargs):
                if 'rpk' not in args:
                    return subprocess.CompletedProcess(args, 0, json.dumps(current).encode())
                command = args[args.index('rpk') + 1:]
                if command[:3] != ('cluster', 'config', 'set'):
                    raise AssertionError('Topics must remain untouched after configuration mismatch')
                return subprocess.CompletedProcess(args, 0, b'')
            with self.subTest(property=missing), patch.object(cli, 'kube', side_effect=kube):
                with self.assertRaisesRegex(RuntimeError, missing):
                    cli.topics()


@unittest.skipUnless(os.environ.get('RUN_REDPANDA_BOOT_CONTRACT') == '1', 'Opt-in pinned-image broker smoke; controller owns Docker')
class ActualBrokerBootContract(unittest.TestCase):
    def test_rendered_boot_has_real_fsync_and_consumer_visible_committed_record(self):
        with tempfile.TemporaryDirectory() as directory:
            resources = broker_resources(directory)
        broker = resources[('StatefulSet', 'redpanda')]['spec']['template']['spec']['containers'][0]
        config = json.loads(resources[('ConfigMap', 'redpanda-config')]['data']['0.json'])
        node = config['redpanda']
        # Only discovery changes for the isolated, disposable one-broker smoke.
        node['seed_servers'] = []
        node['empty_seed_starts_cluster'] = True
        node['advertised_rpc_api']['address'] = 'localhost'
        node['advertised_kafka_api'][0]['address'] = 'localhost'
        bootstrap = json.loads(resources[('ConfigMap', 'redpanda-config')]['data']['bootstrap.json'])
        bootstrap['default_topic_replications'] = 1
        bootstrap['internal_topic_replication_factor'] = 1
        script = '''set -eu
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 -subj /CN=localhost -addext subjectAltName=DNS:localhost -addext basicConstraints=critical,CA:TRUE -out /run/tls/ca.crt -keyout /run/tls/tls.key >/tmp/certificate.log 2>&1
cp /run/tls/ca.crt /run/tls/tls.crt
cat >/run/broker-config/0.json <<'NODE_CONFIG'
''' + json.dumps(config) + '''
NODE_CONFIG
cat >/run/broker-config/bootstrap.json <<'CLUSTER_CONFIG'
''' + json.dumps(bootstrap) + '''
CLUSTER_CONFIG
export POD_INDEX=0 RP_BOOTSTRAP_USER=bootstrap:test-bootstrap-password:SCRAM-SHA-256
export RPK_USER=bootstrap RPK_PASS=test-bootstrap-password RPK_SASL_MECHANISM=SCRAM-SHA-256
export RPK_TLS_ENABLED=true RPK_TLS_CA=/run/tls/ca.crt RPK_ADMIN_HOSTS=127.0.0.1:9645
''' + '/bin/sh -ec ' + shlex.quote(broker['args'][0]) + ''' >/tmp/broker.log 2>&1 &
broker_pid=$!
trap 'kill -TERM "$broker_pid" 2>/dev/null || true; wait "$broker_pid" 2>/dev/null || true' EXIT
attempt=0
while ! rpk cluster health --format json >/tmp/health.json 2>/tmp/health.err; do
    if ! kill -0 "$broker_pid" 2>/dev/null; then cat /tmp/broker.log; exit 1; fi
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 90 ]; then cat /tmp/broker.log /tmp/health.err; exit 1; fi
    sleep 1
done
rpk cluster config get write_caching_default >/tmp/write-caching.txt
curl --fail --silent --show-error --max-time 10 --user "$RPK_USER:$RPK_PASS" http://127.0.0.1:9645/v1/node_config >/tmp/node-config.json
rpk -X brokers=localhost:29092 topic create boot-durability -p 1 -r 1 -c write.caching=true >/tmp/topic-create.txt
printf 'durable-consumer-visible-record\\n' | rpk -X brokers=localhost:29092 topic produce boot-durability --acks=-1 --partition 0 --output-format '%o\\n' >/tmp/produce-offset.txt
rpk -X brokers=localhost:29092 topic consume boot-durability --partitions 0 --offset start --num 1 --format '%v\\n' >/tmp/consumed.txt
curl --fail --silent --show-error --max-time 10 --user "$RPK_USER:$RPK_PASS" http://127.0.0.1:9645/v1/debug/partition/kafka/boot-durability/0 >/tmp/partition-state.json
for file in broker.log health.json write-caching.txt node-config.json produce-offset.txt consumed.txt partition-state.json; do
    printf '\\n===%s===\\n' "$file"
    cat "/tmp/$file"
done
'''
        name = 'broker-boot-contract-' + uuid.uuid4().hex
        try:
            result = subprocess.run(['docker', 'run', '--rm', '--name', name, '-i', '--network=none', '--memory=1g', '--cpus=1', '--read-only',
                                     '--tmpfs', '/tmp:rw,mode=1777', '--mount', 'type=volume,target=/var/lib/redpanda/data',
                                     '--tmpfs', '/run/broker-config:rw,uid=101,gid=101', '--tmpfs', '/run/tls:rw,uid=101,gid=101',
                                     '--user=101:101', '--entrypoint=/bin/sh', broker['image'], '-s'],
                                    input=script, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180, check=False)
        finally:
            subprocess.run(['docker', 'rm', '--force', '--volumes', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=False)
        self.assertEqual(result.returncode, 0, result.stdout)
        sections = {}
        for part in result.stdout.split('\n===')[1:]:
            name, body = part.split('===\n', 1)
            sections[name] = body.strip()
        self.assertIn('--unsafe-bypass-fsync=false', sections['broker.log'])
        self.assertNotIn('--unsafe-bypass-fsync=true', sections['broker.log'])
        self.assertNotIn('development purposes only', sections['broker.log'])
        self.assertNotIn('Ignoring value for', sections['broker.log'])
        self.assertNotIn('Ignoring unknown property', sections['broker.log'])
        self.assertFalse(json.loads(sections['node-config.json'])['developer_mode'])
        self.assertTrue(json.loads(sections['health.json'])['is_healthy'])
        self.assertEqual(sections['write-caching.txt'].strip('"'), 'disabled')
        self.assertEqual(sections['consumed.txt'], 'durable-consumer-visible-record')
        self.assertEqual(sections['produce-offset.txt'], '0')
        replicas = json.loads(sections['partition-state.json'])['replicas']
        self.assertEqual(len(replicas), 1)
        raft = replicas[0]['raft_state']
        self.assertFalse(raft['write_caching_enabled'])
        self.assertGreaterEqual(raft['flushed_offset'], raft['commit_index'])


if __name__ == '__main__':
    unittest.main()
