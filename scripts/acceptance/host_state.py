#!/usr/bin/env python3
"""Owned committed data/session fixture for the isolated Docker-host failure gate."""
import argparse
import hashlib
import http.cookiejar
import json
from pathlib import Path
import re
import secrets
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_ROOT = Path('/home/bpqvg/dev/h1wtest-remediation/platform-infra')
BASE = 'https://localhost:8448'
CA = ROOT / '.local/ca.crt'
STATE = ROOT / '.local/acceptance'

from e2e import Client
sys.path.insert(0, str(ROOT / 'scripts'))
import cli
from private_files import atomic_json


def state_path():
    return STATE / 'host-fault-private.json'


def load(run_id=None):
    value = json.loads(state_path().read_text())
    if not re.fullmatch(r'host_fault_[0-9a-f]{32}', value['database']):
        raise RuntimeError('Invalid owned host-fault database identifier')
    if run_id is not None and value['run_id'] != run_id:
        raise RuntimeError('Host-fault fixture predates this invocation; refusing mutation')
    return value


def saved_client(value):
    client = Client(BASE, str(CA))
    for row in value['cookies']:
        fields = dict(row)
        fields['rest'] = fields.pop('_rest')
        client.jar.set_cookie(http.cookiejar.Cookie(**fields))
    client.csrf = value['csrf']
    return client


def acquire_session(value, account, *, purpose):
    """Publish intent before POST, then response credentials before any extra request."""
    client = Client(BASE, str(CA))
    client.bootstrap_csrf()
    acquisition = {'purpose': purpose, 'state': 'intent', 'started_at': time.time()}
    value.setdefault('acquisitions', []).append(acquisition)
    atomic_json(state_path(), value)
    # An exception here is ambiguous: retain the durable intent, never erase it.
    _, response, _ = client.call('POST', '/api/v1/auth/login', {
        'email': account['email'], 'password': account['password'],
        'device_name': 'Owned host-fault ' + value['run_id'],
    })
    client.csrf = response.get('csrf_token', client.csrf)
    session_id = response.get('session_id')
    acquisition.update(state='recorded', session_id=session_id, response_at=time.time())
    value['cookies'] = [cookie.__dict__ for cookie in client.jar]
    value['csrf'] = client.csrf
    if purpose == 'prepare':
        value['session_id'] = session_id
    elif session_id:
        value.setdefault('cleanup_session_ids', []).append(session_id)
    try:
        atomic_json(state_path(), value)
    except BaseException:
        # The successful response is still in memory: revoke it before propagating.
        # On unsuccessful revocation the prior intent survives for explicit recovery.
        try:
            client.call('POST', '/api/v1/auth/logout', {}, expected=(200, 401))
            client.call('GET', '/api/v1/auth/me', expected=(401,))
            acquisition['state'] = 'revoked'
            atomic_json(state_path(), value)
        except BaseException:
            pass
        raise
    if response.get('status') != 'authenticated' or not session_id or response.get('user', {}).get('id') != value['user_id']:
        raise RuntimeError('Owned probe login did not return the expected authenticated owner/session')
    return client, response


KAFKA_TOPICS = ('identity.events.v1', 'notification.commands.v1')
KAFKA_RECORD_FORMAT = '{"partition":%p,"offset":%o,"key_hex":"%k{hex}","value_hex":"%v{hex}"}\\n'


def rpk(arguments, *, data=None, deadline=None):
    remaining = 20 if deadline is None else min(20, deadline - time.monotonic())
    if remaining <= 0:
        raise TimeoutError('Kafka evidence deadline exceeded')
    command = ['exec']
    if data is not None:
        command.append('-i')
    command += ['redpanda-0', '--', 'rpk', '-X', 'brokers=localhost:29092', *arguments]
    # Credentials stay inside the broker's existing RPK environment; no plaintext
    # response or consumed record is printed or included in command diagnostics.
    result = cli.kube(*command, input=data, timeout=remaining, check=False)
    if result.returncode:
        raise RuntimeError('Kafka evidence command failed: ' + arguments[1])
    return result.stdout.decode()


def broker_healthy(deadline):
    from broker_health import wait_healthy
    wait_healthy(cli, timeout=max(1, min(30, deadline - time.monotonic())))


def kafka_partitions(topic, deadline):
    described = json.loads(rpk(['topic', 'describe', topic, '-p', '--format', 'json'], deadline=deadline))
    if not isinstance(described, list) or len(described) != 1 or described[0].get('summary', {}).get('name') != topic:
        raise RuntimeError('Kafka topic metadata is not the exact requested topic')
    description = described[0]
    partitions = description.get('partitions', [])
    if description['summary'].get('error') or len(partitions) != 6 or {row['partition'] for row in partitions} != set(range(6)):
        raise RuntimeError('Kafka six-partition inventory unavailable')
    for row in partitions:
        if row.get('error') or row.get('load_error') or row.get('offline_replicas') or len(row.get('replicas', [])) != 3:
            raise RuntimeError('Kafka required RF3 partition metadata unhealthy')
        if not isinstance(row.get('log_start_offset'), int) or not isinstance(row.get('high_watermark'), int) or row['log_start_offset'] < 0 or row['high_watermark'] < row['log_start_offset']:
            raise RuntimeError('Kafka partition offset inventory unavailable')
    return partitions


def read_kafka_record(topic, partition, offset, deadline):
    raw = rpk(['topic', 'consume', topic, '--partitions', str(partition), '--offset', str(offset), '--num', '1', '--format', KAFKA_RECORD_FORMAT], deadline=deadline)
    rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    if len(rows) != 1 or rows[0].get('partition') != partition or rows[0].get('offset') != offset:
        raise RuntimeError('Consumer did not return exact requested Kafka coordinate')
    row = rows[0]
    try:
        key = bytes.fromhex(row['key_hex'])
        payload = bytes.fromhex(row['value_hex'])
    except (KeyError, TypeError, ValueError):
        raise RuntimeError('Kafka key/value evidence decoding failed') from None
    return {'topic': topic, 'partition': partition, 'offset': offset,
            'key_sha256': hashlib.sha256(key).hexdigest(),
            'value_sha256': hashlib.sha256(payload).hexdigest(),
            'key_bytes': len(key), 'value_bytes': len(payload)}


def prepare_kafka(value):
    deadline = time.monotonic() + 180
    broker_healthy(deadline)
    topic = 'acceptance-host-' + value['run_id']
    value['kafka'] = {'topic': topic, 'creation_state': 'intent', 'retention_ms': 86400000,
                      'markers': [], 'history': [], 'history_windows': []}
    atomic_json(state_path(), value)
    rpk(['topic', 'create', topic, '-p', '6', '-r', '3', '-c', 'retention.ms=86400000', '-c', 'cleanup.policy=delete'], deadline=deadline)
    value['kafka']['creation_state'] = 'created'
    atomic_json(state_path(), value)
    kafka_partitions(topic, deadline)
    for partition in range(6):
        key = value['run_id'] + ':' + str(partition)
        payload = secrets.token_hex(32)
        acknowledged = json.loads(rpk(['topic', 'produce', topic, '--partition', str(partition), '--key', key, '--acks=-1', '--delivery-timeout', '10s', '--output-format', '{"partition":%p,"offset":%o}\\n'], data=(payload + '\n').encode(), deadline=deadline))
        if not isinstance(acknowledged, dict) or acknowledged.get('partition') != partition or not isinstance(acknowledged.get('offset'), int) or acknowledged['offset'] < 0:
            raise RuntimeError('Kafka producer acknowledgment does not match requested partition')
        marker = {'topic': topic, 'partition': partition, 'offset': acknowledged['offset'],
                  'key_sha256': hashlib.sha256(key.encode()).hexdigest(),
                  'value_sha256': hashlib.sha256(payload.encode()).hexdigest(),
                  'key_bytes': len(key.encode()), 'value_bytes': len(payload.encode())}
        value['kafka']['markers'].append(marker)
        atomic_json(state_path(), value)
        if read_kafka_record(topic, partition, marker['offset'], deadline) != marker:
            raise RuntimeError('Kafka acknowledged marker is not consumer-visible at exact coordinate')
    for existing in KAFKA_TOPICS:
        sampled = []
        for row in kafka_partitions(existing, deadline):
            partition, first, end = row['partition'], row['log_start_offset'], row['high_watermark']
            value['kafka']['history_windows'].append({'topic': existing, 'partition': partition, 'start_offset': first, 'end_offset_exclusive': end})
            offsets = sorted(set(range(first, min(first + 2, end))) | set(range(max(first, end - 2), end)))
            for offset in offsets:
                record = read_kafka_record(existing, partition, offset, deadline)
                value['kafka']['history'].append(record)
                sampled.append(record)
                atomic_json(state_path(), value)
        if not sampled:
            raise RuntimeError('Kafka topic has no existing records; historical durability proof unavailable')
    value['kafka']['prepared_at'] = time.time()
    atomic_json(state_path(), value)


def verify_kafka(value):
    deadline = time.monotonic() + 180
    broker_healthy(deadline)
    evidence = value.get('kafka', {})
    markers, history = evidence.get('markers', []), evidence.get('history', [])
    if len(markers) != 6 or {row['partition'] for row in markers} != set(range(6)) or not all(any(row['topic'] == topic for row in history) for topic in KAFKA_TOPICS):
        raise RuntimeError('Complete acknowledged Kafka markers and nonempty historical evidence required')
    for before in [*markers, *history]:
        actual = read_kafka_record(before['topic'], before['partition'], before['offset'], deadline)
        if actual != before:
            raise RuntimeError('Kafka record hash/coordinate changed across host recovery')
    return {'owned_topic': evidence['topic'], 'acknowledged_markers': markers,
            'existing_history_records': history, 'existing_history_windows': evidence['history_windows'],
            'verified_at': time.time(), 'consumer_groups_modified': False,
            'scope': 'Six acknowledged RF3 partition markers and bounded first/end history samples; not every Kafka record',
            'retained_owned_topic_policy': '24h record retention; topic metadata retained, no truncation/deletion'}


def prepare(run_id=None):
    if state_path().exists():
        raise RuntimeError('An owned fixture already exists; verify/cleanup before another injection')
    account = json.loads((STATE / 'state.json').read_text())['probe']
    # Write ownership before acquiring any server-side resource, including session.
    value = {
        'run_id': run_id or uuid.uuid4().hex,
        'database': 'host_fault_' + uuid.uuid4().hex, 'marker': secrets.token_hex(32),
        'profile_name': 'Host recovery ' + uuid.uuid4().hex,
        'session_id': None, 'user_id': account['user_id'],
        'prepared_at': time.time(),
        'cookies': [], 'csrf': '', 'acquisitions': [],
        'cleanup': {'profile_restored': True}, 'cleanup_session_ids': [],
    }
    atomic_json(state_path(), value)
    client, actor = acquire_session(value, account, purpose='prepare')
    _, profile, _ = client.call('GET', '/api/v1/users/me')
    if profile['profile']['user_id'] != account['user_id']:
        raise RuntimeError('Private acceptance probe does not own authenticated profile')
    value['original_profile_name'] = profile['profile']['display_name']
    atomic_json(state_path(), value)
    cli.dbsql('CREATE DATABASE ' + value['database'])
    cli.dbsql("CREATE TABLE durable_probe (value text PRIMARY KEY); INSERT INTO durable_probe VALUES ('" + value['marker'] + "')", value['database'])
    value['cleanup']['profile_restored'] = False
    atomic_json(state_path(), value)
    client.call('PATCH', '/api/v1/users/me', {'display_name': value['profile_name']})
    prepare_kafka(value)
    verify(value['run_id'], write_evidence=False)
    print('PASS prepared committed database/profile marker and existing session; run_id=' + value['run_id'])


def verify(run_id=None, *, write_evidence=True):
    value = load(run_id)
    client = saved_client(value)
    # NEVER login here: only the exact pre-fault session is acceptable evidence.
    _, actor, _ = client.call('GET', '/api/v1/auth/me')
    if actor['session_id'] != value['session_id'] or actor['user']['id'] != value['user_id']:
        raise RuntimeError('Pre-fault authenticated session was not preserved')
    _, profile, _ = client.call('GET', '/api/v1/users/me')
    if profile['profile']['user_id'] != value['user_id'] or profile['profile']['display_name'] != value['profile_name']:
        raise RuntimeError('Pre-fault committed profile was not preserved')
    actual = cli.dbsql('SELECT value FROM durable_probe', value['database'])
    if actual != value['marker']:
        raise RuntimeError('Pre-fault committed database value was not preserved')
    kafka_evidence = verify_kafka(value)
    if write_evidence:
        atomic_json(STATE / 'host-fault-business.json', {
            'run_id': value['run_id'], 'verified_at': time.time(), 'prepared_at': value['prepared_at'],
            'committed_value_sha256': hashlib.sha256(actual.encode()).hexdigest(),
            'committed_profile_preserved': True, 'preexisting_session_preserved': True,
            'database_value_preserved': True,
            'kafka': kafka_evidence,
        })
        print('PASS exact preexisting session, committed profile and database value preserved')


def cleanup(run_id=None):
    if not state_path().exists():
        print('Owned host-fault fixture already absent')
        return
    value = load(run_id)
    done = value.setdefault('cleanup', {})
    errors = []

    def complete(name):
        done[name] = True
        atomic_json(state_path(), value)

    def attempt(name, action):
        if done.get(name):
            return
        try:
            action()
            complete(name)
        except Exception as error:
            errors.append(name + ':' + type(error).__name__)

    # DB cleanup is independent of HTTP/session health and can always be retried.
    attempt('database_removed', lambda: cli.dbsql('DROP DATABASE IF EXISTS ' + value['database']))
    client = None
    try:
        client = saved_client(value)
        status, actor, _ = client.call('GET', '/api/v1/auth/me', expected=(200, 401))
        if status == 401:
            account = json.loads((STATE / 'state.json').read_text())['probe']
            if account['user_id'] != value['user_id']:
                raise RuntimeError('Cleanup account no longer matches fixture owner')
            client, actor = acquire_session(value, account, purpose='cleanup')
        if actor['user']['id'] != value['user_id']:
            raise RuntimeError('Cleanup session does not own fixture')

        def restore_profile():
            _, profile, _ = client.call('GET', '/api/v1/users/me')
            current = profile['profile']
            if current['user_id'] != value['user_id']:
                raise RuntimeError('Refusing to overwrite foreign profile')
            if current['display_name'] == value['original_profile_name']:
                return
            if current['display_name'] != value['profile_name']:
                raise RuntimeError('Profile changed outside this fixture; refusing overwrite')
            client.call('PATCH', '/api/v1/users/me', {'display_name': value['original_profile_name']})
            _, after, _ = client.call('GET', '/api/v1/users/me')
            if after['profile']['display_name'] != value['original_profile_name']:
                raise RuntimeError('Original profile not restored')
        attempt('profile_restored', restore_profile)

        def revoke_owned():
            _, active, _ = client.call('GET', '/api/v1/auth/sessions')
            active_ids = {row['session_id'] for row in active}
            failures = []
            for session_id in [value.get('session_id'), *value.get('cleanup_session_ids', [])]:
                # Current cleanup session is revoked last, after all other requests.
                if session_id and session_id != actor['session_id'] and session_id in active_ids:
                    try:
                        client.call('DELETE', '/api/v1/auth/sessions/' + str(uuid.UUID(session_id)))
                    except Exception as error:
                        failures.append(type(error).__name__)
            try:
                client.call('POST', '/api/v1/auth/logout', {}, expected=(200, 401))
                client.call('GET', '/api/v1/auth/me', expected=(401,))
            except Exception as error:
                failures.append(type(error).__name__)
            if failures:
                raise RuntimeError('Some owned sessions could not be revoked: ' + ', '.join(failures))
        # Never persist an overall revocation flag: a retry may need a new cleanup session.
        try:
            revoke_owned()
        except Exception as error:
            errors.append('owned_sessions_revoked:' + type(error).__name__)
    except Exception as error:
        errors.append('cleanup_authentication:' + type(error).__name__)
    if any(item['state'] == 'intent' for item in value.get('acquisitions', [])):
        errors.append('session_acquisition_outcome_unknown: retained intent requires explicit reconciliation')
    if errors:
        raise RuntimeError('Owned cleanup incomplete; private marker retained: ' + ', '.join(errors))
    if not done.get('database_removed') or not done.get('profile_restored'):
        raise RuntimeError('Owned cleanup incomplete; private marker retained')
    state_path().unlink()
    print('Removed only owned database/sessions; original profile restored')


def readiness(run_id=None):
    cli.check()
    nodes = json.loads(cli.run(['kubectl', '--context', cli.CONTEXT, 'get', 'nodes', '-o', 'json'], timeout=15).stdout)['items']
    expected = {'k3d-sso-remediation-server-' + str(index) for index in range(3)}
    if {node['metadata']['name'] for node in nodes} != expected:
        raise RuntimeError('Expected exactly three isolated control-plane nodes')
    for node in nodes:
        if node.get('metadata', {}).get('deletionTimestamp') or not any(condition['type'] == 'Ready' and condition['status'] == 'True' for condition in node['status'].get('conditions', [])):
            raise RuntimeError('Control-plane node is not Ready')
    operator = json.loads(cli.run(['kubectl', '--context', cli.CONTEXT, '-n', 'cnpg-system', 'get', 'deployment', 'cnpg-controller-manager', '-o', 'json'], timeout=15).stdout)
    desired = operator['spec']['replicas']
    status = operator.get('status', {})
    if desired < 1 or status.get('observedGeneration', 0) < operator['metadata']['generation'] or any(status.get(field, 0) != desired for field in ('updatedReplicas', 'availableReplicas', 'readyReplicas')):
        raise RuntimeError('CNPG operator is not current and fully Ready')
    checks = {}
    for name in sorted(expected):
        # The image's kubectl multicall applet takes kubectl arguments directly.
        # Explicit kubeconfig and loopback server avoid ambient context/load-balancer.
        result = cli.run(['docker', 'exec', name, 'kubectl', '--kubeconfig=/etc/rancher/k3s/k3s.yaml', '--server=https://127.0.0.1:6443', 'get', '--raw', '/readyz?verbose'], timeout=15)
        report = result.stdout.decode()
        if 'readyz check passed' not in report or '[+]etcd ok' not in report or '[-]' in report:
            raise RuntimeError('Per-node API/etcd readiness failed')
        checks[name] = report.strip().splitlines()
    atomic_json(STATE / 'host-fault-readiness.json', {
        'run_id': run_id, 'verified_at': time.time(), 'ready_nodes': sorted(expected),
        'operator_desired_replicas': desired, 'operator_ready_replicas': status['readyReplicas'],
        'per_node_readyz': checks, 'application_controllers_and_broker_quorum_ready': True,
    })
    print('PASS all nodes, per-node API/etcd readyz, CNPG operator and application/quorum readiness')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('prepare', 'verify', 'cleanup', 'readiness'))
    parser.add_argument('--run-id')
    args = parser.parse_args()
    if ROOT != EXPECTED_ROOT:
        parser.error('Host fixture restricted to the isolated acceptance workspace')
    if args.run_id is not None and not re.fullmatch(r'[0-9a-f]{32}', args.run_id):
        parser.error('run-id must be a lowercase UUID hex string')
    {'prepare': prepare, 'verify': verify, 'cleanup': cleanup, 'readiness': readiness}[args.mode](args.run_id)
