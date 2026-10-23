#!/usr/bin/env python3
"""Real Kafka inbox/delivery/poison acceptance on isolated local cluster.

Duplicates public events only; no production access or direct SMTP simulation.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import time
import uuid

from e2e import eventually


def kubectl(args, *command, data=None, timeout=60):
    result = subprocess.run(['kubectl', '--context', args.context, '-n', args.namespace, *command],
                            input=data, text=True, capture_output=True, timeout=timeout)
    assert result.returncode == 0, f'kubectl {command[0]} failed: {result.stderr[:400]}'
    return result.stdout


def sql(args, database, query):
    return kubectl(args, 'exec', args.postgres_pod, '--', 'psql', '-U', args.postgres_user,
                   '-d', database, '-At', '-v', 'ON_ERROR_STOP=1', '-c', query).strip()


def publish(args, payload, key, owned=False):
    command = ['exec', '-i', args.broker_pod, '--', 'rpk', 'topic', 'produce', 'identity.events.v1', '-X', 'brokers=' + args.broker, '--key', key]
    if owned:
        command += ['--output-format', '{"partition":%p,"offset":%o}\\n']
    result = kubectl(args, *command, data=payload + '\n')
    return json.loads(result) if owned else result


def create_event(user_id):
    event_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    event = {'schema_version': 1, 'event_id': event_id, 'event_type': 'identity.user_logged_in',
             'aggregate_id': user_id, 'occurred_at': timestamp,
             'traceparent': '00-' + uuid.uuid4().hex + '-' + uuid.uuid4().hex[:16] + '-01',
             'payload': {'user_id': user_id, 'session_id': str(uuid.uuid4()), 'ip_address': '127.0.0.1',
                         'user_agent': 'Real-Kafka-Acceptance', 'device_name': 'Disposable reliability probe',
                         'logged_in_at': timestamp}}
    return event_id, json.dumps(event, separators=(',', ':'))


def notification_caught_up(args):
    observed = kubectl(args, 'exec', args.broker_pod, '--', 'rpk', 'group', 'describe',
                       'notification-v1', '-X', 'brokers=' + args.broker)
    for line in observed.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0] == 'TOTAL-LAG':
            return fields[1] == '0'
    raise AssertionError('Consumer lag evidence unavailable')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--context', default='k3d-sso-remediation')
    parser.add_argument('--namespace', default='sso-remediation')
    parser.add_argument('--state', required=True)
    parser.add_argument('--postgres-pod')
    parser.add_argument('--postgres-user', default='postgres')
    parser.add_argument('--broker-pod', default='redpanda-0')
    parser.add_argument('--broker', default='redpanda-0.redpanda:29092')
    parser.add_argument('--smtp-fault', action='store_true')
    args = parser.parse_args()
    if args.context != 'k3d-sso-remediation' or args.namespace != 'sso-remediation':
        parser.error('Only isolated local remediation environment is allowed')
    if not args.postgres_pod:
        args.postgres_pod = kubectl(args, 'get', 'cluster.postgresql.cnpg.io', 'postgres', '-o', 'jsonpath={.status.currentPrimary}').strip()
    account = json.loads(Path(args.state).read_text())['probe']
    user_id = str(uuid.UUID(account['user_id']))
    event_id, encoded = create_event(user_id)
    smtp_replicas = None
    try:
        if args.smtp_fault:
            smtp_replicas = int(kubectl(args, 'get', 'deployment', 'mailpit', '-o', 'jsonpath={.spec.replicas}'))
            kubectl(args, 'scale', 'deployment/mailpit', '--replicas=0')
            eventually('actual SMTP pods unavailable', lambda: not json.loads(kubectl(args, 'get', 'pods', '-l', 'app=mailpit', '-o', 'json'))['items'], 60)
        publish(args, encoded, user_id)
        publish(args, encoded, user_id)
        def persisted():
            return sql(args, 'notification_db', f"SELECT count(*) FROM delivery_jobs WHERE event_id='{event_id}'") == '1'
        eventually('real duplicate event produces one delivery job', persisted)
        assert sql(args, 'notification_db', f"SELECT count(*) FROM inbox WHERE event_id='{event_id}'") == '1'
        if args.smtp_fault:
            def retried():
                return sql(args, 'notification_db', f"SELECT count(*) FROM delivery_jobs WHERE event_id='{event_id}' AND attempts>=1 AND status='retry'") == '1'
            eventually('SMTP outage persists retry rather than dropping event', retried, 90)
            kubectl(args, 'scale', 'deployment/mailpit', '--replicas=' + str(smtp_replicas))
            kubectl(args, 'rollout', 'status', 'deployment/mailpit', '--timeout=90s', timeout=100)
            smtp_replicas = None
        eventually('actual SMTP job delivered', lambda: sql(args, 'notification_db', f"SELECT count(*) FROM delivery_jobs WHERE event_id='{event_id}' AND status='sent'") == '1', 120)
        eventually('notification group commits both duplicate records', lambda: notification_caught_up(args), 60)
        assert sql(args, 'notification_db', f"SELECT count(*) FROM delivery_jobs WHERE event_id='{event_id}'") == '1'
        attempts = sql(args, 'notification_db', f"SELECT attempts FROM delivery_jobs WHERE event_id='{event_id}'")
        assert int(attempts) >= (2 if args.smtp_fault else 1)
        print('PASS duplicate Kafka event -> one durable inbox and job; real SMTP ' + ('failure/retry/recovery' if args.smtp_fault else 'delivery'))
        poison_run = str(uuid.uuid4())
        produced = publish(args, '{"schema_version":999,"acceptance_run":"' + poison_run + '","broken":', user_id, owned=True)
        if isinstance(produced, list):
            assert len(produced) == 1
            produced = produced[0]
        partition = int(produced['partition']); offset = int(produced['offset'])
        def owned_quarantine():
            result = sql(args, 'notification_db', f"SELECT id FROM quarantine WHERE topic='identity.events.v1' AND partition_id={partition} AND offset_id={offset}")
            return str(uuid.UUID(result)) if result else None
        quarantine_id = eventually('exact produced malformed record quarantined', owned_quarantine)
        from fixtures import save_poison
        save_poison({'run_id': poison_run, 'quarantine_id': quarantine_id, 'topic': 'identity.events.v1', 'partition': partition, 'offset': offset})
        following_id, following = create_event(user_id)
        publish(args, following, user_id)
        eventually('valid event following poison still delivered', lambda: sql(args, 'notification_db',
                   f"SELECT count(*) FROM delivery_jobs WHERE event_id='{following_id}' AND status='sent'") == '1', 120)
        eventually('consumer commits beyond quarantined poison', lambda: notification_caught_up(args), 60)
        print('PASS malformed Kafka event quarantined and following valid event delivered')
    finally:
        if smtp_replicas is not None:
            kubectl(args, 'scale', 'deployment/mailpit', '--replicas=' + str(smtp_replicas))


if __name__ == '__main__':
    main()
