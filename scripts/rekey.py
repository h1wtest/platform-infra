"""Explicit fail-closed shared-key cutover; immutable owner jobs rewrap ciphertext transactionally."""
import base64
import json
import os
from pathlib import Path
import secrets
import time
import uuid
import manifests
import env_secrets


def execute(runtime, unused=False):
    legacy = runtime.STATE / 'secrets.json'
    legacy_unused = unused and legacy.is_file() and not (runtime.STATE / env_secrets.MARKER).exists()
    if legacy_unused:
        values = env_secrets.read_legacy(runtime.STATE)
    else:
        if legacy.is_file():
            env_secrets.migrate(runtime.STATE)
        values = env_secrets.load(runtime.STATE)
    if 'encryption_key' not in values:
        raise RuntimeError('No legacy shared key; rekey is not required')
    context = runtime.run(['kubectl', 'config', 'get-contexts', '-o', 'name']).stdout.decode().splitlines()
    if unused:
        if runtime.CONTEXT in context:
            # A newly created cluster is safe only when no namespace/storage/app resource ever owns ciphertext.
            namespace = runtime.kube('get', 'namespace', runtime.NS, '--ignore-not-found=true', '-o', 'json').stdout.strip()
            volumes = json.loads(runtime.kube('get', 'persistentvolumes', '-o', 'json').stdout)['items']
            if namespace or any(v.get('spec', {}).get('claimRef', {}).get('namespace') == runtime.NS for v in volumes):
                raise RuntimeError('Isolated namespace or retained data volume exists; unused-key cutover refused')
        else:
            clusters = json.loads(runtime.run(['k3d', 'cluster', 'list', '-o', 'json']).stdout)
            if any(cluster['name'] == runtime.CLUSTER for cluster in clusters):
                raise RuntimeError('Cluster exists without expected context; cannot prove empty bootstrap')
        if legacy_unused:
            # Only proven unused historical bootstrap may create material that never existed.
            generated = {*env_secrets.PURPOSE_KEYS, 'gateway_token',
                         *(key for key in env_secrets.REQUIRED_KEYS if key.startswith('kafka_'))}
            for key in env_secrets.REQUIRED_KEYS:
                if key not in generated and not values.get(key):
                    raise RuntimeError('Missing original legacy credential: ' + key.upper())
            for relative in ('ca.key', 'ca.crt', 'tls.key', 'tls.crt', 'signing.pem', 'backup.key'):
                if not (runtime.STATE / relative).is_file() or not (runtime.STATE / relative).read_bytes():
                    raise RuntimeError('Missing original legacy private/certificate material: ' + relative)
            from security_material import SERVICES, ensure
            for service in SERVICES:
                directory = runtime.STATE / 'certificates' / service
                if (directory / 'tls.key').exists() and not (directory / 'tls.crt').exists():
                    raise RuntimeError('Incomplete historical service identity; restore matching certificate before retry')
            completed = dict(values)
            completed.pop('encryption_key')
            if 'gateway_token' not in completed:
                completed['gateway_token'] = secrets.token_urlsafe(32)
            ensure(runtime.STATE, completed, runtime.run, initialize=True)
            completed['encryption_key'] = values['encryption_key']
            # Keep the full legacy source until verified owner-env import commits.
            from private_files import atomic_json
            atomic_json(legacy, completed)
            env_secrets.migrate(runtime.STATE)
            values = env_secrets.load(runtime.STATE)
        archived = runtime.STATE / ('unused-legacy-key-' + uuid.uuid4().hex + '.json')
        from private_files import preserve_key_manifest
        for key in env_secrets.PURPOSE_KEYS:
            if key not in values:
                values[key] = base64.b64encode(secrets.token_bytes(32)).decode()
        preserve_key_manifest(runtime.STATE, values, name=archived.name)
        values.pop('encryption_key'); env_secrets.save(runtime.STATE, values)
        runtime.create_secrets(runtime.STATE)
        print('Explicitly unused legacy key archived after proving no namespace or retained data; purpose keys retained/generated.')
        return
    if runtime.CONTEXT not in context:
        raise RuntimeError('No isolated cluster: use explicit rekey --unused only for unused bootstrap credentials')
    from helm_release import prepare_rekey, publish_rekey
    publication = prepare_rekey(runtime, values)
    # Kafka historical encrypted commands cannot be rewritten in place. Refuse until retention removes all old records.
    topics = runtime.kube('exec', 'redpanda-0', '--', 'rpk', '-X', 'brokers=localhost:29092', 'topic', 'describe', 'notification.commands.v1', '-p', '--format', 'json').stdout
    partitions = json.loads(topics)
    if isinstance(partitions, dict): partitions = partitions.get('partitions', [])
    if not isinstance(partitions, list) or len(partitions) != 6:
        raise RuntimeError('Cannot verify all six legacy Kafka partition offsets')
    for partition in partitions:
        start = partition.get('start_offset', partition.get('log_start_offset'))
        end = partition.get('high_watermark', partition.get('last_stable_offset'))
        if start is None or end is None or int(start) != int(end):
            raise RuntimeError('Legacy encrypted commands remain in Kafka. Drain delivery jobs with old runtime, wait configured retention, and retry; no topic truncation is allowed.')
    group_data = json.loads(runtime.kube('exec', 'redpanda-0', '--', 'rpk', '-X', 'brokers=localhost:29092', 'group', 'describe', 'notification-v1', '--format', 'json').stdout)
    group_records = group_data.get('partitions', []) if isinstance(group_data, dict) else group_data
    command_offsets = [record for record in group_records if record.get('topic') == 'notification.commands.v1']
    if len(command_offsets) != 6 or any(record.get('current_offset') is None or record.get('log_end_offset') is None or int(record['current_offset']) != int(record['log_end_offset']) for record in command_offsets):
        raise RuntimeError('All six legacy notification consumer committed offsets must equal broker ends before cutover')
    pending_jobs = runtime.dbsql("SELECT count(*) FROM delivery_jobs WHERE status IN ('pending','retry','leased')", 'notification_db')
    if pending_jobs != '0':
        raise RuntimeError('Legacy notification jobs must drain to terminal states before key migration; no ciphertext is dropped')
    pending_outbox = runtime.dbsql('SELECT count(*) FROM outbox_events WHERE NOT is_processed', 'identity_db')
    if pending_outbox != '0':
        raise RuntimeError('Legacy identity outbox must drain before broker retention/key cutover')
    original_replicas = {}
    for name in manifests.APPS:
        deployment = json.loads(runtime.kube('get', 'deployment', name, '-o', 'json').stdout)
        original_replicas[name] = deployment['spec']['replicas']
        if name != 'notification-worker':
            runtime.kube('delete', 'hpa', name, '--ignore-not-found=true')
        runtime.kube('scale', 'deployment/' + name, '--replicas=0')
    for name in manifests.APPS:
        runtime.kube('wait', '--for=delete', 'pod', '-l', 'app=' + name, '--timeout=120s')
    if runtime.dbsql('SELECT count(*) FROM outbox_events WHERE NOT is_processed', 'identity_db') != '0' or runtime.dbsql("SELECT count(*) FROM delivery_jobs WHERE status IN ('pending','retry','leased')", 'notification_db') != '0':
        raise RuntimeError('New legacy work appeared before write fence; runtimes remain stopped for explicit recovery')
    final_partitions = json.loads(runtime.kube('exec', 'redpanda-0', '--', 'rpk', '-X', 'brokers=localhost:29092', 'topic', 'describe', 'notification.commands.v1', '-p', '--format', 'json').stdout)
    if final_partitions != json.loads(topics):
        raise RuntimeError('Sensitive broker offsets changed before runtime fence; legacy key retained and writers stopped')
    runtime.backup()
    for key in ('mfa_encryption_key', 'delivery_encryption_key', 'profile_quarantine_key', 'notification_quarantine_key', 'admin_quarantine_key'):
        if key not in values: values[key] = base64.b64encode(secrets.token_bytes(32)).decode()
    from private_files import preserve_key_manifest
    preserve_key_manifest(runtime.STATE, values, name='rekey-precommit-' + uuid.uuid4().hex + '.json')
    env_secrets.save(runtime.STATE, values)
    # Keep legacy material on disk and runtime stopped on any failure; each owner transaction is idempotent.
    runtime.apply([manifests.secret('rekey-material', values)])
    images = runtime.load_images()
    for name, (target, _, db) in manifests.APPS.items():
        if target == 'worker': continue
        env = {'DATABASE_URL': (db + '-database', 'MIGRATION_DATABASE_URL'), 'LEGACY_ENCRYPTION_KEY': ('rekey-material', 'encryption_key')}
        if target == 'identity':
            env.update({'MFA_ENCRYPTION_KEY': ('rekey-material', 'mfa_encryption_key'), 'DELIVERY_ENCRYPTION_KEY': ('rekey-material', 'delivery_encryption_key')})
        else:
            env['QUARANTINE_ENCRYPTION_KEY'] = ('rekey-material', target + '_quarantine_key')
            if target == 'notification': env['DELIVERY_ENCRYPTION_KEY'] = ('rekey-material', 'delivery_encryption_key')
        spec = manifests.pod(name, images[target], env=env, args=['rekey'], volumes=[{'name': 'postgres-ca', 'secret': {'secretName': 'postgres-ca'}}], mounts=[{'name': 'postgres-ca', 'mountPath': '/run/postgres', 'readOnly': True}])
        spec['restartPolicy'] = 'Never'
        from database_gate import attach
        attach(spec, images)
        job = 'rekey-' + target + '-' + uuid.uuid4().hex[:8]
        runtime.apply([manifests.resource('Job', job, {'backoffLimit': 0, 'activeDeadlineSeconds': 300, 'template': {'metadata': {'labels': {'app': name}}, 'spec': spec}})])
        runtime.kube('wait', '--for=condition=complete', 'job/' + job, '--timeout=330s')
    archive = runtime.STATE / ('rekey-complete-' + uuid.uuid4().hex + '.json')
    preserve_key_manifest(runtime.STATE, values, name=archive.name)
    final_values = dict(values)
    final_values.pop('encryption_key')
    # Writers remain stopped. Publish only after every owner committed, retaining
    # legacy + targets in env/archive until publication succeeds for safe retry.
    publish_rekey(runtime, publication, final_values)
    env_secrets.save(runtime.STATE, final_values)
    runtime.kube('delete', 'secret', 'rekey-material')
    print('All owner ciphertext rekeys committed. Runtime remains stopped; run make up to migrate/apply purpose-separated configuration and resume.')
