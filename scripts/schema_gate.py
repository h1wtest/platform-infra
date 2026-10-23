"""Actual identity process: empty schema must be live but not ready; migrations unlock readiness."""
import json
import subprocess
import time
import uuid
import cli
import manifests
import env_secrets


def verify():
    suffix = uuid.uuid4().hex[:10]
    database = 'schema_gate_' + suffix
    name = 'schema-gate-' + suffix
    image = cli.load_images()['identity']
    values = env_secrets.load(cli.STATE)
    cli.dbsql(f'CREATE DATABASE {database} OWNER identity_migration; GRANT CONNECT ON DATABASE {database} TO identity_runtime;')
    forward = None
    try:
        cli.dbsql('REVOKE CREATE ON SCHEMA public FROM PUBLIC; GRANT ALL ON SCHEMA public TO identity_migration; CREATE EXTENSION IF NOT EXISTS "uuid-ossp"; ALTER DEFAULT PRIVILEGES FOR ROLE identity_migration IN SCHEMA public GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO identity_runtime; ALTER DEFAULT PRIVILEGES FOR ROLE identity_migration IN SCHEMA public GRANT USAGE,SELECT ON SEQUENCES TO identity_runtime;', database)
        runtime = manifests.database_url('identity_runtime', values['identity_runtime_password'], database)
        migration = manifests.database_url('identity_migration', values['identity_migration_password'], database)
        cli.apply([manifests.secret(name, {'runtime': runtime, 'migration': migration})])
        deployment = next(r for r in manifests.applications(cli.load_images(), cli.STATE) if r['kind'] == 'Deployment' and r['metadata']['name'] == 'identity-service')
        deployment['metadata']['name'] = name
        deployment['spec']['replicas'] = 1
        spec = deployment['spec']['template']['spec']
        for entry in spec['containers'][0]['env']:
            if entry['name'] == 'DATABASE_URL':
                entry['valueFrom']['secretKeyRef'] = {'name': name, 'key': 'runtime'}
        deployment['spec']['selector']['matchLabels'] = {'app': name}
        deployment['spec']['template']['metadata']['labels'] = {'app': name}
        policy = manifests.resource('NetworkPolicy', name, {'podSelector': {'matchLabels': {'app': name}}, 'policyTypes': ['Egress'], 'egress': [{'to': [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': cli.NS}}, 'podSelector': {'matchLabels': {'cnpg.io/cluster': 'postgres'}}}], 'ports': [{'port': 5432}]}]})
        database_ingress = manifests.resource('NetworkPolicy', name + '-database', {'podSelector': {'matchLabels': {'cnpg.io/cluster': 'postgres'}}, 'policyTypes': ['Ingress'], 'ingress': [{'from': [{'podSelector': {'matchLabels': {'app': name}}}], 'ports': [{'port': 5432}]}]})
        cli.apply([deployment, policy, database_ingress])
        deadline = time.monotonic() + 120
        pod_name = None
        while time.monotonic() < deadline:
            pods = json.loads(cli.kube('get', 'pods', '-l', 'app=' + name, '-o', 'json').stdout)['items']
            if pods and pods[0]['status'].get('phase') == 'Running':
                pod_name = pods[0]['metadata']['name']; break
            time.sleep(2)
        if not pod_name:
            raise RuntimeError('Schema probe process never started')
        forward = subprocess.Popen(['kubectl', '--context', cli.CONTEXT, '-n', cli.NS, 'port-forward', '--address=127.0.0.1', 'pod/' + pod_name, '18001:8001'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        def status(path):
            result = cli.run(['curl', '--silent', '--show-error', '--max-time', '3', '--noproxy', '*', '--resolve', 'identity-service:18001:127.0.0.1', '--cacert', cli.STATE / 'ca.crt', '-o', '/dev/null', '-w', '%{http_code}', 'https://identity-service:18001' + path], check=False)
            return result.stdout.decode().strip() if result.returncode == 0 else '000'
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and status('/health/live') != '200':
            time.sleep(1)
        if status('/health/live') != '200' or status('/health/ready') != '503':
            raise RuntimeError('Missing schema must produce live=200, ready=503')
        migration_spec = manifests.pod('identity-service', image, env={'DATABASE_URL': (name, 'migration'), 'MFA_ENCRYPTION_KEY': ('platform-secrets', 'mfa_encryption_key')}, args=['migrate'])
        migration_spec['restartPolicy'] = 'Never'
        migration_spec['volumes'].append({'name': 'postgres-ca', 'secret': {'secretName': 'postgres-ca'}})
        migration_spec['containers'][0]['volumeMounts'].append({'name': 'postgres-ca', 'mountPath': '/run/postgres', 'readOnly': True})
        from database_gate import attach
        attach(migration_spec, cli.load_images())
        cli.apply([manifests.resource('Job', name, {'backoffLimit': 0, 'activeDeadlineSeconds': 120, 'template': {'metadata': {'labels': {'app': 'identity-service'}}, 'spec': migration_spec}})])
        cli.kube('wait', '--for=condition=complete', 'job/' + name, '--timeout=150s')
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and status('/health/ready') != '200':
            time.sleep(1)
        if status('/health/ready') != '200':
            raise RuntimeError('Identity did not become Ready after real migration')
        print('Observed empty schema live200/ready503, then real migration and ready200.')
    finally:
        if forward:
            forward.terminate(); forward.wait(timeout=10)
        cli.kube('delete', 'deployment,job,secret', name, '--ignore-not-found=true', '--wait=true', '--timeout=90s')
        cli.kube('delete', 'networkpolicy', name, name + '-database', '--ignore-not-found=true')
        cli.dbsql(f'DROP DATABASE {database}')
