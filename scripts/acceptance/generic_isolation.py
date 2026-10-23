#!/usr/bin/env python3
"""Exercise actual generic-owner DSNs, Kafka ACLs, TLS and NetworkPolicy.

Parent-run only. Every kubectl call uses the explicit private kubeconfig/context
and generic namespace. Credentials remain in memory/stdin, never argv or output.
Only uniquely labelled probe pods are deleted; acknowledged poison records and
consumer quarantine remain as durable, harmless acceptance evidence.
"""
from __future__ import annotations

import argparse
import base64
import hmac
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time
from urllib.parse import parse_qs, unquote, urlsplit
import uuid

INFRA = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(INFRA / 'scripts'))
import broker_security
import cluster_identity
import env_secrets

NS = 'generic-subscriptions'
CONTEXT = 'k3d-sso-remediation'
LABEL = 'acceptance.generic/isolation-run'
OWNERS = {
    'identity': ('identity-service', 'users', 8001),
    'profile': ('profile-service', 'profiles', 8002),
    'notification': ('notification-service', 'delivery_jobs', 8003),
    'audit': ('admin-audit-service', 'audit_events', 8004),
    'catalog': ('catalog-service', 'catalog_products', 8006),
    'billing': ('billing-service', 'billing_orders', 8007),
    'subscription': ('subscription-service', 'subscriptions', 8008),
    'referral': ('referral-service', 'referral_accounts', 8009),
}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def private_file(path):
    require(path.is_file() and not path.is_symlink(), 'private regular input file required')
    require(os.name == 'nt' or path.stat().st_mode & 0o077 == 0,
            'private input permissions must exclude group/other')


class Acceptance:
    def __init__(self, args):
        self.args = args
        self.run_id = uuid.uuid4().hex
        self.base = ['kubectl', '--kubeconfig', str(args.kubeconfig), '--context', CONTEXT,
                     '--namespace', NS, '--request-timeout=20s']
        self.created = []
        self.secret_cache = {}
        self.db_probes = {}
        self.dsns = {}
        self.markers = []
        self.checks = []
        self.ca = args.ca.read_bytes()
        self.environment = {key: value for key, value in os.environ.items()
                            if key in ('PATH', 'HOME', 'SYSTEMROOT', 'WINDIR', 'TMPDIR', 'TEMP', 'TMP')}

    def kube(self, *command, data=None, timeout=60, check=True):
        try:
            result = subprocess.run(self.base + list(command), input=data, text=True,
                                    capture_output=True, timeout=timeout, env=self.environment)
        except (OSError, subprocess.TimeoutExpired):
            raise RuntimeError('isolated kubectl command unavailable or timed out (output withheld)') from None
        if check:
            require(result.returncode == 0, 'isolated kubectl command failed (output withheld)')
        return result

    def get(self, kind, name=None, selector=None):
        command = ['get', kind]
        if name:
            command.append(name)
        if selector:
            command += ['-l', selector]
        return json.loads(self.kube(*command, '-o', 'json').stdout)

    def secret(self, name):
        if name not in self.secret_cache:
            data = self.get('secret', name).get('data', {})
            self.secret_cache[name] = {key: base64.b64decode(value, validate=True).decode()
                                       for key, value in data.items()}
        return self.secret_cache[name]

    def guard(self):
        config = json.loads(self.kube('config', 'view', '--raw', '--minify', '-o', 'json').stdout)
        require(len(config.get('clusters', [])) == 1 and len(config.get('contexts', [])) == 1,
                'one explicit local cluster/context required')
        cluster = config['clusters'][0]['cluster']
        server = urlsplit(cluster.get('server', ''))
        require(server.scheme == 'https' and server.hostname in ('127.0.0.1', 'localhost', '::1')
                and not server.username and not server.password and server.path in ('', '/')
                and not server.query and not server.fragment
                and not cluster.get('insecure-skip-tls-verify') and not cluster.get('proxy-url')
                and bool(cluster.get('certificate-authority-data') or cluster.get('certificate-authority')),
                'private kubeconfig must verify an explicit direct loopback cluster without proxy override')
        require(config['contexts'][0]['name'] == CONTEXT,
                'unexpected isolated cluster context')
        for user in config.get('users', []):
            require(not any(key in user.get('user', {}) for key in ('exec', 'auth-provider')),
                    'external/cloud kubeconfig credential plugins are forbidden')
        # Reuse the canonical snapshot/integrity contract without cli's ambient
        # kubeconfig or any original .local/Docker state. These are read-only API
        # queries over the already validated explicit task-private transport.
        baseline = self.args.state / 'namespace-identity.json'
        private_file(baseline)
        require(os.name == 'nt' or baseline.stat().st_mode & 0o377 == 0,
                'generic namespace baseline must be private read-only')
        envelope = json.loads(baseline.read_text(encoding='utf-8'))
        require(isinstance(envelope, dict) and isinstance(envelope.get('identity'), dict)
                and isinstance(envelope.get('sha256'), str)
                and hmac.compare_digest(envelope['sha256'], cluster_identity.digest(envelope['identity'])),
                'generic namespace baseline integrity mismatch')
        namespace = self.get('namespace', NS)
        api_cluster = self.get('namespace', 'kube-system')
        actual = cluster_identity.namespace_snapshot(
            CONTEXT, cluster['server'], api_cluster['metadata']['uid'], namespace)
        cluster_identity.validate_namespace(envelope['identity'], actual)
        self.checks.append('saved_generic_namespace_uid_api_cluster_baseline')
        for owner in ('platform-infra', 'identity-service', 'user-notification-service',
                      'catalog-service', 'billing-service', 'subscription-service', 'referral-service'):
            directory = self.args.state / 'owners' / owner
            require(not directory.is_symlink(), 'isolated owner credential directory must be regular')
            private_file(directory / '.env')
        env_secrets.configure(generic=True)
        self.values = env_secrets.load(self.args.state)
        require(self.secret('platform-ca').get('ca.crt', '').encode() == self.ca,
                'explicit CA differs from actual namespace owner trust root')
        self.checks.append('explicit_private_loopback_kubeconfig_generic_namespace')

    def resolve_env(self, container):
        resolved = {}
        for source in container.get('envFrom', []):
            require('secretRef' not in source, 'runtime must not import broad secret environments')
            if 'configMapRef' in source:
                data = self.get('configmap', source['configMapRef']['name']).get('data', {})
                resolved.update({source.get('prefix', '') + key: value for key, value in data.items()})
        for entry in container.get('env', []):
            if 'value' in entry:
                resolved[entry['name']] = entry['value']
            elif 'secretKeyRef' in entry.get('valueFrom', {}):
                ref = entry['valueFrom']['secretKeyRef']
                require('migration' not in ref['key'].lower() and ref['name'] != 'database-superuser',
                        'runtime references migration/superuser credentials')
                resolved[entry['name']] = self.secret(ref['name'])[ref['key']]
            elif 'configMapKeyRef' in entry.get('valueFrom', {}):
                ref = entry['valueFrom']['configMapKeyRef']
                resolved[entry['name']] = self.get('configmap', ref['name'])['data'][ref['key']]
        return resolved

    def runtime_identity(self):
        migration_values = [self.values[owner + '_migration_password'] for owner in OWNERS]
        self.app_envs = {}
        self.non_runtime_pods = []
        for owner, (app, _, _) in [*OWNERS.items(),
                                  ('notification', ('notification-worker', 'delivery_jobs', 8005))]:
            deployment = self.get('deployment', app)
            template = deployment['spec']['template']['spec']
            deployment_uid = deployment['metadata']['uid']
            replica_sets = self.get('replicasets')['items']
            owned_sets = {replica['metadata']['uid'] for replica in replica_sets
                          if any(reference.get('controller') is True
                                 and reference.get('kind') == 'Deployment'
                                 and reference.get('uid') == deployment_uid
                                 for reference in replica['metadata'].get('ownerReferences', []))}
            require(owned_sets, app + ': no Deployment-owned ReplicaSets')
            pods = []
            # Labels are policy/routing metadata, not runtime ownership. Migration
            # Jobs deliberately share app labels but must not impersonate replicas.
            for pod in self.get('pods')['items']:
                metadata = pod['metadata']
                references = metadata.get('ownerReferences', [])
                owned = any(reference.get('controller') is True
                            and reference.get('kind') == 'ReplicaSet'
                            and reference.get('uid') in owned_sets for reference in references)
                if not owned:
                    if metadata.get('labels', {}).get('app') == app:
                        self.non_runtime_pods.append({
                            'app': app, 'pod': metadata['name'],
                            'phase': pod.get('status', {}).get('phase', 'Unknown'),
                            'controller_kinds': [reference.get('kind', 'Unknown')
                                                 for reference in references if reference.get('controller') is True]})
                    continue
                if metadata.get('deletionTimestamp'):
                    continue
                require(pod.get('status', {}).get('phase') == 'Running',
                        app + ': Deployment-owned current replica is not Running')
                pods.append(pod)
            desired = deployment['spec'].get('replicas', 1)
            status = deployment.get('status', {})
            require(desired > 0 and len(pods) >= desired
                    and status.get('observedGeneration', 0) >= deployment['metadata'].get('generation', 1)
                    and status.get('updatedReplicas', 0) >= desired
                    and status.get('readyReplicas', 0) >= desired
                    and status.get('availableReplicas', 0) >= desired,
                    app + ': complete current Deployment replica readiness required')
            require(all(any(condition.get('type') == 'Ready' and condition.get('status') == 'True'
                            for condition in pod.get('status', {}).get('conditions', [])) for pod in pods),
                    app + ': an actual current runtime replica is not Ready')
            for spec in [template, *(pod['spec'] for pod in pods)]:
                require(spec.get('serviceAccountName') == app
                        and spec.get('automountServiceAccountToken') is False,
                        app + ': owner service account/token automount isolation failed')
                sa = self.get('serviceaccount', app)
                require(sa.get('automountServiceAccountToken') is False,
                        app + ': service account automount must be false')
                for volume in spec.get('volumes', []):
                    projected = volume.get('projected', {}).get('sources', [])
                    require(not any('serviceAccountToken' in source for source in projected),
                            app + ': projected service account token present')
                    mounted = [volume['secret']] if 'secret' in volume else []
                    mounted += [source['secret'] for source in projected if 'secret' in source]
                    for secret in mounted:
                        name = secret.get('secretName', secret.get('name', ''))
                        require(name not in ('platform-secrets', 'database-superuser',
                                             *(o + '-database' for o in OWNERS)),
                                app + ': runtime mounts broad database/migration secrets')
                        require(not any(value and value == credential
                                        for value in self.secret(name).values() for credential in migration_values),
                                app + ': runtime mounted migration credential')
                require(not spec.get('ephemeralContainers'), app + ': unexpected ephemeral runtime containers')
                for container in spec.get('containers', []) + spec.get('initContainers', []):
                    resolved = self.resolve_env(container)
                    require(not any('migration' in name.lower() for name in resolved),
                            app + ': migration environment present')
                    serialized = json.dumps([resolved, container.get('command', []), container.get('args', [])])
                    require(not any(value and value in serialized for value in migration_values),
                            app + ': migration credential exposed to runtime')
                    if 'DATABASE_URL' in resolved:
                        self.validate_dsn(owner, resolved['DATABASE_URL'])
                for container in spec.get('containers', []):
                    resolved = self.resolve_env(container)
                    require(resolved.get('DATABASE_URL'), app + ': runtime database DSN missing')
                    role = 'admin' if owner == 'audit' else owner
                    require(resolved.get('KAFKA_SASL_USERNAME') == role
                            and resolved.get('KAFKA_SASL_PASSWORD') == self.values['kafka_' + role + '_password'],
                            app + ': runtime Kafka principal differs from canonical owner')
                    self.dsns[owner] = resolved['DATABASE_URL']
                    self.app_envs[app] = resolved
            if app == 'notification-worker':
                continue
            self.checks.append(owner + '_actual_runtime_identity_no_migration_credentials')
        self.postgres_image = self.get('statefulset', 'postgres')['spec']['template']['spec']['containers'][0]['image']
        self.broker_image = self.get('statefulset', 'redpanda')['spec']['template']['spec']['containers'][0]['image']

    def validate_dsn(self, owner, dsn):
        url = urlsplit(dsn)
        query = parse_qs(url.query)
        require(url.scheme in ('postgres', 'postgresql')
                and url.hostname == 'postgres-rw.' + NS + '.svc' and url.port == 5432
                and unquote(url.username or '') == owner + '_runtime'
                and unquote(url.password or '') == self.values[owner + '_runtime_password']
                and unquote(url.path) == '/' + owner + '_db'
                and query.get('sslmode') == ['verify-full']
                and query.get('sslrootcert') == ['/run/postgres/ca.crt'],
                owner + ': actual DSN must use canonical runtime credentials and verified owner TLS')

    def pod(self, label, image, *, owner_sa=None, ca=False):
        name = 'isolation-' + self.run_id[:12] + '-' + str(len(self.created))
        container = {'name': 'probe', 'image': image, 'imagePullPolicy': 'IfNotPresent',
                     'command': ['/bin/sh', '-c', 'sleep 3600'],
                     # Do not join an application's Service endpoints despite policy labels.
                     'readinessProbe': {'exec': {'command': ['/bin/sh', '-c', 'exit 1']}, 'periodSeconds': 2},
                     'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True,
                                         'capabilities': {'drop': ['ALL']}},
                     'resources': {'requests': {'cpu': '5m', 'memory': '32Mi'},
                                   'limits': {'cpu': '250m', 'memory': '192Mi'}},
                     'volumeMounts': [{'name': 'tmp', 'mountPath': '/tmp'}]}
        spec = {'automountServiceAccountToken': False, 'serviceAccountName': owner_sa or 'default',
                'restartPolicy': 'Never', 'activeDeadlineSeconds': 3600, 'terminationGracePeriodSeconds': 1,
                'securityContext': {'runAsNonRoot': True, 'runAsUser': 10001, 'runAsGroup': 10001,
                                    'seccompProfile': {'type': 'RuntimeDefault'}},
                'containers': [container], 'volumes': [{'name': 'tmp', 'emptyDir': {'medium': 'Memory', 'sizeLimit': '16Mi'}}]}
        if ca:
            spec['volumes'].append({'name': 'ca', 'secret': {'secretName': 'platform-ca'}})
            container['volumeMounts'].append({'name': 'ca', 'mountPath': '/run/postgres', 'readOnly': True})
        labels = {'app': label, LABEL: self.run_id}
        # A Job controller owns the pod, preventing ReplicaSet adoption despite
        # policy labels. Failed readiness also keeps probes out of live Services.
        document = {'apiVersion': 'batch/v1', 'kind': 'Job',
                    'metadata': {'name': name, 'namespace': NS, 'labels': {LABEL: self.run_id}},
                    'spec': {'backoffLimit': 0, 'activeDeadlineSeconds': 3600,
                             'template': {'metadata': {'labels': labels}, 'spec': spec}}}
        self.created.append(name)
        self.kube('create', '-f', '-', data=json.dumps(document))
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            pods = self.get('pods', selector='job-name=' + name + ',' + LABEL + '=' + self.run_id)['items']
            if not pods:
                time.sleep(1)
                continue
            require(len(pods) == 1, 'probe Job must own exactly one pod')
            current = pods[0]
            require(current['metadata']['labels'].get(LABEL) == self.run_id, 'probe ownership changed')
            phase = current.get('status', {}).get('phase')
            statuses = current.get('status', {}).get('containerStatuses', [])
            if phase == 'Running' and statuses and all(s.get('state', {}).get('running') for s in statuses):
                return current['metadata']['name']
            require(phase not in ('Failed', 'Succeeded'), 'probe terminated before acceptance')
            time.sleep(1)
        raise RuntimeError('probe did not start (events/output withheld)')

    def shell(self, pod, script, *, timeout=45):
        return self.kube('exec', '-i', pod, '-c', 'probe', '--', '/bin/sh', '-s',
                         data='set +x\numask 077\n' + script, timeout=timeout, check=False)

    def sql(self, owner, query, *, database=None):
        url = urlsplit(self.dsns[owner])
        environment = {'PGHOST': url.hostname, 'PGPORT': '5432', 'PGUSER': unquote(url.username),
                       'PGPASSWORD': unquote(url.password), 'PGDATABASE': database or owner + '_db',
                       'PGSSLMODE': 'verify-full', 'PGSSLROOTCERT': '/run/postgres/ca.crt',
                       'PGCONNECT_TIMEOUT': '5', 'PGOPTIONS': '-c statement_timeout=5000 -c lock_timeout=2000'}
        script = ''.join('export ' + key + '=' + shlex.quote(value) + '\n' for key, value in environment.items())
        script += "psql -X -q -A -t -v ON_ERROR_STOP=1 -v VERBOSITY=verbose <<'ISOLATION_SQL'\n"
        script += query + '\nISOLATION_SQL\n'
        return self.shell(self.db_probes[owner], script)

    @staticmethod
    def sql_failure(result):
        # Match locally but emit only fixed classifications, never raw libpq
        # diagnostics (which can include connection strings or credential paths).
        diagnostic = (result.stderr + '\n' + result.stdout).lower()
        classes = (
            ('tool_unavailable', ('psql: not found', 'psql: command not found', 'executable file not found')),
            ('exec_transport', ('unable to upgrade connection', 'container not found', 'error dialing backend')),
            ('dns_resolution', ('could not translate host name', 'name or service not known', 'temporary failure in name resolution')),
            ('network_timeout', ('connection timed out', 'timeout expired', 'no route to host')),
            ('network_refused', ('connection refused',)),
            ('tls_ca_unreadable', ('root certificate file', 'could not read certificate file', 'could not open certificate file')),
            ('tls_client_identity_unreadable', ('could not open private key file', 'could not load private key file', 'could not access private key file', 'could not access certificate file')),
            ('tls_verification', ('certificate verify failed', 'does not match host name', 'server certificate', 'ssl error')),
            ('authentication', ('password authentication failed', 'no password supplied', 'no pg_hba.conf entry')),
            ('database_authorization', ('permission denied for database',)),
            ('table_authorization', ('permission denied for table', 'permission denied for schema')),
            ('schema_missing', ('relation', 'does not exist')),
            ('query_privilege', ('42501',)),
            ('sql_syntax', ('42601',)),
        )
        for classification, terms in classes:
            if any(term in diagnostic for term in terms):
                return classification
        return 'unexpected_result_shape' if result.returncode == 0 else 'unclassified_subprocess_failure'

    def databases(self):
        for owner, (app, table, _) in OWNERS.items():
            self.db_probes[owner] = self.pod(app, self.postgres_image, owner_sa=app, ca=True)
            # Running precedes asynchronous policy/service programming on a newly
            # admitted probe. Retry only positive-connect DNS/refusal failures;
            # authentication, TLS, SQL and authorization failures remain immediate.
            deadline = time.monotonic() + 60
            while True:
                result = self.sql(owner, 'SELECT current_user; SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid();'
                                  ' SELECT 1 FROM public.' + table + ' LIMIT 0;')
                if (result.returncode == 0 or self.sql_failure(result) not in
                        ('network_refused', 'dns_resolution') or time.monotonic() >= deadline):
                    break
                time.sleep(min(2, max(0, deadline - time.monotonic())))
            require(result.returncode == 0 and result.stdout.splitlines() == [owner + '_runtime', 't'],
                    owner + ': actual runtime TLS DSN cannot SELECT owned table; class='
                    + self.sql_failure(result) + '; exit=' + str(result.returncode))
            for query in ('CREATE TABLE public.isolation_' + self.run_id + '(id integer)',
                          'CREATE SCHEMA isolation_' + self.run_id,
                          'ALTER TABLE public.' + table + ' ADD COLUMN isolation_' + self.run_id + ' integer',
                          'ALTER SCHEMA public RENAME TO isolation_' + self.run_id):
                result = self.sql(owner, 'BEGIN; ' + query + '; ROLLBACK;')
                require(result.returncode != 0 and '42501' in result.stderr,
                        owner + ': DDL was not denied with insufficient_privilege')
            for foreign in OWNERS:
                if foreign == owner:
                    continue
                result = self.sql(owner, 'SELECT 1;', database=foreign + '_db')
                require(result.returncode != 0 and 'permission denied for database' in result.stderr.lower(),
                        owner + ': actual cross-owner CONNECT was not authoritatively denied')
            self.checks.append(owner + '_tls_select_create_alter_cross_database_denials')

    def kafka(self, role, arguments, *, record=None, key=None):
        # Shell stdin transports credentials; rpk inherits them in protected process
        # environment. No secret is a kubectl/rpk command argument or pod env spec.
        exports = {'RPK_USER': role, 'RPK_PASS': self.values['kafka_' + role + '_password'],
                   'RPK_SASL_MECHANISM': 'SCRAM-SHA-256', 'RPK_TLS_ENABLED': 'true',
                   'RPK_TLS_CA': '/run/postgres/ca.crt'}
        script = ''.join('export ' + name + '=' + shlex.quote(value) + '\n' for name, value in exports.items())
        command = ['rpk', '-X', 'brokers=redpanda-0.redpanda:29092,redpanda-1.redpanda:29092,redpanda-2.redpanda:29092',
                   '-X', 'tls.enabled=true', '-X', 'tls.ca=/run/postgres/ca.crt',
                   '-X', 'sasl.mechanism=SCRAM-SHA-256', *arguments]
        if key:
            command += ['--key', key]
        if record is not None:
            script += "printf '%s\\n' " + shlex.quote(record) + ' | '
        script += shlex.join(command) + '\n'
        return self.shell(self.broker_probe, script, timeout=40)

    @staticmethod
    def denied(result, resource):
        diagnostic = (result.stdout + result.stderr).upper()
        # Even a nonzero producer failure must not hide an acknowledged record.
        acknowledged = re.search(r'(?i)"(?:partition|offset)"\s*:\s*[0-9]+', result.stdout)
        return (result.returncode != 0 and resource + '_AUTHORIZATION_FAILED' in diagnostic
                and not acknowledged)

    @staticmethod
    def metadata_denied(result, resource, name):
        # rpk topic describe returns exit0 for a per-resource broker error.
        # Bind the wire authorization token to this single explicitly requested
        # public resource; mixed successful metadata and error output fails closed.
        diagnostic = result.stdout + '\n' + result.stderr
        upper = diagnostic.upper()
        if resource + '_AUTHORIZATION_FAILED' not in upper:
            return False
        if any(token in upper for token in
               ('SASL_AUTHENTICATION_FAILED', 'UNKNOWN_TOPIC_OR_PARTITION',
                'CLUSTER_AUTHORIZATION_FAILED', 'NETWORK_EXCEPTION', 'NOT_COORDINATOR',
                'COORDINATOR_NOT_AVAILABLE', 'COORDINATOR_LOAD_IN_PROGRESS', 'REQUEST_TIMED_OUT',
                'CONNECTION REFUSED', 'CONNECTION TIMED OUT', 'I/O TIMEOUT', 'NO SUCH HOST',
                'NO ROUTE TO HOST', 'CONNECTION RESET')):
            return False
        named = bool(re.search(r'(?<![A-Za-z0-9_.-])' + re.escape(name)
                               + r'(?![A-Za-z0-9_.-])', diagnostic))
        if not named:
            # Observed rpk fatal FindCoordinator denial omits the group name.
            # This branch is called only for one explicit group describe, and
            # requires no stdout/metadata, nonzero exit and the exact group error.
            if not (resource == 'GROUP' and result.returncode != 0 and not result.stdout.strip()
                    and 'GROUP_AUTHORIZATION_FAILED' in result.stderr.upper()
                    and 'TOPIC_AUTHORIZATION_FAILED' not in upper):
                return False
            if re.search(r'(?i)"(?:partition|partitions|state|members|coordinator|current_offset|log_end_offset)"\s*:', diagnostic):
                return False
            if re.search(r'(?im)^\s*(?:STATE|MEMBERS|COORDINATOR|TOPIC|PARTITION|CURRENT-OFFSET)\s+\S', diagnostic):
                return False
        if re.search(r'(?im)^\s*(?:PARTITIONS|REPLICAS)\s*[:=]?\s*[1-9][0-9]*\b', diagnostic):
            return False
        if re.search(r'(?i)"(?:partition|partitions|replicas|current_offset|log_end_offset)"\s*:\s*(?:[1-9][0-9]*|\[\s*\{)', diagnostic):
            return False
        if resource == 'GROUP' and re.search(r'(?im)^\s*STATE\s+(?:Stable|CompletingRebalance|PreparingRebalance)\b', diagnostic):
            return False
        return True

    @staticmethod
    def kafka_diagnostic(result, resource, name=None):
        # Only protocol-defined fixed tokens and process status are reportable.
        # Never return arbitrary rpk output, connection metadata or credentials.
        stdout = result.stdout.upper()
        stderr = result.stderr.upper()
        token = resource + '_AUTHORIZATION_FAILED'
        diagnostic = result.stdout + '\n' + result.stderr
        named = bool(name and re.search(r'(?<![A-Za-z0-9_.-])' + re.escape(name)
                                       + r'(?![A-Za-z0-9_.-])', diagnostic))
        success_fields = bool(re.search(r'(?im)^\s*(?:PARTITIONS|REPLICAS|STATE|MEMBERS|TOPIC|PARTITION|CURRENT-OFFSET)\s+\S', diagnostic)
                              or re.search(r'(?i)"(?:partition|partitions|replicas|current_offset|log_end_offset|state|members|coordinator)"\s*:', diagnostic))
        other_errors = [token for token in ('SASL_AUTHENTICATION_FAILED', 'UNKNOWN_TOPIC_OR_PARTITION',
                                            'TOPIC_AUTHORIZATION_FAILED', 'GROUP_AUTHORIZATION_FAILED',
                                            'CLUSTER_AUTHORIZATION_FAILED')
                        if token != resource + '_AUTHORIZATION_FAILED' and token in stdout + stderr]
        transient = [code for code in ('NETWORK_EXCEPTION', 'NOT_COORDINATOR', 'COORDINATOR_NOT_AVAILABLE',
                                       'COORDINATOR_LOAD_IN_PROGRESS', 'REQUEST_TIMED_OUT',
                                       'CONNECTION REFUSED', 'CONNECTION TIMED OUT', 'I/O TIMEOUT',
                                       'NO SUCH HOST', 'NO ROUTE TO HOST', 'CONNECTION RESET', 'EOF')
                     if code in stdout + stderr]
        return ('exit=' + str(result.returncode)
                + '; auth_stdout=' + str(token in stdout).lower()
                + '; auth_stderr=' + str(token in stderr).lower()
                + '; sasl_auth_failed=' + str('SASL_AUTHENTICATION_FAILED' in stdout + stderr).lower()
                + '; unknown_topic=' + str('UNKNOWN_TOPIC_OR_PARTITION' in stdout + stderr).lower()
                + '; named_resource=' + str(named).lower()
                + '; metadata_fields=' + str(success_fields).lower()
                + '; stdout_empty=' + str(not result.stdout.strip()).lower()
                + '; unrelated_errors=' + ','.join(other_errors)
                + '; transport_codes=' + ','.join(transient))

    def broker(self):
        self.broker_probe = self.pod('profile-service', self.broker_image, owner_sa='profile-service', ca=True)
        # Establish a genuinely authorized metadata positive control before the
        # negative ACL matrix; a new Pod may precede network-policy programming.
        deadline = time.monotonic() + 60
        while True:
            control = self.kafka('identity', ['topic', 'describe', 'identity.events.v2', '--print-summary'])
            diagnostic = (control.stdout + control.stderr).upper()
            admitted = (control.returncode == 0 and 'AUTHORIZATION_FAILED' not in diagnostic
                        and bool(re.search(r'(?im)^\s*PARTITIONS\s+[1-9][0-9]*\b', control.stdout)))
            if admitted:
                break
            transient = any(code in diagnostic for code in
                            ('NETWORK_EXCEPTION', 'NOT_COORDINATOR', 'COORDINATOR_NOT_AVAILABLE',
                             'COORDINATOR_LOAD_IN_PROGRESS', 'REQUEST_TIMED_OUT', 'CONNECTION REFUSED',
                             'CONNECTION TIMED OUT', 'I/O TIMEOUT', 'NO SUCH HOST',
                             'NO ROUTE TO HOST', 'CONNECTION RESET'))
            require(transient and 'AUTHORIZATION_FAILED' not in diagnostic
                    and 'SASL_AUTHENTICATION_FAILED' not in diagnostic and time.monotonic() < deadline,
                    'identity: broker positive admission control failed; topic=identity.events.v2; '
                    + self.kafka_diagnostic(control, 'TOPIC', 'identity.events.v2'))
            time.sleep(min(2, max(0, deadline - time.monotonic())))
        self.checks.append('actual_broker_tls_sasl_authorized_metadata_admission_control')
        rules = broker_security.owner_acls()
        topics = [topic for topic, _ in broker_security.topic_inventory(generic=True)]
        roles = ['admin' if owner == 'audit' else owner for owner in OWNERS]
        groups = sorted({resource for _, _, kind, resource in rules if kind == 'group'})
        for role in roles:
            writes = {resource for principal, operations, kind, resource in rules
                      if principal == role and kind == 'topic' and 'write' in operations.split(',')}
            describes = {resource for principal, operations, kind, resource in rules
                         if principal == role and kind == 'topic' and 'describe' in operations.split(',')}
            owned_groups = {resource for principal, operations, kind, resource in rules
                            if principal == role and kind == 'group' and 'read' in operations.split(',')}
            for topic in topics:
                result = self.kafka(role, ['topic', 'describe', topic, '--print-summary'])
                if topic in describes:
                    require(result.returncode == 0 and 'AUTHORIZATION_FAILED' not in
                            (result.stdout + result.stderr).upper(),
                            role + ': allowed topic metadata unavailable; topic=' + topic + '; '
                            + self.kafka_diagnostic(result, 'TOPIC'))
                else:
                    require(self.metadata_denied(result, 'TOPIC', topic),
                            role + ': foreign topic metadata not denied; topic='
                            + topic + '; ' + self.kafka_diagnostic(result, 'TOPIC'))
                event_id, aggregate = str(uuid.uuid4()), str(uuid.uuid4())
                # Invalid schema cannot drive business effects even if a forbidden
                # ACL is broken. UUIDs name no real user, order or subscription.
                marker = json.dumps({'schema_version': -1, 'event_id': event_id,
                                     'aggregate_id': aggregate, 'producer': 'isolation-invalid-producer',
                                     'isolation_run': self.run_id}, separators=(',', ':'))
                result = self.kafka(role, ['topic', 'produce', topic, '--acks=-1', '--delivery-timeout', '10s',
                                          '--output-format', '{"partition":%p,"offset":%o}\\n'],
                                    record=marker, key=aggregate)
                if topic not in writes:
                    # Stop immediately: do not continue after any unauthorized ack.
                    require(self.denied(result, 'TOPIC'), role + ': wrong producer not rejected by broker ACL; topic='
                            + topic + '; ' + self.kafka_diagnostic(result, 'TOPIC'))
                    continue
                require(result.returncode == 0, role + ': owned topic write not acknowledged')
                acknowledged = json.loads(result.stdout)
                require(isinstance(acknowledged, dict) and type(acknowledged.get('partition')) is int
                        and type(acknowledged.get('offset')) is int and acknowledged['partition'] >= 0
                        and acknowledged['offset'] >= 0, role + ': invalid broker acknowledgment coordinate')
                consumers = {('audit' if principal == 'admin' else principal)
                             for principal, operations, kind, resource in rules
                             if kind == 'topic' and resource == topic and 'read' in operations.split(',')}
                if consumers:
                    self.markers.append({'topic': topic, 'partition': acknowledged['partition'],
                                         'offset': acknowledged['offset'], 'event_id': event_id,
                                         'consumers': sorted(consumers)})
            for group in groups:
                result = self.kafka(role, ['group', 'describe', group, '--format', 'json'])
                if group in owned_groups:
                    require(result.returncode == 0 and 'AUTHORIZATION_FAILED' not in
                            (result.stdout + result.stderr).upper(), role + ': owned consumer group metadata unavailable')
                else:
                    require(self.metadata_denied(result, 'GROUP', group),
                            role + ': foreign consumer group not denied; group='
                            + group + '; ' + self.kafka_diagnostic(result, 'GROUP', group))
            self.checks.append(role + '_all_topic_produce_metadata_and_group_acl_matrix')
        deadline = time.monotonic() + 120
        pending = [(marker, owner) for marker in self.markers for owner in marker['consumers']]
        while pending and time.monotonic() < deadline:
            remaining = []
            for marker, owner in pending:
                topic, partition, offset = marker['topic'], marker['partition'], marker['offset']
                query = ("SELECT count(*) FROM quarantine WHERE topic='" + topic + "' AND partition_id="
                         + str(partition) + ' AND offset_id=' + str(offset)
                         + " AND length(encrypted_record)>20 AND encrypted_record NOT LIKE '%" + self.run_id + "%';"
                         + " SELECT count(*) FROM inbox WHERE event_id='" + marker['event_id'] + "';"
                         + " SELECT count(*) FROM quarantine q JOIN dlq_outbox d ON d.id=q.id WHERE q.topic='"
                         + topic + "' AND q.partition_id=" + str(partition) + ' AND q.offset_id=' + str(offset) + ';')
                result = self.sql(owner, query)
                require(result.returncode == 0, owner + ': quarantine evidence query failed')
                if result.stdout.splitlines() != ['1', '0', '1']:
                    remaining.append((marker, owner))
            pending = remaining
            if pending:
                time.sleep(2)
        require(not pending, 'allowed-topic invalid-producer markers did not reach encrypted quarantine without inbox effects')
        self.checks.append('actual_allowed_topic_poison_pipeline_encrypted_quarantine_no_inbox_effects')

    def python(self, pod, code, payload, *, timeout=90):
        return self.kube('exec', '-i', pod, '-c', 'probe', '--', 'python3', '-c', code,
                         data=json.dumps(payload), check=False, timeout=timeout)

    def policy_probe_identity(self, name, label, original=None):
        pod = self.get('pod', name)
        metadata, spec = pod['metadata'], pod['spec']
        require(metadata.get('labels', {}).get(LABEL) == self.run_id
                and metadata['labels'].get('app') == label
                and not metadata.get('deletionTimestamp'), 'causal policy probe ownership/label changed')
        job_names = [reference['name'] for reference in metadata.get('ownerReferences', [])
                     if reference.get('controller') is True and reference.get('kind') == 'Job']
        require(len(job_names) == 1 and job_names[0] in self.created
                and not spec.get('hostNetwork') and spec.get('automountServiceAccountToken') is False
                and spec['containers'][0].get('readinessProbe', {}).get('exec', {}).get('command')
                == ['/bin/sh', '-c', 'exit 1'], 'causal policy probe must be an owned isolated unready Job Pod')
        require(pod.get('status', {}).get('phase') == 'Running'
                and not any(condition.get('type') == 'Ready' and condition.get('status') == 'True'
                            for condition in pod.get('status', {}).get('conditions', [])),
                'causal policy probe must not join ready Service endpoints')
        identity = (metadata['uid'], pod['status'].get('podIP'), spec.get('nodeName'))
        require(all(identity) and (original is None or identity == original),
                'causal policy probe UID/IP/node changed')
        result = self.python(name, 'import json,os;print(json.dumps(os.readlink("/proc/self/ns/net")))', {})
        require(result.returncode == 0, 'causal policy probe network namespace unavailable')
        network_namespace = json.loads(result.stdout)
        require(isinstance(network_namespace, str) and network_namespace.startswith('net:['),
                'causal policy probe network namespace invalid')
        return identity, network_namespace

    def policy_label(self, name, before, after, original):
        identity, netns = self.policy_probe_identity(name, before, original[0])
        require(netns == original[1], 'causal policy probe network namespace changed')
        patch = [{'op': 'test', 'path': '/metadata/uid', 'value': identity[0]},
                 {'op': 'test', 'path': '/metadata/labels/app', 'value': before},
                 {'op': 'test', 'path': '/metadata/labels/' + LABEL.replace('/', '~1'), 'value': self.run_id},
                 {'op': 'replace', 'path': '/metadata/labels/app', 'value': after}]
        self.kube('patch', 'pod', name, '--type=json', '-p', json.dumps(patch))
        current = self.policy_probe_identity(name, after, original[0])
        require(current == original, 'causal policy probe changed across label-only transition')

    def network_tls(self):
        authorized = self.pod('gateway', self.args.probe_image, owner_sa='gateway')
        untrusted = self.pod('acceptance-untrusted', self.args.probe_image)
        services = [(app, port) for app, _, port in OWNERS.values()] + [('notification-worker', 8005)]
        targets = []
        for app, port in services:
            address = self.get('service', app)['spec']['clusterIP']
            require(address and address != 'None', app + ': ClusterIP required')
            targets.append({'host': app, 'ip': address, 'port': port})
        ca = base64.b64encode(self.ca).decode()
        code = '''import base64,json,socket,ssl,sys,time
p=json.load(sys.stdin)
context=ssl.create_default_context(cadata=base64.b64decode(p['ca']).decode())
for target in p['targets']:
 deadline=time.monotonic()+60
 while True:
  try:
   raw=socket.create_connection((target['ip'],target['port']),timeout=5)
   break
  except (ConnectionRefusedError,socket.gaierror):
   if time.monotonic()>=deadline:
    raise
   time.sleep(2)
 with raw:
  with context.wrap_socket(raw,server_hostname=target['host']) as connection:
   connection.sendall(('GET /health/live HTTP/1.1\\r\\nHost: '+target['host']+'\\r\\nConnection: close\\r\\n\\r\\n').encode())
   assert connection.recv(1024).split(b'\\r\\n',1)[0].split()[1]==b'200'
 try:
  with socket.create_connection((target['ip'],target['port']),timeout=5) as raw:
   context.wrap_socket(raw,server_hostname='isolation-invalid.invalid')
 except ssl.SSLCertVerificationError as error:
  assert error.verify_code==62
 else:
  raise RuntimeError('wrong TLS hostname accepted')
print('verified')
'''
        result = self.python(authorized, code, {'ca': ca, 'targets': targets})
        require(result.returncode == 0 and result.stdout.strip() == 'verified',
                'authorized owner HTTP/TLS positive controls or wrong-host certificate denial failed')
        blocked = [target for target in targets if target['host'] in ('identity-service', 'profile-service')]
        blocked.append({'host': 'postgres-rw', 'ip': self.get('service', 'postgres-rw')['spec']['clusterIP'], 'port': 5432})
        code = '''import errno,json,socket,sys
p=json.load(sys.stdin)
# A successful loopback socket is a positive control for the probe binary itself.
with socket.socket() as listener:
 listener.bind(('127.0.0.1',0));listener.listen(1)
 with socket.create_connection(listener.getsockname(),timeout=2):
  connection,_=listener.accept();connection.close()
results=[]
for target in p['targets']:
 try:
  connection=socket.create_connection((target['ip'],target['port']),timeout=4)
 except (socket.timeout,TimeoutError):
  outcome='timeout'
 except OSError as error:
  outcome={errno.ECONNREFUSED:'connection_refused',errno.ENETUNREACH:'network_unreachable',
           errno.EHOSTUNREACH:'host_unreachable',errno.EACCES:'permission_denied',
           errno.EPERM:'operation_not_permitted',errno.ECONNRESET:'connection_reset'}.get(error.errno,'other_socket_error')
 else:
  connection.close();outcome='connected'
 results.append({'target':target['host'],'outcome':outcome})
print(json.dumps({'loopback':True,'targets':results},sort_keys=True))
'''
        expected = [target['host'] for target in blocked]
        allowed_outcomes = {'timeout', 'connection_refused', 'network_unreachable', 'host_unreachable',
                            'permission_denied', 'operation_not_permitted', 'connection_reset',
                            'other_socket_error', 'connected'}

        def outcomes():
            result = self.python(untrusted, code, {'targets': blocked})
            require(result.returncode == 0, 'untrusted TCP probe execution failed; exit=' + str(result.returncode))
            observed = json.loads(result.stdout)
            require(observed.get('loopback') is True and isinstance(observed.get('targets'), list),
                    'untrusted TCP probe result shape failed')
            rows = observed['targets']
            require(len(rows) == len(expected) and [row.get('target') for row in rows] == expected
                    and all(row.get('outcome') in allowed_outcomes for row in rows),
                    'untrusted TCP probe target/result mismatch')
            return rows

        original = self.policy_probe_identity(untrusted, 'acceptance-untrusted')
        before = outcomes()
        require(all(row['outcome'] in ('timeout', 'connection_refused') for row in before),
                'initial untrusted policy denial failed; outcomes='
                + ','.join(row['target'] + ':' + row['outcome'] for row in before))
        changed = False
        try:
            # Only this owned Pod label changes. Existing policies/apps and the
            # Job template stay untouched; failed readiness prevents Service use.
            changed = True
            self.policy_label(untrusted, 'acceptance-untrusted', 'notification-worker', original)
            positive = '''import base64,errno,json,socket,ssl,struct,sys,time
p=json.load(sys.stdin)
context=ssl.create_default_context(cadata=base64.b64decode(p['ca']).decode())
results=[]
for target in p['targets']:
 deadline=time.monotonic()+60
 while True:
  try:
   with socket.create_connection((target['ip'],target['port']),timeout=4) as raw:
    if target['port']==5432:
     raw.sendall(struct.pack('!II',8,80877103));assert raw.recv(1)==b'S'
    with context.wrap_socket(raw,server_hostname=target['tls_host']) as connection:
     if target['port']!=5432:
      connection.sendall(('GET /health/live HTTP/1.1\\r\\nHost: '+target['tls_host']+'\\r\\nConnection: close\\r\\n\\r\\n').encode())
      assert connection.recv(1024).split(b'\\r\\n',1)[0].split()[1]==b'200'
   outcome='verified_tls';break
  except ssl.SSLCertVerificationError:
   outcome='tls_verification_failed';break
  except ssl.SSLError:
   outcome='tls_protocol_failed';break
  except (ConnectionRefusedError,socket.timeout,TimeoutError) as error:
   if time.monotonic()>=deadline:
    outcome='connection_refused' if isinstance(error,ConnectionRefusedError) else 'timeout';break
   time.sleep(2)
  except AssertionError:
   outcome='http_or_pg_protocol_failed';break
  except OSError as error:
   outcome={errno.ENETUNREACH:'network_unreachable',errno.EHOSTUNREACH:'host_unreachable',
            errno.EACCES:'permission_denied',errno.ECONNRESET:'connection_reset'}.get(error.errno,'other_socket_error');break
 results.append({'target':target['host'],'outcome':outcome})
print(json.dumps(results))
'''
            positive_targets = [dict(target, tls_host=(
                'postgres-rw.' + NS + '.svc' if target['port'] == 5432 else target['host'])) for target in blocked]
            result = self.python(untrusted, positive, {'ca': ca, 'targets': positive_targets}, timeout=240)
            require(result.returncode == 0, 'same-pod authorized TLS probe execution failed; exit=' + str(result.returncode))
            positive_outcomes = json.loads(result.stdout)
            positive_classes = {'verified_tls', 'tls_verification_failed', 'tls_protocol_failed',
                                'connection_refused', 'timeout', 'http_or_pg_protocol_failed',
                                'network_unreachable', 'host_unreachable', 'permission_denied',
                                'connection_reset', 'other_socket_error'}
            require(isinstance(positive_outcomes, list) and len(positive_outcomes) == len(expected)
                    and [row.get('target') for row in positive_outcomes] == expected
                    and all(row.get('outcome') in positive_classes for row in positive_outcomes),
                    'same-pod authorized TLS probe result shape failed')
            require(all(row['outcome'] == 'verified_tls' for row in positive_outcomes),
                    'same-pod authorized TLS positive controls failed; outcomes='
                    + ','.join(row['target'] + ':' + row['outcome'] for row in positive_outcomes))
            require(self.policy_probe_identity(untrusted, 'notification-worker') == original,
                    'causal policy probe identity/network namespace changed during positive control')
        finally:
            if changed:
                current = self.get('pod', untrusted)['metadata'].get('labels', {}).get('app')
                if current == 'notification-worker':
                    self.policy_label(untrusted, 'notification-worker', 'acceptance-untrusted', original)
                require(self.policy_probe_identity(untrusted, 'acceptance-untrusted') == original,
                        'owned causal probe label restoration failed')
        deadline = time.monotonic() + 60
        while True:
            after = outcomes()
            if all(row['outcome'] in ('timeout', 'connection_refused') for row in after):
                break
            require(all(row['outcome'] in ('connected', 'timeout', 'connection_refused') for row in after)
                    and time.monotonic() < deadline,
                    'restored untrusted policy denial failed; outcomes='
                    + ','.join(row['target'] + ':' + row['outcome'] for row in after))
            time.sleep(min(2, max(0, deadline - time.monotonic())))
        require(self.policy_probe_identity(untrusted, 'acceptance-untrusted') == original,
                'causal policy probe identity changed after restored denial')
        self.network_evidence = {'pod_uid': original[0][0], 'pod_ip': original[0][1],
                                 'netns': original[1], 'initial_denials': before,
                                 'allowed_verified_tls_targets': expected,
                                 'restored_denials': after, 'restored_label': 'acceptance-untrusted'}
        self.checks.append('same_pod_uid_ip_netns_deny_allow_verified_tls_restore_deny_three_targets')
        self.checks.append('all_nine_owner_live_tls_hostnames_wrong_hostname_denial')
        self.checks.append('untrusted_tcp_identity_profile_postgres_denied_authorized_http_db_controls')

    def cleanup(self):
        failed = []
        for name in reversed(self.created):
            result = self.kube('get', 'job', name, '--ignore-not-found', '-o', 'json', check=False)
            if result.returncode:
                failed.append(name)
                continue
            if not result.stdout.strip():
                continue
            document = json.loads(result.stdout)
            if document.get('metadata', {}).get('labels', {}).get(LABEL) != self.run_id:
                failed.append(name)
                continue
            result = self.kube('delete', 'job', name,
                               '--ignore-not-found', '--cascade=foreground', '--wait=true', '--timeout=30s', check=False)
            if result.returncode:
                failed.append(name)
        require(not failed, 'owned probe cleanup failed; run label=' + self.run_id)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kubeconfig', required=True, type=Path)
    parser.add_argument('--ca', required=True, type=Path)
    parser.add_argument('--state', required=True, type=Path)
    parser.add_argument('--probe-image', required=True,
                        help='Digest-pinned image providing /bin/sh, sleep and Python3 stdlib; no network installs')
    args = parser.parse_args()
    try:
        state = INFRA / '.generic-local'
        require(args.state.resolve() == state.resolve() and not args.state.is_symlink(),
                'only this worktree isolated .generic-local state is permitted')
        private_file(args.kubeconfig)
        require(args.kubeconfig.resolve().is_relative_to(state.resolve()),
                'task-private kubeconfig must be inside isolated state')
        require(args.ca.is_file() and not args.ca.is_symlink()
                and args.ca.resolve() == (state / 'ca.crt').resolve(), 'explicit isolated public CA required')
        require(re.fullmatch(r'[^\s]+@sha256:[a-f0-9]{64}', args.probe_image),
                'digest-pinned Python probe image required')
        acceptance = Acceptance(args)
        try:
            acceptance.guard()
            acceptance.runtime_identity()
            acceptance.databases()
            acceptance.broker()
            acceptance.network_tls()
        finally:
            acceptance.cleanup()
        print(json.dumps({'result': 'PASS', 'run': acceptance.run_id, 'checks': acceptance.checks,
                          'quarantine_coordinates': acceptance.markers,
                          'non_runtime_pods': acceptance.non_runtime_pods,
                          'network_policy_causal_evidence': acceptance.network_evidence}, sort_keys=True))
    except Exception as error:
        # Never render exceptions from kubectl, parsers or libraries that may
        # include client certificates, DSNs or secret values in their message.
        message = str(error) if isinstance(error, RuntimeError) else 'unexpected acceptance error (details withheld)'
        print('FAIL generic isolation: ' + message, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
