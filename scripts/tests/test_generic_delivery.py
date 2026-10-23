# SPDX-License-Identifier: MIT
"""Behavioral owner credential, namespace and transport boundaries for generic mode."""
import base64
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cli
import cluster_identity
import env_secrets
import helm_release
import manifests
import broker_security
import release_values
import security_material
import render


class GenericDelivery(unittest.TestCase):
    def setUp(self):
        self.saved = (cli.STATE, cli.NS, cli.CONTEXT)
        cli.configure_profile('generic', 'k3d-sso-remediation')
        self.addCleanup(self.restore)

    def restore(self):
        cli.configure_profile('default', None)
        cli.STATE, cli.NS, cli.CONTEXT = self.saved

    def fixture(self, directory):
        state = Path(directory) / 'platform-infra' / '.generic-local'
        state.mkdir(parents=True)
        values = {key: 'fixture-' + key for key in env_secrets.REQUIRED_KEYS}
        values['telegram_bot_token'] = ''
        values['nowpayments_api_key'] = 'provider-api-fixture'
        values['nowpayments_ipn_secret'] = 'provider-ipn-fixture'
        env_secrets.save(state, values)
        (state / 'ca.crt').write_bytes(b'fixture public certificate')
        (state / 'signing.pem').write_bytes(b'fixture signing key')
        for name in security_material.SERVICES:
            leaf = state / 'certificates' / name
            leaf.mkdir(parents=True)
            (leaf / 'tls.crt').write_bytes(b'fixture certificate')
            (leaf / 'tls.key').write_bytes(b'fixture key')
        images = dict(cli.PINS)
        images.update({name: 'sso-remediation/' + name + ':sha256-' + '1' * 64
                       for name in (*[item[0] for item in manifests.APPS.values()], 'frontend')})
        runtime = SimpleNamespace(ROOT=cli.ROOT, STATE=state, NS=cli.NS, CONTEXT=cli.CONTEXT,
                                  run=cli.run, kube=cli.kube)
        return runtime, images, values

    def test_generated_owner_files_never_touch_original_repository_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for owner in env_secrets.REPOSITORIES:
                (root / owner).mkdir()
                (root / owner / '.env').write_text('UNCHANGED=original\n')
            runtime, _, values = self.fixture(directory)
            self.assertEqual(env_secrets.load(runtime.STATE), values)
            for owner in env_secrets.REPOSITORIES:
                self.assertEqual((root / owner / '.env').read_text(), 'UNCHANGED=original\n')
                path = runtime.STATE / 'owners' / owner / '.env'
                _, assignments = env_secrets._parse(path)
                for key, expected_owner in env_secrets.OWNERS.items():
                    self.assertEqual(env_secrets.variable(key) in assignments, expected_owner == owner and key in values)
            billing = runtime.STATE / 'owners' / 'billing-service' / '.env'
            self.assertIn('NOWPAYMENTS_API_KEY', env_secrets._parse(billing)[1])
    def test_generated_generic_tls_and_cipher_keys_are_owner_distinct_and_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'platform-infra' / '.generic-local'
            values = cli.create_secrets(state)
            keys = [values[key] for key in env_secrets.PURPOSE_KEYS]
            self.assertEqual(len(keys), len(set(keys)))
            self.assertTrue(all(len(base64.b64decode(key, validate=True)) == 32 for key in keys))
            private = []
            for owner in ('catalog', 'billing', 'subscription', 'referral'):
                leaf = state / 'certificates' / (owner + '-service')
                private.append((leaf / 'tls.key').read_bytes())
                cli.run(['openssl', 'verify', '-CAfile', state / 'ca.crt',
                         '-verify_hostname', owner + '-service.generic-subscriptions.svc', leaf / 'tls.crt'])
            self.assertEqual(len(private), len(set(private)))
            cli.run(['openssl', 'verify', '-CAfile', state / 'ca.crt', '-verify_hostname',
                     'postgres-rw.generic-subscriptions.svc', state / 'certificates/postgres/tls.crt'])
            self.assertEqual(cli.create_secrets(state), values)
            self.assertNotIn('nowpayments_api_key', values)


    def test_all_application_metrics_discover_ready_pods_without_api_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, images, _ = self.fixture(directory)
            specs = release_values.release_specs(images, runtime.STATE, runtime.ROOT)
            config = json.loads(specs['platform-config']['values']['configMaps']['prometheus-yml']['prometheus.yml'])
            services = {name: helm_release.render(runtime, name, specs[name]) for name in manifests.APPS}
            prometheus = helm_release.render(runtime, 'prometheus', specs['prometheus'])
        app_jobs = [job for job in config['scrape_configs'] if job['job_name'].startswith('platform/')]
        self.assertEqual({job['job_name'].split('/', 1)[1] for job in app_jobs}, set(manifests.APPS))
        for name, (owner, port, _) in manifests.APPS.items():
            deployment = next(obj for obj in services[name] if obj['kind'] == 'Deployment')
            labels = deployment['spec']['template']['metadata']['labels']
            headless = next(obj for obj in services[name] if obj['kind'] == 'Service' and obj['metadata']['name'] == name + '-metrics')
            self.assertEqual(headless['spec']['clusterIP'], 'None')
            self.assertFalse(headless['spec'].get('publishNotReadyAddresses', False))
            self.assertTrue(all(labels.get(key) == value for key, value in headless['spec']['selector'].items()))
            self.assertEqual(headless['spec']['ports'], [{'name': 'metrics', 'port': port, 'targetPort': port}])
            job = next(job for job in app_jobs if job['job_name'] == 'platform/' + name)
            self.assertNotIn('static_configs', job)
            self.assertNotIn('kubernetes_sd_configs', job)
            self.assertEqual(job['dns_sd_configs'], [{'names': [name + '-metrics.generic-subscriptions.svc.cluster.local'],
                                                     'type': 'A', 'port': port, 'refresh_interval': '5s'}])
            self.assertEqual(job['tls_config'], {'ca_file': '/run/tls/ca.crt', 'server_name': name})
            target_labels = {rule['target_label']: rule['replacement'] for rule in job['relabel_configs']}
            self.assertEqual(target_labels, {'job': 'platform', 'app': name, 'service': name,
                                            'owner': 'notification' if owner == 'worker' else owner})
        for obj in prometheus:
            self.assertNotIn(obj['kind'], ('Role', 'RoleBinding', 'ClusterRole', 'ClusterRoleBinding'))
        deployment = next(obj for obj in prometheus if obj['kind'] == 'Deployment')
        self.assertFalse(deployment['spec']['template']['spec']['automountServiceAccountToken'])
        for name in ('frontend', 'gateway'):
            self.assertFalse(specs[name]['values'].get('metricsDiscovery', False))

    def test_rendered_generic_objects_keep_namespace_and_owner_credentials_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, images, _ = self.fixture(directory)
            specs = release_values.release_specs(images, runtime.STATE, runtime.ROOT)
            releases = {name: helm_release.render(runtime, name, spec) for name, spec in specs.items()}
        for objects in releases.values():
            for obj in objects:
                self.assertEqual(obj['metadata']['namespace'], 'generic-subscriptions')
                self.assertNotEqual(obj['kind'], 'Namespace')
                self.assertNotEqual(obj.get('spec', {}).get('type'), 'LoadBalancer')
        for owner, port in (('catalog', 8006), ('billing', 8007), ('subscription', 8008), ('referral', 8009)):
            obj = next(o for o in releases[owner + '-service'] if o['kind'] == 'Deployment')
            container = obj['spec']['template']['spec']['containers'][0]
            env = {entry['name']: entry for entry in container['env']}
            self.assertEqual(env['HTTP_PORT']['value'], str(port))
            self.assertEqual(env['DATABASE_URL']['valueFrom']['secretKeyRef']['name'], owner + '-database')
            self.assertEqual(env['INTERNAL_SERVICE_TOKEN']['valueFrom']['secretKeyRef']['key'], owner + '_token')
            self.assertEqual('NOWPAYMENTS_API_KEY' in env, owner == 'billing')
            self.assertNotIn('MIGRATION_DATABASE_URL', env)
            self.assertEqual(container['readinessProbe']['httpGet']['scheme'], 'HTTPS')
        config = specs['platform-config']['values']
        self.assertIn('generic-subscriptions.svc', base64.b64decode(config['secrets']['catalog-database']['DATABASE_URL']).decode())
        self.assertIn('https://localhost:18448', config['configMaps']['gateway-conf']['gateway.conf'])
        broker_policy = next(o for o in releases['platform-config'] if o['metadata']['name'] == 'allow-redpanda')
        self.assertIn('notification-worker', json.dumps(broker_policy))
        self.assertIn('billing-service', json.dumps(broker_policy))
        broker = next(o for o in releases['redpanda'] if o['kind'] == 'StatefulSet')
        startup = broker['spec']['template']['spec']['containers'][0]['args'][0]
        self.assertIn('--reactor-backend=epoll', startup)
        self.assertIn('--unsafe-bypass-fsync=false', startup)
        self.assertNotIn('--unsafe-bypass-fsync=true', startup)
        postgres = next(o for o in releases['postgres'] if o['kind'] == 'StatefulSet')
        labels = postgres['spec']['template']['metadata']['labels']
        policy = next(o for o in releases['platform-config'] if o['metadata']['name'] == 'allow-postgres')
        self.assertTrue(all(labels.get(key) == value for key, value in policy['spec']['podSelector']['matchLabels'].items()))
        for owner in ('catalog', 'billing', 'subscription', 'referral'):
            peer_names = {peer.get('podSelector', {}).get('matchLabels', {}).get('app')
                          for rule in policy['spec']['ingress'] for peer in rule.get('from', [])}
            self.assertIn(owner + '-service', peer_names)

    def test_new_owner_migrations_receive_only_selected_owner_database_and_runtime_identity(self):
        images = {target: 'example.invalid/' + target + '@sha256:' + '1' * 64
                  for target, _, _ in manifests.APPS.values()}
        images['postgres'] = cli.PINS['postgres']
        for owner in ('catalog', 'billing', 'subscription', 'referral'):
            with self.subTest(owner=owner), patch.object(cli, 'apply') as apply, \
                    patch.object(cli, 'kube'), patch.object(cli, 'dbsql') as sql:
                cli.migration_jobs(images, selected=owner + '-service')
                job = apply.call_args.args[0][0]
                container = job['spec']['template']['spec']['containers'][0]
                env = {entry['name']: entry for entry in container['env']}
                self.assertEqual(job['spec']['template']['spec']['serviceAccountName'], 'default')
                self.assertFalse(job['spec']['template']['spec']['automountServiceAccountToken'])
                self.assertEqual(job['metadata']['namespace'], 'generic-subscriptions')
                self.assertEqual(container['args'], ['migrate'])
                self.assertEqual(env['DATABASE_URL']['valueFrom']['secretKeyRef'],
                                 {'name': owner + '-database', 'key': 'MIGRATION_DATABASE_URL'})
                self.assertEqual(env['INTERNAL_SERVICE_TOKEN']['valueFrom']['secretKeyRef']['key'], owner + '_token')
                self.assertNotIn('NOWPAYMENTS_API_KEY', env)
                self.assertEqual(sql.call_args.args[1], owner + '_db')

    def test_owner_acls_do_not_grant_cross_owner_writes_or_sensitive_command_reads(self):
        rules = broker_security.owner_acls()
        allowed = {(role, resource, name): operations for role, operations, resource, name in rules}
        self.assertIn(('identity', 'topic', 'notification.commands.v2'), allowed)
        for role in ('profile', 'admin', 'catalog', 'billing', 'subscription', 'referral'):
            self.assertNotIn((role, 'topic', 'notification.commands.v2'), allowed)
        self.assertEqual(allowed[('billing', 'topic', 'billing.events.v1')], 'write,describe')
        self.assertEqual(allowed[('subscription', 'topic', 'billing.events.v1')], 'read,describe')
        self.assertEqual(allowed[('subscription', 'group', 'subscription-service-v2')], 'read,describe')
        self.assertFalse(any(name == '*' for _, _, _, name in rules))
        topics = dict(broker_security.topic_inventory(True))
        self.assertIn('identity.events.v1', topics)
        self.assertIn('identity.events.v2', topics)
        self.assertNotIn('billing.events.v2', topics)

    def test_omitted_optional_provider_credentials_do_not_get_generated_fake_values(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, images, values = self.fixture(directory)
            values.pop('nowpayments_api_key')
            values.pop('nowpayments_ipn_secret')
            env_secrets.save(runtime.STATE, values)
            self.assertNotIn('nowpayments_api_key', env_secrets.load(runtime.STATE))
            specs = release_values.release_specs(images, runtime.STATE, runtime.ROOT)
        env = {entry['name']: entry for entry in specs['billing-service']['values']['env']}
        self.assertNotIn('NOWPAYMENTS_API_KEY', env)
        self.assertNotIn('TEST_PROVIDER_MODE', env)
        self.assertEqual(env['NOWPAYMENTS_BASE_URL']['value'], 'https://api.nowpayments.io/v1')

    def test_original_default_render_does_not_resolve_nonexistent_generic_owners(self):
        cli.configure_profile('default', None)
        from test_helm_charts import fixture
        with tempfile.TemporaryDirectory() as directory:
            runtime, images = fixture(directory)
            specs = release_values.release_specs(images, runtime.STATE, runtime.ROOT)
        self.assertNotIn('catalog-service', specs)
        self.assertNotIn('localEpoll', specs['redpanda']['values'])
        config = specs['platform-config']['values']['configMaps']['gateway-conf']['gateway.conf']
        self.assertNotIn('proxy_pass https://catalog-service', config)
        self.assertIn('https://localhost:8448', config)

    def test_render_sidecar_does_not_impersonate_initialized_runtime_ca(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / '.generic-local'
            output = state / 'render.json'
            source = Path(directory) / 'ephemeral-ca.crt'
            source.write_bytes(b'ephemeral rendering CA')
            objects = [{'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'render-proof'}}]
            render.write_artifacts(output, source, objects)
            self.assertEqual(json.loads(output.read_text())['items'], objects)
            self.assertEqual(output.with_name('render-ca.crt').read_bytes(), source.read_bytes())
            self.assertFalse((state / 'ca.crt').exists())
            self.assertFalse(env_secrets.exists(state))

    def test_isolated_state_is_not_a_build_source_and_new_owner_code_is(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'catalog-service'
            source.mkdir()
            (source / 'main.go').write_text('package main\n')
            before = cli.workspace_hash(root)
            private = source / '.generic-local'
            private.mkdir()
            (private / 'not-a-build-input.json').write_text('{"secret":"private-test"}')
            self.assertEqual(cli.workspace_hash(root), before)
            (source / 'main.go').write_text('package catalog\n')
            self.assertNotEqual(cli.workspace_hash(root), before)

    def test_context_allowlist_and_cluster_commands_fail_closed_before_execution(self):
        with self.assertRaisesRegex(RuntimeError, 'context'):
            cli.configure_profile('generic', 'production')
        cli.configure_profile('generic', 'k3d-sso-remediation')
        with patch.object(cli, 'run') as command:
            for action in (cli.cluster, cli.start_cluster):
                with self.assertRaisesRegex(RuntimeError, 'namespace-only'):
                    action()
            command.assert_not_called()

    def test_namespace_initialization_mutates_only_new_namespace_and_never_baselines_original(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / '.generic-local'
            state.mkdir()
            calls = []
            created = False
            def command(args, **kwargs):
                nonlocal created
                calls.append((args, kwargs))
                if args[3:6] == ['config', 'view', '--minify']:
                    body = {'clusters': [{'cluster': {'server': 'https://127.0.0.1:6445'}}]}
                elif args[3:6] == ['get', 'namespace', 'kube-system']:
                    body = {'metadata': {'uid': 'cluster-one'}}
                elif args[3:6] == ['get', 'namespace', 'generic-subscriptions']:
                    body = {'metadata': {'name': 'generic-subscriptions', 'uid': 'owned-one',
                             'labels': {'platform.local/profile': 'generic'}}} if created else None
                elif args[3:6] == ['create', '-f', '-']:
                    document = json.loads(kwargs['input'])
                    self.assertEqual(document['kind'], 'Namespace')
                    self.assertEqual(document['metadata']['name'], 'generic-subscriptions')
                    created = True
                    body = {}
                else:
                    self.fail('Unexpected context/global mutation: ' + str(args))
                return SimpleNamespace(stdout=json.dumps(body).encode() if body is not None else b'')
            runtime = SimpleNamespace(CONTEXT='k3d-sso-remediation', NS='generic-subscriptions',
                                      STATE=state, run=command)
            first = cluster_identity.guard(runtime, initialize=True)
            self.assertEqual(first['namespace_uid'], 'owned-one')
            self.assertTrue((state / 'namespace-identity.json').is_file())
            self.assertFalse((state / 'cluster-identity.json').exists())
            self.assertEqual(cluster_identity.guard(runtime), first)
            self.assertEqual(sum(args[3:6] == ['create', '-f', '-'] for args, _ in calls), 1)

    def test_namespace_identity_rejects_replaced_cluster_and_foreign_namespace(self):
        namespace = {'metadata': {'name': 'generic-subscriptions', 'uid': 'namespace-one',
                                 'labels': {'platform.local/profile': 'generic'}}}
        first = cluster_identity.namespace_snapshot('k3d-sso-remediation',
                    'https://127.0.0.1:6445', 'cluster-one', namespace)
        self.assertEqual(first['namespace_uid'], 'namespace-one')
        with self.assertRaisesRegex(RuntimeError, 'ownership'):
            cluster_identity.namespace_snapshot('k3d-sso-remediation',
                    'https://127.0.0.1:6445', 'cluster-one', {'metadata': {'name': 'generic-subscriptions', 'uid': 'foreign', 'labels': {}}})
        with self.assertRaisesRegex(RuntimeError, 'loopback'):
            cluster_identity.namespace_snapshot('k3d-sso-remediation',
                    'https://remote.example:6443', 'cluster-one', namespace)
        with self.assertRaisesRegex(RuntimeError, 'differs'):
            cluster_identity.validate_namespace(first, {**first, 'cluster_uid': 'cluster-two'})


if __name__ == '__main__':
    unittest.main()
