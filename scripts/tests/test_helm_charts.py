"""Render real Helm artifacts: image, ownership, security and credential boundaries."""
import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cli
import env_secrets
import helm_release
import manifests
import release_values
import security_material


def fixture(directory):
    workspace = Path(directory)
    state = workspace / 'platform-infra' / '.local'
    state.mkdir(parents=True)
    for owner in ('identity-service', 'user-notification-service'):
        (workspace / owner).mkdir()
    values = {key: 'fixture-' + key for key in env_secrets.REQUIRED_KEYS}
    values['telegram_bot_token'] = 'fixture-telegram_bot_token'
    for database in manifests.DBS:
        for role in ('runtime', 'migration'):
            values[database + '_' + role + '_password'] = 'fixture-' + database + role
    env_secrets.save(state, values)
    (state / 'ca.crt').write_bytes(b'fixture certificate')
    (state / 'signing.pem').write_bytes(b'fixture signing key')
    for name in security_material.SERVICES:
        leaf = state / 'certificates' / name
        leaf.mkdir(parents=True)
        (leaf / 'tls.crt').write_bytes(b'fixture certificate')
        (leaf / 'tls.key').write_bytes(b'fixture private key')
    images = {**cli.PINS, **{name: 'sso-remediation/' + name + ':sha256-' + '1' * 64
                           for name in ('identity', 'profile', 'notification', 'worker', 'admin', 'frontend')}}
    runtime = SimpleNamespace(ROOT=cli.ROOT, STATE=state, NS=cli.NS,
                              CONTEXT=cli.CONTEXT, run=cli.run, kube=cli.kube)
    return runtime, images


def rendered(runtime, images):
    return {name: helm_release.render(runtime, name, spec)
            for name, spec in release_values.release_specs(images, runtime.STATE, runtime.ROOT).items()}


def workload(objects, name):
    return next(obj for obj in objects if obj['kind'] in ('Deployment', 'StatefulSet')
                and obj['metadata']['name'] == name)


class HelmArtifactBoundaries(unittest.TestCase):
    def test_releases_own_disjoint_original_objects_and_retain_data(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, images = fixture(directory)
            releases = rendered(runtime, images)
        owned = {}
        for release, objects in releases.items():
            for obj in objects:
                key = (obj['apiVersion'], obj['kind'], obj['metadata']['name'])
                self.assertNotIn(key, owned, (release, key))
                owned[key] = release
                self.assertEqual(obj['metadata']['namespace'], 'sso-remediation')
                self.assertNotIn(obj['kind'], ('Namespace', 'ClusterRole', 'ClusterRoleBinding', 'CustomResourceDefinition'))
                if obj['kind'] in ('PersistentVolumeClaim', 'Cluster'):
                    self.assertEqual(obj['metadata']['annotations']['helm.sh/resource-policy'], 'keep')
                if obj['kind'] == 'Secret' or obj['kind'] == 'ConfigMap' or obj['kind'] == 'NetworkPolicy':
                    self.assertEqual(release, 'platform-config')
        self.assertEqual(owned[('v1', 'Service', 'gateway-public')], 'gateway')
        self.assertEqual(owned[('postgresql.cnpg.io/v1', 'Cluster', 'postgres')], 'postgres')
        self.assertEqual(releases['postgres'][0]['spec']['postgresql']['synchronous']['dataDurability'], 'required')

    def test_selected_image_reaches_main_container_without_touching_database_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, images = fixture(directory)
            specs = release_values.release_specs(images, runtime.STATE, runtime.ROOT)
            for name in release_values.APPLICATION_RELEASES:
                spec = copy.deepcopy(specs[name])
                spec['values']['image'] = 'example.invalid/selected@sha256:' + '2' * 64
                spec['values']['readinessPath'] = '/deployment/ready'
                deployment = workload(helm_release.render(runtime, name, spec), name)
                pod = deployment['spec']['template']['spec']
                self.assertEqual(pod['containers'][0]['image'], spec['values']['image'])
                self.assertFalse(pod['automountServiceAccountToken'])
                self.assertTrue(pod['securityContext']['runAsNonRoot'])
                self.assertTrue(pod['containers'][0]['securityContext']['readOnlyRootFilesystem'])
                self.assertEqual(deployment['spec']['strategy']['rollingUpdate'], {'maxSurge': 1, 'maxUnavailable': 0})
                self.assertGreater(deployment['spec']['minReadySeconds'], 0)
                self.assertLessEqual(deployment['spec']['progressDeadlineSeconds'], 240)
                self.assertEqual(pod['containers'][0]['readinessProbe']['httpGet']['path'], '/deployment/ready')
                self.assertEqual(pod['containers'][0]['startupProbe']['httpGet']['path'], '/deployment/ready')
                self.assertEqual(pod['containers'][0]['lifecycle']['preStop'], {'sleep': {'seconds': 5}})
                self.assertGreaterEqual(pod['terminationGracePeriodSeconds'], 50)
                if name in manifests.APPS:
                    self.assertEqual(pod['initContainers'][0]['image'], images['postgres'])
                    refs = {env['name']: env.get('valueFrom', {}).get('secretKeyRef') for env in pod['containers'][0]['env']}
                    self.assertEqual(refs['DATABASE_URL']['key'], 'DATABASE_URL')
                    self.assertNotIn('MIGRATION_DATABASE_URL', refs)
                if name in ('identity-service', 'profile-service', 'notification-service', 'admin-audit-service'):
                    self.assertNotIn('replicas', deployment['spec'])
                else:
                    self.assertIn('replicas', deployment['spec'])

    def test_owner_telegram_edit_restarts_only_consumers_not_unrelated_services(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, images = fixture(directory)
            first = rendered(runtime, images)
            values = env_secrets.load(runtime.STATE)
            self.assertEqual(values['telegram_bot_token'], 'fixture-telegram_bot_token')
            values['telegram_bot_token'] = 'edited-bot-token'
            env_secrets.save(runtime.STATE, values)
            self.assertEqual(env_secrets.load(runtime.STATE)['telegram_bot_token'], 'edited-bot-token')
            second = rendered(runtime, images)
        for name in release_values.APPLICATION_RELEASES + ('grafana',):
            before = workload(first[name], name)['spec']['template']
            after = workload(second[name], name)['spec']['template']
            if name in ('profile-service', 'notification-service', 'notification-worker'):
                self.assertNotEqual(before, after, name)
            else:
                self.assertEqual(before, after, name)
            self.assertNotIn('edited-bot-token', json.dumps(after))
        self.assertNotIn('secretKeyRef', json.dumps(workload(second['frontend'], 'frontend')))

    def test_api_policy_uses_only_discovered_values_and_is_config_owned(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, images = fixture(directory)
            spec = release_values.release_specs(images, runtime.STATE, runtime.ROOT)['platform-config']
            rules = [{'to': [{'ipBlock': {'cidr': '10.43.0.1/32'}}], 'ports': [{'protocol': 'TCP', 'port': 443}]},
                     {'to': [{'ipBlock': {'cidr': '172.18.0.2/32'}}], 'ports': [{'protocol': 'TCP', 'port': 6443}]}]
            spec['values']['apiNetworkPolicy'] = {'spec': {'egress': rules}}
            objects = helm_release.render(runtime, 'platform-config', spec)
        policy = next(obj for obj in objects if obj['metadata']['name'] == 'allow-postgres-kubernetes-api')
        self.assertEqual(policy['spec']['egress'], rules)
        self.assertEqual(policy['spec']['podSelector'], {'matchLabels': {'cnpg.io/cluster': 'postgres'}})


if __name__ == '__main__':
    unittest.main()
