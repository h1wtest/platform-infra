"""Authenticated-release overlay and effective grant behavior; no cluster processes."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cnpg_operator as cnpg

IMAGE = 'ghcr.io/cloudnative-pg/cloudnative-pg:1.30.1@sha256:' + 'a' * 64


def grants(objects, namespace, group, resource, verb, name=None):
    roles = {(o['kind'], o['metadata'].get('namespace'), o['metadata']['name']): o for o in objects if o['kind'] in ('Role', 'ClusterRole')}
    for binding in objects:
        if binding['kind'] not in ('RoleBinding', 'ClusterRoleBinding'):
            continue
        if binding['kind'] == 'RoleBinding' and binding['metadata']['namespace'] != namespace:
            continue
        if not any(s.get('kind') == 'ServiceAccount' and s.get('name') == 'cnpg-manager' and s.get('namespace') == 'cnpg-system' for s in binding['subjects']):
            continue
        ref = binding['roleRef']
        role = roles[(ref['kind'], namespace if ref['kind'] == 'Role' else None, ref['name'])]
        for rule in role['rules']:
            if group in rule['apiGroups'] and resource in rule['resources'] and verb in rule['verbs'] and ('resourceNames' not in rule or name in rule['resourceNames']):
                return True
    return False


class ScopedOperatorTests(unittest.TestCase):
    def test_operand_grants_do_not_reach_other_namespaces(self):
        objects = cnpg.rbac_objects(copy.deepcopy(cnpg.EXPECTED_RULES), 'sso-remediation')
        for namespace in ('sso-remediation', 'kube-system', 'default', 'cnpg-system'):
            for resource, verb in [('secrets', 'get'), ('secrets', 'list'), ('pods/exec', 'create'), ('services', 'update')]:
                expected = namespace == 'sso-remediation' or namespace == 'cnpg-system' and resource == 'secrets'
                self.assertEqual(grants(objects, namespace, '', resource, verb), expected, (namespace, resource, verb))
        self.assertTrue(grants(objects, 'sso-remediation', 'rbac.authorization.k8s.io', 'roles', 'create'))
        self.assertTrue(grants(objects, 'sso-remediation', 'postgreSQL.cnpg.io'.lower(), 'backups', 'create'))

    def test_cluster_grants_keep_catalog_nodes_and_only_own_webhooks(self):
        objects = cnpg.rbac_objects(copy.deepcopy(cnpg.EXPECTED_RULES), 'sso-remediation')
        self.assertTrue(grants(objects, None, '', 'nodes', 'list'))
        self.assertTrue(grants(objects, None, 'postgresql.cnpg.io', 'clusterimagecatalogs', 'watch'))
        for resource, name in [('mutatingwebhookconfigurations', 'cnpg-mutating-webhook-configuration'), ('validatingwebhookconfigurations', 'cnpg-validating-webhook-configuration')]:
            self.assertTrue(grants(objects, None, 'admissionregistration.k8s.io', resource, 'patch', name))
            self.assertFalse(grants(objects, None, 'admissionregistration.k8s.io', resource, 'patch', 'another-webhook'))
            self.assertFalse(grants(objects, None, 'admissionregistration.k8s.io', resource, 'list'))

    def test_unknown_missing_wildcard_or_changed_privileges_fail_closed(self):
        mutations = [lambda r: r.append({'apiGroups': [''], 'resources': ['endpoints'], 'verbs': ['get']}), lambda r: r.pop(), lambda r: r[0]['verbs'].append('*'), lambda r: r[0].update(resourceNames=['x'])]
        for mutation in mutations:
            rules = copy.deepcopy(cnpg.EXPECTED_RULES)
            mutation(rules)
            with self.subTest(mutation=mutation), self.assertRaisesRegex(RuntimeError, 'privilege shape'):
                cnpg.rbac_objects(rules, 'sso-remediation')

    def test_namespace_cannot_expand_or_overlap_operator_namespace(self):
        for namespace in ('', '*', 'a,b', 'cnpg-system', 'A', 'a\nkind: ClusterRole'):
            with self.subTest(namespace=namespace), self.assertRaises(RuntimeError):
                cnpg.rbac_objects(copy.deepcopy(cnpg.EXPECTED_RULES), namespace)

    def test_operator_secret_renewal_and_leader_election_remain_possible(self):
        objects = cnpg.rbac_objects(copy.deepcopy(cnpg.EXPECTED_RULES), 'sso-remediation')
        for secret in ('cnpg-ca-secret', 'cnpg-webhook-cert'):
            self.assertTrue(grants(objects, 'cnpg-system', '', 'secrets', 'update', secret))
        self.assertFalse(grants(objects, 'cnpg-system', '', 'secrets', 'update', 'unrelated'))
        self.assertTrue(grants(objects, 'cnpg-system', '', 'secrets', 'patch', 'cnpg-webhook-cert'))
        self.assertFalse(grants(objects, 'cnpg-system', '', 'secrets', 'patch', 'unrelated'))
        self.assertFalse(grants(objects, 'cnpg-system', '', 'secrets', 'patch', 'cnpg-ca-secret'))
        self.assertTrue(grants(objects, 'cnpg-system', '', 'secrets', 'create'))
        self.assertTrue(grants(objects, 'cnpg-system', 'coordination.k8s.io', 'leases', 'update', 'db9c8771.cnpg.io'))
        self.assertFalse(grants(objects, 'cnpg-system', '', 'pods/exec', 'create'))

    def test_changed_manifest_or_lock_fails_before_any_command(self):
        with self.assertRaisesRegex(RuntimeError, 'authenticated'):
            cnpg.render(b'not the release', cnpg.UPSTREAM_SHA256, IMAGE, 'sso-remediation')
        with self.assertRaisesRegex(RuntimeError, 'authenticated'):
            cnpg.render(b'not the release', hashlib.sha256(b'not the release').hexdigest(), IMAGE, 'sso-remediation')

    def test_unexpected_binding_to_operator_is_rejected(self):
        objects = cnpg.rbac_objects(copy.deepcopy(cnpg.EXPECTED_RULES), 'sso-remediation')
        bindings = [o for o in objects if o['kind'] in ('RoleBinding', 'ClusterRoleBinding')]
        cnpg.validate_bindings(bindings, 'sso-remediation')
        extra = copy.deepcopy(bindings[0])
        extra['metadata']['name'] = 'unexpected-extra'
        with self.assertRaisesRegex(RuntimeError, 'Unexpected.*binding'):
            cnpg.validate_bindings(bindings + [extra], 'sso-remediation')

    def test_original_binding_is_supported_but_retargeted_role_is_not(self):
        binding = {'kind': 'ClusterRoleBinding', 'metadata': {'name': 'cnpg-manager-rolebinding'}, 'roleRef': {'apiGroup': cnpg.RBAC_GROUP, 'kind': 'ClusterRole', 'name': 'cnpg-manager'}, 'subjects': [{'kind': 'ServiceAccount', 'name': 'cnpg-manager', 'namespace': 'cnpg-system'}]}
        cnpg.validate_bindings([binding], 'sso-remediation')
        binding['roleRef']['name'] = 'cluster-admin'
        with self.assertRaisesRegex(RuntimeError, 'Unexpected.*binding'):
            cnpg.validate_bindings([binding], 'sso-remediation')

    def test_document_identity_accepts_release_metadata_ending_at_separator(self):
        # Exact first release document after splitting off its YAML separator:
        # the final name line has no newline, unlike metadata followed by spec.
        document = 'apiVersion: v1\nkind: Namespace\nmetadata:\n  labels:\n    app.kubernetes.io/name: cloudnative-pg\n  name: cnpg-system'
        self.assertEqual(cnpg._identity(document), ('Namespace', 'cnpg-system'))
        self.assertEqual(cnpg._identity('apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: cnpg-manager\n  namespace: cnpg-system'), ('ServiceAccount', 'cnpg-manager'))

    def test_authenticated_local_release_preserves_crds_and_pins_injection_image(self):
        path = Path(__file__).resolve().parents[2] / '.local/cnpg-operator.yaml'
        if not path.is_file():
            self.skipTest('Authenticated release fixture is a local downloaded prerequisite')
        original = path.read_bytes()
        for image in (IMAGE, 'sso-remediation/cnpg-operator:sha256-' + 'b' * 64):
            rendered = cnpg.render(original, cnpg.UPSTREAM_SHA256, image, 'sso-remediation').decode()
            documents = rendered.split('\n---\n')
            policies = [json.loads(doc) for doc in documents if doc.startswith('{')]
            self.assertFalse(grants(policies, 'kube-system', '', 'secrets', 'get'))
            self.assertTrue(grants(policies, 'sso-remediation', '', 'pods/exec', 'create'))
            deployment = next(doc for doc in documents if '\nkind: Deployment\n' in doc)
            self.assertIn('        image: ' + image + '\n', deployment)
            self.assertIn('        - name: OPERATOR_IMAGE_NAME\n          value: ' + image + '\n', deployment)
            self.assertIn('        - name: WATCH_NAMESPACE\n          value: sso-remediation\n', deployment)
            container_fields = dict(line.strip().split(': ', 1) for line in deployment.splitlines() if line.startswith('        image: ') or line.startswith('        imagePullPolicy: '))
            self.assertEqual(container_fields, {'image': image, 'imagePullPolicy': 'IfNotPresent' if image.startswith('sso-remediation/') else 'Always'})
            original_crds = [doc for doc in original.decode().split('\n---\n') if '\nkind: CustomResourceDefinition\n' in doc]
            self.assertTrue(original_crds)
            for crd in original_crds:
                self.assertIn(crd, documents)
        for image in ('latest', 'ghcr.io/cloudnative-pg/cloudnative-pg:1.30.1', 'sso-remediation/cnpg-operator:latest'):
            with self.subTest(image=image), self.assertRaisesRegex(RuntimeError, 'immutable'):
                cnpg.render(original, cnpg.UPSTREAM_SHA256, image, 'sso-remediation')

    def test_serviceaccount_group_grants_cannot_bypass_binding_preflight(self):
        for kind, name in [('User', 'system:serviceaccount:cnpg-system:cnpg-manager'), ('Group', 'system:serviceaccounts:cnpg-system'), ('Group', 'system:serviceaccounts'), ('Group', 'system:authenticated')]:
            binding = {'kind': 'ClusterRoleBinding', 'metadata': {'name': 'extra-authority'}, 'roleRef': {'apiGroup': cnpg.RBAC_GROUP, 'kind': 'ClusterRole', 'name': 'cluster-admin'}, 'subjects': [{'kind': kind, 'name': name, 'apiGroup': cnpg.RBAC_GROUP}]}
            with self.subTest(subject=name), self.assertRaisesRegex(RuntimeError, 'Unexpected.*binding'):
                cnpg.validate_bindings([binding], 'sso-remediation')

    def test_issuer_discovery_requires_exact_builtin_role_not_only_trusted_name(self):
        name = 'system:service-account-issuer-discovery'
        binding = {'kind': 'ClusterRoleBinding', 'metadata': {'name': name}, 'roleRef': {'apiGroup': cnpg.RBAC_GROUP, 'kind': 'ClusterRole', 'name': name}, 'subjects': [{'apiGroup': cnpg.RBAC_GROUP, 'kind': 'Group', 'name': 'system:serviceaccounts'}]}
        role = {'kind': 'ClusterRole', 'metadata': {'name': name}, 'rules': [{'verbs': ['get'], 'nonResourceURLs': ['/.well-known/openid-configuration', '/.well-known/openid-configuration/', '/openid/v1/jwks', '/openid/v1/jwks/']}]}
        cnpg.validate_bindings([binding], 'sso-remediation', {name: role})
        with self.assertRaisesRegex(RuntimeError, 'built-in'):
            cnpg.validate_bindings([binding], 'sso-remediation')
        for extra in ({'verbs': ['get'], 'apiGroups': [''], 'resources': ['secrets']}, {'verbs': ['get'], 'nonResourceURLs': ['/*']}):
            changed = copy.deepcopy(role)
            changed['rules'].append(extra)
            with self.subTest(extra=extra), self.assertRaisesRegex(RuntimeError, 'built-in'):
                cnpg.validate_bindings([binding], 'sso-remediation', {name: changed})
        role['aggregationRule'] = {'clusterRoleSelectors': [{}]}
        with self.assertRaisesRegex(RuntimeError, 'built-in'):
            cnpg.validate_bindings([binding], 'sso-remediation', {name: role})

    def test_rollout_barrier_rejects_old_ready_primary_until_every_instance_is_current(self):
        cluster, pods = instance_snapshot()
        self.assertEqual(cnpg.instances_ready(cluster, pods, IMAGE), 'postgres-2')
        # Actual failure timeline: Ready remained true before the controller
        # replaced the old bootstrap image, then replicas updated first.
        for count in (3, 2, 1):
            snapshot = copy.deepcopy(pods)
            for pod in snapshot[:count]:
                pod['spec']['initContainers'][0]['image'] = 'sso-remediation/cnpg-operator:sha256-' + 'b' * 64
            self.assertIsNone(cnpg.instances_ready(cluster, snapshot, IMAGE))
        for mutation in ('terminating', 'not-ready', 'missing', 'extra', 'init-incomplete', 'unhealthy', 'switching', 'stale-count', 'wrong-owner'):
            current_cluster, current_pods = instance_snapshot()
            if mutation == 'terminating':
                current_pods[0]['metadata']['deletionTimestamp'] = '2026-10-23T00:00:00Z'
            elif mutation == 'not-ready':
                current_pods[0]['status']['conditions'][0]['status'] = 'False'
            elif mutation == 'missing':
                current_pods.pop()
            elif mutation == 'extra':
                extra = copy.deepcopy(current_pods[0])
                extra['metadata'].update(name='postgres-4', uid='pod-4')
                current_pods.append(extra)
            elif mutation == 'init-incomplete':
                current_pods[0]['status']['initContainerStatuses'][0]['state'] = {'running': {}}
            elif mutation == 'unhealthy':
                current_cluster['status']['phase'] = 'Upgrading cluster'
            elif mutation == 'switching':
                current_cluster['status']['targetPrimary'] = 'postgres-1'
            elif mutation == 'stale-count':
                current_cluster['status']['readyInstances'] = 2
            else:
                current_pods[0]['metadata']['ownerReferences'][0]['uid'] = 'foreign-cluster'
            with self.subTest(mutation=mutation):
                self.assertIsNone(cnpg.instances_ready(current_cluster, current_pods, IMAGE))


def instance_snapshot():
    cluster = {'metadata': {'name': 'postgres', 'uid': 'cluster-id'}, 'spec': {'instances': 3}, 'status': {'instances': 3, 'readyInstances': 3, 'phase': 'Cluster in healthy state', 'currentPrimary': 'postgres-2', 'targetPrimary': 'postgres-2', 'conditions': [{'type': 'Ready', 'status': 'True'}]}}
    pods = [{'metadata': {'name': 'postgres-' + str(i), 'uid': 'pod-' + str(i), 'ownerReferences': [{'apiVersion': 'postgresql.cnpg.io/v1', 'kind': 'Cluster', 'name': 'postgres', 'uid': 'cluster-id', 'controller': True}]}, 'spec': {'initContainers': [{'name': 'bootstrap-controller', 'image': IMAGE}]}, 'status': {'phase': 'Running', 'conditions': [{'type': 'Ready', 'status': 'True'}], 'containerStatuses': [{'name': 'postgres', 'ready': True}], 'initContainerStatuses': [{'name': 'bootstrap-controller', 'state': {'terminated': {'exitCode': 0}}}]}} for i in range(3)]
    return cluster, pods

if __name__ == '__main__':
    unittest.main()
