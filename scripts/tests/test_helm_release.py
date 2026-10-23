"""Safety contracts exercised without a cluster; only CLI process I/O is substituted."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import helm_release

IMAGE = 'sso-remediation/identity:sha256-' + 'a' * 64
REGISTRY_IMAGE = 'registry.example.test/team/app@sha256:' + 'b' * 64
SECRET = 'must-never-escape-in-an-error'


def deployment(name='identity-service'):
    return {'apiVersion': 'apps/v1', 'kind': 'Deployment',
            'metadata': {'name': name, 'namespace': 'sso-remediation'},
            'spec': {'selector': {'matchLabels': {'app': name}},
                     'template': {'metadata': {'labels': {'app': name}},
                                  'spec': {'containers': [{'name': name, 'image': IMAGE}]}}}}


def spec():
    return {'chart': 'platform-service', 'values': {'name': 'identity-service', 'image': IMAGE, 'credential': SECRET}}


class ProcessRuntime:
    """In-memory external Helm/Kubernetes boundary, including mutation effects."""
    CONTEXT = 'k3d-sso-remediation'
    NS = 'sso-remediation'

    def __init__(self, root):
        self.ROOT = Path(root)
        self.STATE = self.ROOT / '.local'
        self.STATE.mkdir()
        (self.ROOT / 'charts' / 'platform-service').mkdir(parents=True)
        self.documents = [deployment()]
        self.objects = {}
        self.installed = False
        self.release_status = 'deployed'
        self.release_values = {'name': 'identity-service', 'image': IMAGE}
        self.revisions = [{'revision': 1, 'status': 'deployed', 'description': SECRET}]
        self.fail_operation = None
        self.image_id = 'sha256:' + 'a' * 64
        self.installed_name = 'identity-service'
        self.commands = []
        self.patches = []
        self.values_paths = []
        self.fail_get = False
        self.fail_rollout = False

    def add_existing(self, obj=None):
        obj = copy.deepcopy(obj or deployment())
        obj['metadata'].update(uid='original-uid', resourceVersion='42')
        self.objects[(obj['kind'], obj['metadata']['name'])] = obj
        return obj

    def run(self, command, *, input=None, capture=True, timeout=600, check=True):
        args = [str(arg) for arg in command]
        self.commands.append(args)
        out, code = b'', 0
        if args[0] == 'docker':
            out = json.dumps([{'Id': self.image_id}]).encode()
        elif args[0] == 'kubectl':
            self.assert_scope(args)
            op = args[5:]
            kind, name = op[1].split('.')[0], op[2]
            if op[0] == 'rollout':
                if self.fail_rollout:
                    return subprocess.CompletedProcess(args, 1, b'', SECRET.encode())
            elif op[0] == 'get':
                if self.fail_get:
                    return subprocess.CompletedProcess(args, 1, b'', SECRET.encode())
                item = self.objects.get((kind, name))
                out = json.dumps(item).encode() if item else b''
            elif op[0] == 'patch':
                operations = json.loads(input)
                item = self.objects[(kind, name)]
                for operation in operations:
                    metadata_path = operation['path'].startswith('/metadata/')
                    target = item['metadata'] if metadata_path else item
                    key = operation['path'].removeprefix('/metadata/') if metadata_path else operation['path'].removeprefix('/')
                    if operation['op'] == 'test':
                        if target.get(key) != operation['value']:
                            return subprocess.CompletedProcess(args, 1, b'', SECRET.encode())
                    elif operation['op'] in ('add', 'replace'):
                        target[key] = operation['value']
                    else:
                        raise AssertionError(operation)
                self.patches.append((kind, name))
                out = json.dumps(item).encode()
            else:
                raise AssertionError(args)
        else:
            op = args[1]
            self.assert_scope(args)
            if '--values' in args:
                path = Path(args[args.index('--values') + 1])
                self.values_paths.append(path)
                assert path.stat().st_mode & 0o777 == 0o600
                assert path.parent.stat().st_mode & 0o777 == 0o700
                assert json.loads(path.read_text())['credential'] == SECRET
            if op == 'template':
                out = ('---\n# Source: platform-service/templates/deployment.yaml\n' + '\n---\n'.join(json.dumps(doc) for doc in self.documents)).encode()
            elif op == 'list':
                out = json.dumps([{'name': self.installed_name, 'status': self.release_status}] if self.installed else []).encode()
            elif op == 'history':
                out = json.dumps(self.revisions).encode()
            elif op == 'status':
                out = json.dumps({'name': 'identity-service', 'version': 1, 'info': {'status': self.release_status, 'notes': SECRET}}).encode()
            elif op == 'get':
                out = json.dumps(self.release_values).encode()
            elif op in ('install', 'upgrade', 'rollback'):
                if self.fail_operation == op:
                    code, out = 1, SECRET.encode()
                else:
                    self.installed = True
            else:
                raise AssertionError(args)
        return subprocess.CompletedProcess(args, code, out, SECRET.encode() if code else b'')

    def assert_scope(self, args):
        context_flag = '--context' if args[0] == 'kubectl' else '--kube-context'
        assert args[args.index(context_flag) + 1] == self.CONTEXT
        assert args[args.index('--namespace') + 1] == self.NS


class HelmSafetyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.runtime = ProcessRuntime(self.directory.name)

    def test_render_returns_real_documents_and_removes_private_values(self):
        docs = helm_release.render(self.runtime, 'identity-service', spec())
        self.assertEqual(docs[0]['spec']['selector'], {'matchLabels': {'app': 'identity-service'}})
        self.assertTrue(self.runtime.values_paths)
        self.assertFalse(any(path.exists() for path in self.runtime.values_paths))

    def test_rejects_mutable_image_references_before_processes(self):
        for image in ('nginx', 'nginx:latest', 'registry.test/app:v1', 'app@sha256:1234', 'sso-remediation/identity:sha256-' + 'A' * 64):
            with self.subTest(image=image):
                selected = spec()
                selected['values']['image'] = image
                with self.assertRaises(RuntimeError):
                    helm_release.deploy(self.runtime, 'identity-service', selected)
        self.assertEqual(self.runtime.commands, [])

    def test_mutated_content_addressed_local_tag_is_rejected(self):
        self.runtime.image_id = 'sha256:' + 'c' * 64
        with self.assertRaises(RuntimeError):
            helm_release.deploy(self.runtime, 'identity-service', spec())
        self.assertFalse(self.runtime.installed)

    def test_digest_reference_needs_no_mutable_local_tag_trust(self):
        selected = spec()
        selected['values']['image'] = REGISTRY_IMAGE
        self.runtime.documents[0]['spec']['template']['spec']['containers'][0]['image'] = REGISTRY_IMAGE
        helm_release.deploy(self.runtime, 'identity-service', selected)
        self.assertTrue(self.runtime.installed)
        self.assertFalse(any(command[0] == 'docker' for command in self.runtime.commands))

    def test_invalid_names_paths_timeouts_and_rollback_scope_fail_before_commands(self):
        invalid = [('bad/name', spec(), {}), ('identity-service', {'chart': '../escape', 'values': spec()['values']}, {}),
                   ('identity-service', spec(), {'timeout': 0}), ('identity-service', spec(), {'timeout': True}),
                   ('identity-service', spec(), {'timeout': 3601}), ('identity-service', spec(), {'timeout': float('inf')}),
                   ('platform-config', {'chart': 'platform-config', 'values': {'name': 'platform-config'}}, {'rollback': True})]
        for release, selected, kwargs in invalid:
            with self.subTest(release=release, kwargs=kwargs):
                with self.assertRaises(RuntimeError):
                    helm_release.deploy(self.runtime, release, selected, **kwargs)
        self.assertEqual(self.runtime.commands, [])

    def test_wrong_context_or_namespace_is_rejected_before_processes(self):
        for key, value in (('CONTEXT', 'production'), ('NS', 'other')):
            original = getattr(self.runtime, key)
            setattr(self.runtime, key, value)
            with self.assertRaises(RuntimeError):
                helm_release.render(self.runtime, 'identity-service', spec())
            setattr(self.runtime, key, original)
        self.assertEqual(self.runtime.commands, [])

    def test_normal_install_never_claims_unmanaged_original(self):
        original = copy.deepcopy(self.runtime.add_existing())
        with self.assertRaises(RuntimeError):
            helm_release.deploy(self.runtime, 'identity-service', spec())
        self.assertEqual(self.runtime.objects[('Deployment', 'identity-service')], original)
        self.assertFalse(self.runtime.installed)
        self.assertEqual(self.runtime.patches, [])

    def test_inventory_read_failure_is_not_treated_as_missing(self):
        self.runtime.fail_get = True
        with self.assertRaises(RuntimeError):
            helm_release.adopt(self.runtime, {'identity-service': spec()})
        self.assertEqual(self.runtime.patches, [])

    def test_adoption_preserves_uid_spec_and_clears_credential_bearing_last_apply(self):
        original = self.runtime.add_existing()
        original['metadata']['annotations'] = {'kubectl.kubernetes.io/last-applied-configuration': SECRET, 'custom': 'retained'}
        original['spec']['template']['spec']['containers'][0]['image'] = 'old-image:drift-is-allowed'
        before_spec = copy.deepcopy(original['spec'])
        helm_release.adopt(self.runtime, {'identity-service': spec()})
        observed = self.runtime.objects[('Deployment', 'identity-service')]
        self.assertEqual(observed['metadata']['uid'], 'original-uid')
        self.assertEqual(observed['spec'], before_spec)
        self.assertEqual(observed['metadata']['annotations'], {'custom': 'retained', 'meta.helm.sh/release-name': 'identity-service', 'meta.helm.sh/release-namespace': 'sso-remediation'})
        self.assertEqual(observed['metadata']['labels']['app.kubernetes.io/managed-by'], 'Helm')
        helm_release.adopt(self.runtime, {'identity-service': spec()})
        self.assertEqual(observed['metadata']['uid'], 'original-uid')

    def test_all_inventory_is_validated_before_any_metadata_patch(self):
        self.runtime.add_existing()
        other = {'apiVersion': 'v1', 'kind': 'Service',
                 'metadata': {'name': 'identity-service', 'namespace': 'sso-remediation'},
                 'spec': {'selector': {'app': 'identity-service'}, 'ports': [{'port': 8001}]}}
        self.runtime.documents.append(other)
        self.runtime.add_existing(other)['metadata']['ownerReferences'] = [{'apiVersion': 'postgresql.cnpg.io/v1', 'kind': 'Cluster', 'name': 'postgres', 'uid': 'operator-parent'}]
        with self.assertRaises(RuntimeError):
            helm_release.adopt(self.runtime, {'identity-service': spec()})
        self.assertEqual(self.runtime.patches, [])

    def test_foreign_owner_namespace_uid_and_selector_mismatches_are_never_adopted(self):
        mutations = [lambda obj: obj['metadata'].update(namespace='other'),
                     lambda obj: obj['metadata'].pop('uid'),
                     lambda obj: obj['metadata'].update(annotations={'meta.helm.sh/release-name': 'foreign'}),
                     lambda obj: obj['metadata'].update(annotations={'meta.helm.sh/release-namespace': 'foreign'}),
                     lambda obj: obj['metadata'].update(labels={'app.kubernetes.io/managed-by': 'operator'}),
                     lambda obj: obj['spec'].update(selector={'matchLabels': {'app': 'unrelated'}})]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                self.runtime.objects.clear()
                mutate(self.runtime.add_existing())
                with self.assertRaises(RuntimeError):
                    helm_release.adopt(self.runtime, {'identity-service': spec()})
        self.assertEqual(self.runtime.patches, [])

    def test_duplicate_and_unrecognized_desired_inventory_fail_closed(self):
        for documents in ([deployment(), deployment()], [deployment('unrecognized-service')],
                          [{'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': 'sso-remediation'}}]):
            with self.subTest(documents=documents):
                self.runtime.documents = documents
                with self.assertRaises(RuntimeError):
                    helm_release.adopt(self.runtime, {'identity-service': spec()})
        self.assertEqual(self.runtime.patches, [])

    def test_pvc_and_cnpg_without_keep_policy_are_rejected(self):
        for chart, release, resource in [('platform-postgres', 'postgres', {'apiVersion': 'postgresql.cnpg.io/v1', 'kind': 'Cluster', 'metadata': {'namespace': 'sso-remediation', 'name': 'postgres'}, 'spec': {}}),
                                         ('platform-mailpit', 'mailpit', {'apiVersion': 'v1', 'kind': 'PersistentVolumeClaim', 'metadata': {'namespace': 'sso-remediation', 'name': 'mailpit'}, 'spec': {}})]:
            with self.subTest(kind=resource['kind']):
                (self.runtime.ROOT / 'charts' / chart).mkdir()
                self.runtime.documents = [resource]
                selected = {'chart': chart, 'values': {'name': release, 'image': REGISTRY_IMAGE, 'credential': SECRET}}
                with self.assertRaises(RuntimeError):
                    helm_release.deploy(self.runtime, release, selected)
        self.assertFalse(self.runtime.installed)

    def test_failed_first_install_never_uninstalls_adopted_resources_or_leaks_output(self):
        self.runtime.add_existing()
        self.runtime.fail_operation = 'install'
        with self.assertRaises(RuntimeError) as error:
            helm_release.deploy(self.runtime, 'identity-service', spec(), adopt=True)
        self.assertNotIn(SECRET, str(error.exception))
        self.assertIsNone(error.exception.__cause__)
        self.assertEqual(self.runtime.objects[('Deployment', 'identity-service')]['metadata']['uid'], 'original-uid')
        self.assertFalse(any('uninstall' in command or '--rollback-on-failure' in command for command in self.runtime.commands))
        evidence_files = list((self.runtime.STATE / 'helm-failures').glob('*.json'))
        self.assertEqual(len(evidence_files), 1)
        self.assertEqual(os.stat(evidence_files[0]).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(evidence_files[0].parent).st_mode & 0o777, 0o700)
        self.assertIn(evidence_files[0].name, str(error.exception))
        evidence = json.loads(evidence_files[0].read_text())
        self.assertEqual(evidence['returncode'], 1)
        self.assertEqual(evidence['stderr'], SECRET)
        self.assertNotIn('stdout', evidence)
        self.assertNotIn('input', evidence)

    def test_existing_app_readiness_failure_uses_bounded_safe_rollback_without_values_leak(self):
        self.runtime.installed = True
        self.runtime.fail_operation = 'upgrade'
        with self.assertRaises(RuntimeError) as error:
            helm_release.deploy(self.runtime, 'identity-service', spec(), timeout=17, rollback=True)
        self.assertNotIn(SECRET, str(error.exception))
        upgrade = next(command for command in self.runtime.commands if command[1] == 'upgrade')
        self.assertIn('--rollback-on-failure', upgrade)
        self.assertIn('--server-side=false', upgrade)
        self.assertIn('--wait=legacy', upgrade)
        self.assertEqual(upgrade[upgrade.index('--timeout') + 1], '17s')
        self.assertFalse(any('--take-ownership' in command for command in self.runtime.commands))

    def test_pending_or_failed_revision_requires_explicit_recovery(self):
        self.runtime.installed = True
        for state in ('pending-upgrade', 'pending-install', 'pending-rollback', 'failed', 'uninstalling'):
            with self.subTest(state=state):
                self.runtime.release_status = state
                with self.assertRaises(RuntimeError):
                    helm_release.deploy(self.runtime, 'identity-service', spec())
        self.assertFalse(any(command[1] in ('install', 'upgrade') for command in self.runtime.commands if command[0] != 'docker'))

    def test_history_and_status_exclude_secret_bearing_descriptions_and_notes(self):
        self.runtime.installed = True
        result = {'history': helm_release.history(self.runtime, 'identity-service'), 'status': helm_release.status(self.runtime, 'identity-service')}
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertEqual(result['history'][0]['revision'], 1)
        self.assertEqual(result['status']['status'], 'deployed')
        self.assertEqual(helm_release.current_values(self.runtime, 'identity-service'), self.runtime.release_values)

    def test_rollback_rejects_missing_failed_and_invalid_revisions(self):
        self.runtime.installed = True
        self.runtime.revisions.append({'revision': 2, 'status': 'failed', 'description': SECRET})
        for revision in (0, -1, True, '1', 2, 9):
            with self.subTest(revision=revision):
                with self.assertRaises(RuntimeError):
                    helm_release.rollback(self.runtime, 'identity-service', revision)
        self.assertFalse(any(command[1] == 'rollback' for command in self.runtime.commands))
        helm_release.rollback(self.runtime, 'identity-service', 1, timeout=19)
        rollback_command = next(command for command in self.runtime.commands if command[1] == 'rollback')
        self.assertIn('--wait=legacy', rollback_command)
        self.assertIn('--server-side=false', rollback_command)

    def test_render_rejects_scalar_and_unexpected_private_output(self):
        for document in (['not-a-resource'], {'metadata': {'name': 'identity-service'}, 'kind': 'Secret', 'apiVersion': 'v1'}):
            with self.subTest(document=document):
                self.runtime.documents = [document]
                with self.assertRaises(RuntimeError) as error:
                    helm_release.render(self.runtime, 'identity-service', spec())
                self.assertNotIn(SECRET, str(error.exception))

    def test_nested_mutable_init_container_is_rejected(self):
        self.runtime.documents[0]['spec']['template']['spec']['initContainers'] = [{'name': 'database-gate', 'image': 'postgres:latest'}]
        with self.assertRaises(RuntimeError):
            helm_release.deploy(self.runtime, 'identity-service', spec())
        self.assertFalse(self.runtime.installed)

    def test_adoption_never_changes_secret_data_and_rejects_different_credentials(self):
        (self.runtime.ROOT / 'charts' / 'platform-config').mkdir()
        secret = {'apiVersion': 'v1', 'kind': 'Secret',
                  'metadata': {'name': 'platform-secrets', 'namespace': 'sso-remediation'},
                  'type': 'Opaque', 'data': {'password': 'cHJvdGVjdGVk'}}
        self.runtime.documents = [secret]
        existing = self.runtime.add_existing(secret)
        selected = {'chart': 'platform-config', 'values': {'name': 'platform-config', 'credential': SECRET}}
        helm_release.adopt(self.runtime, {'platform-config': selected})
        self.assertEqual(existing['data'], {'password': 'cHJvdGVjdGVk'})
        self.assertEqual(existing['metadata']['uid'], 'original-uid')
        self.runtime.patches.clear()
        existing['data']['password'] = 'ZGlmZmVyZW50'
        with self.assertRaises(RuntimeError):
            helm_release.adopt(self.runtime, {'platform-config': selected})
        self.assertEqual(self.runtime.patches, [])

    def test_infrastructure_upgrades_never_automatically_roll_back(self):
        (self.runtime.ROOT / 'charts' / 'platform-postgres').mkdir()
        self.runtime.installed = True
        self.runtime.installed_name = 'postgres'
        self.runtime.documents = [{'apiVersion': 'postgresql.cnpg.io/v1', 'kind': 'Cluster',
                                   'metadata': {'namespace': 'sso-remediation', 'name': 'postgres',
                                                'annotations': {'helm.sh/resource-policy': 'keep'}},
                                   'spec': {'imageName': REGISTRY_IMAGE}}]
        selected = {'chart': 'platform-postgres', 'values': {'name': 'postgres', 'image': REGISTRY_IMAGE, 'credential': SECRET}}
        helm_release.deploy(self.runtime, 'postgres', selected)
        upgrade = next(command for command in self.runtime.commands if command[1] == 'upgrade')
        self.assertNotIn('--rollback-on-failure', upgrade)

    def test_stale_kubectl_credentials_require_explicit_metadata_cleanup(self):
        existing = self.runtime.add_existing()
        existing['metadata']['labels'] = {'app.kubernetes.io/managed-by': 'Helm'}
        existing['metadata']['annotations'] = {'meta.helm.sh/release-name': 'identity-service',
                                               'meta.helm.sh/release-namespace': 'sso-remediation',
                                               'kubectl.kubernetes.io/last-applied-configuration': SECRET}
        with self.assertRaises(RuntimeError):
            helm_release.deploy(self.runtime, 'identity-service', spec())
        self.assertFalse(self.runtime.installed)

    def test_process_exception_is_private_and_preserves_actionable_diagnostics(self):
        original_run = self.runtime.run
        def unavailable(command, **kwargs):
            if str(command[0]) != 'docker':
                raise OSError('missing helm binary; ' + SECRET)
            return original_run(command, **kwargs)
        self.runtime.run = unavailable
        with self.assertRaises(RuntimeError) as error:
            helm_release.render(self.runtime, 'identity-service', spec())
        self.assertNotIn(SECRET, str(error.exception))
        evidence_files = list((self.runtime.STATE / 'helm-failures').glob('*.json'))
        self.assertEqual(len(evidence_files), 1)
        evidence = json.loads(evidence_files[0].read_text())
        self.assertEqual(evidence['exception_type'], 'OSError')
        self.assertIn('missing helm binary', evidence['exception'])
        self.assertEqual(os.stat(evidence_files[0]).st_mode & 0o777, 0o600)

    def test_adoption_accepts_api_normalized_empty_network_selector_but_not_changed_labels(self):
        (self.runtime.ROOT / 'charts' / 'platform-config').mkdir()
        policy = {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
                  'metadata': {'name': 'allow-dns', 'namespace': 'sso-remediation'},
                  'spec': {'podSelector': {'matchLabels': {}, 'matchExpressions': []}, 'policyTypes': ['Egress']}}
        self.runtime.documents = [policy]
        existing = self.runtime.add_existing(policy)
        existing['spec']['podSelector'] = {}
        selected = {'chart': 'platform-config', 'values': {'name': 'platform-config', 'credential': SECRET}}
        helm_release.adopt(self.runtime, {'platform-config': selected})
        self.assertEqual(existing['metadata']['uid'], 'original-uid')
        self.assertEqual(existing['spec']['podSelector'], {})
        self.assertEqual(len(self.runtime.patches), 1)
        self.runtime.patches.clear()
        for changed in ({'matchLabels': {'app': 'foreign'}},
                        {'matchExpressions': [{'key': 'app', 'operator': 'Exists'}]}):
            with self.subTest(selector=changed):
                existing['spec']['podSelector'] = changed
                with self.assertRaises(RuntimeError):
                    helm_release.adopt(self.runtime, {'platform-config': selected})
        self.assertEqual(self.runtime.patches, [])

    def rekey_secret(self):
        original = {'encryption_key': 'legacy'}
        secret = {'apiVersion': 'v1', 'kind': 'Secret',
                  'metadata': {'name': 'platform-secrets', 'namespace': 'sso-remediation'},
                  'type': 'Opaque', 'data': {'encryption_key': 'bGVnYWN5'}}
        return original, self.runtime.add_existing(secret)

    def test_legacy_rekey_preflight_then_one_time_publication_preserves_identity(self):
        original, existing = self.rekey_secret()
        plan = helm_release.prepare_rekey(self.runtime, original)
        self.assertEqual(self.runtime.patches, [])
        from private_files import atomic_json
        atomic_json(self.runtime.STATE / 'rekey-complete-test.json', {'keys': {**original, 'mfa_encryption_key': 'target'}})
        helm_release.publish_rekey(self.runtime, plan, {'mfa_encryption_key': 'target'})
        self.assertEqual(existing['data'], {'mfa_encryption_key': 'dGFyZ2V0'})
        self.assertEqual(existing['metadata']['uid'], 'original-uid')
        self.assertNotIn('annotations', existing['metadata'])
        self.assertEqual(len(self.runtime.patches), 1)
        with self.assertRaises(RuntimeError):
            helm_release.publish_rekey(self.runtime, plan, {'mfa_encryption_key': 'target'})

    def test_legacy_rekey_refuses_wrong_data_or_any_helm_controller_claim_before_work(self):
        original, existing = self.rekey_secret()
        for metadata in ({'annotations': {'meta.helm.sh/release-name': 'platform-config'}},
                         {'labels': {'app.kubernetes.io/managed-by': 'Helm'}},
                         {'ownerReferences': [{'kind': 'Cluster', 'name': 'postgres'}]}):
            with self.subTest(metadata=metadata):
                base = copy.deepcopy(existing['metadata'])
                existing['metadata'].update(metadata)
                with self.assertRaises(RuntimeError):
                    helm_release.prepare_rekey(self.runtime, original)
                existing['metadata'] = base
        with self.assertRaises(RuntimeError):
            helm_release.prepare_rekey(self.runtime, {'encryption_key': 'different'})
        self.assertEqual(self.runtime.patches, [])

    def test_legacy_publication_refuses_changed_owner_data_or_resource_version(self):
        original, existing = self.rekey_secret()
        plan = helm_release.prepare_rekey(self.runtime, original)
        existing['metadata']['resourceVersion'] = '43'
        with self.assertRaises(RuntimeError):
            helm_release.publish_rekey(self.runtime, plan, {'mfa_encryption_key': 'target'})
        existing['metadata']['resourceVersion'] = '42'
        self.runtime.installed = True
        self.runtime.installed_name = 'platform-config'
        with self.assertRaises(RuntimeError):
            helm_release.publish_rekey(self.runtime, plan, {'mfa_encryption_key': 'target'})
        self.assertEqual(self.runtime.patches, [])

    def test_managed_rekey_uses_helm_and_never_falls_back_on_upgrade_failure(self):
        original, existing = self.rekey_secret()
        (self.runtime.ROOT / 'charts' / 'platform-config').mkdir()
        self.runtime.installed = True
        self.runtime.installed_name = 'platform-config'
        existing['metadata'].update(labels={'app.kubernetes.io/managed-by': 'Helm'}, annotations={'meta.helm.sh/release-name': 'platform-config', 'meta.helm.sh/release-namespace': 'sso-remediation'})
        self.runtime.release_values = {'name': 'platform-config', 'credential': SECRET, 'secrets': {'platform-secrets': {'encryption_key': 'bGVnYWN5'}}}
        self.runtime.documents = [copy.deepcopy(existing)]
        plan = helm_release.prepare_rekey(self.runtime, original)
        from private_files import atomic_json
        atomic_json(self.runtime.STATE / 'rekey-complete-test.json', {'keys': {**original, 'mfa_encryption_key': 'target'}})
        self.runtime.fail_operation = 'upgrade'
        with self.assertRaises(RuntimeError):
            helm_release.publish_rekey(self.runtime, plan, {'mfa_encryption_key': 'target'})
        self.assertEqual(existing['data'], {'encryption_key': 'bGVnYWN5'})
        self.assertEqual(self.runtime.patches, [])
        self.runtime.release_status = 'failed'
        with self.assertRaises(RuntimeError):
            helm_release.prepare_rekey(self.runtime, original)

    def test_explicit_config_restore_accepts_failed_but_not_pending_or_absent(self):
        (self.runtime.ROOT / 'charts' / 'platform-config').mkdir()
        self.runtime.documents = [{'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'alerts-yml', 'namespace': 'sso-remediation'}, 'data': {'alerts.yml': 'original'}}]
        self.runtime.installed_name = 'platform-config'
        values = {'name': 'platform-config', 'credential': SECRET}
        for state in ('pending-install', 'pending-upgrade', 'pending-rollback'):
            self.runtime.installed = True
            self.runtime.release_status = state
            with self.assertRaises(RuntimeError):
                helm_release.restore_config(self.runtime, values, timeout=12)
        self.runtime.installed = False
        with self.assertRaises(RuntimeError):
            helm_release.restore_config(self.runtime, values)
        self.runtime.installed = True
        self.runtime.release_status = 'failed'
        helm_release.restore_config(self.runtime, values, timeout=12)
        upgrades = [command for command in self.runtime.commands if len(command) > 1 and command[1] == 'upgrade']
        self.assertEqual(len(upgrades), 1)
        self.assertIn('--wait=legacy', upgrades[0])
        self.assertNotIn('--rollback-on-failure', upgrades[0])

    def test_successful_rollback_reconciles_only_existing_selected_image_record(self):
        self.runtime.installed = True
        path = self.runtime.STATE / 'release-images.json'
        path.write_text(json.dumps({'identity-service': REGISTRY_IMAGE, 'frontend': REGISTRY_IMAGE}))
        helm_release.rollback(self.runtime, 'identity-service', 1)
        self.assertEqual(json.loads(path.read_text()), {'identity-service': IMAGE, 'frontend': REGISTRY_IMAGE})
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        path.unlink()
        helm_release.rollback(self.runtime, 'identity-service', 1)
        self.assertFalse(path.exists())

    def test_rekey_retry_accepts_only_archived_exact_added_purpose_targets(self):
        original, existing = self.rekey_secret()
        retry = {**original, 'mfa_encryption_key': 'target'}
        with self.assertRaises(RuntimeError):
            helm_release.prepare_rekey(self.runtime, retry)
        from private_files import atomic_json
        archive = self.runtime.STATE / 'rekey-precommit-test.json'
        atomic_json(archive, {'keys': retry})
        plan = helm_release.prepare_rekey(self.runtime, retry)
        self.assertEqual(plan['data'], {'encryption_key': 'bGVnYWN5'})
        with self.assertRaises(RuntimeError):
            helm_release.prepare_rekey(self.runtime, {**retry, 'gateway_token': 'changed'})
        helm_release.publish_rekey(self.runtime, plan, {'mfa_encryption_key': 'target'})
        self.assertEqual(existing['data'], {'mfa_encryption_key': 'dGFyZ2V0'})

    def test_rekey_crash_after_publication_requires_exact_complete_archive_for_retry(self):
        original, existing = self.rekey_secret()
        retry = {**original, 'mfa_encryption_key': 'target'}
        existing['data'] = {'mfa_encryption_key': 'dGFyZ2V0'}
        from private_files import atomic_json
        atomic_json(self.runtime.STATE / 'rekey-precommit-test.json', {'keys': retry})
        with self.assertRaises(RuntimeError):
            helm_release.prepare_rekey(self.runtime, retry)
        atomic_json(self.runtime.STATE / 'rekey-complete-test.json', {'keys': retry})
        plan = helm_release.prepare_rekey(self.runtime, retry)
        helm_release.publish_rekey(self.runtime, plan, {'mfa_encryption_key': 'target'})
        self.assertEqual(self.runtime.patches, [])
        existing['data']['mfa_encryption_key'] = 'b3RoZXI='
        with self.assertRaises(RuntimeError):
            helm_release.prepare_rekey(self.runtime, retry)

    def test_complete_rollout_failure_restores_prior_success_and_still_fails(self):
        self.runtime.installed = True
        self.runtime.fail_rollout = True
        with self.assertRaises(RuntimeError) as error:
            helm_release.deploy(self.runtime, 'identity-service', spec(), timeout=23)
        self.assertNotIn(SECRET, str(error.exception))
        rollout = next(command for command in self.runtime.commands if command[0] == 'kubectl' and 'rollout' in command)
        self.assertIn('deployment/identity-service', rollout)
        self.assertIn('--timeout=23s', rollout)
        recovery = [command for command in self.runtime.commands if command[0] == 'helm' and command[1] == 'rollback']
        self.assertEqual(len(recovery), 1)
        self.assertEqual(recovery[0][2:4], ['identity-service', '1'])

    def test_complete_rollout_failure_on_first_install_never_rolls_back(self):
        self.runtime.fail_rollout = True
        with self.assertRaises(RuntimeError):
            helm_release.deploy(self.runtime, 'identity-service', spec(), timeout=23)
        self.assertFalse(any(command[0] == 'helm' and command[1] in ('rollback', 'uninstall') for command in self.runtime.commands))

    def test_rekey_publication_cannot_remove_or_rotate_unrelated_credentials(self):
        original, existing = self.rekey_secret()
        original['gateway_token'] = 'protected'
        existing['data']['gateway_token'] = 'cHJvdGVjdGVk'
        plan = helm_release.prepare_rekey(self.runtime, original)
        from private_files import atomic_json
        atomic_json(self.runtime.STATE / 'rekey-complete-test.json', {'keys': {**original, 'mfa_encryption_key': 'target'}})
        for final in ({'mfa_encryption_key': 'target'}, {'gateway_token': 'rotated', 'mfa_encryption_key': 'target'},
                      {'gateway_token': 'protected', 'mfa_encryption_key': 'unarchived'}):
            with self.subTest(final=final):
                with self.assertRaises(RuntimeError):
                    helm_release.publish_rekey(self.runtime, plan, final)
        self.assertEqual(self.runtime.patches, [])

    def test_rollback_wait_failure_does_not_reconcile_selection_or_recurse(self):
        self.runtime.installed = True
        self.runtime.fail_rollout = True
        path = self.runtime.STATE / 'release-images.json'
        path.write_text(json.dumps({'identity-service': REGISTRY_IMAGE}))
        with self.assertRaises(RuntimeError):
            helm_release.rollback(self.runtime, 'identity-service', 1, timeout=23)
        self.assertEqual(json.loads(path.read_text()), {'identity-service': REGISTRY_IMAGE})
        self.assertEqual(len([command for command in self.runtime.commands if command[0] == 'helm' and command[1] == 'rollback']), 1)


if __name__ == '__main__':
    unittest.main()
