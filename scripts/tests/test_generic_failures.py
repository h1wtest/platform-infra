"""Behavioral fault ownership tests; fake Kubernetes boundary, no live cluster."""
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import base64
import tempfile

ACCEPTANCE = Path(__file__).resolve().parents[1] / 'acceptance'
import sys
sys.path.insert(0, str(ACCEPTANCE))
import generic_failures


class FakeKubernetes:
    """Atomic JSONPatch tests emulate the API boundary, including a replacement race."""
    def __init__(self):
        self.object = {'metadata': {'uid': 'owned-workload', 'resourceVersion': '1'},
                       'spec': {'replicas': 2, 'template': {'unchanged': True}}}
        self.race = False
        self.version_race = False
        self.operations = []

    def invoke(self, *args, **kwargs):
        if self.race:
            self.object['metadata'] = {'uid': 'replacement-workload', 'resourceVersion': '2'}
            self.race = False
        if self.version_race:
            self.object['metadata']['resourceVersion'] = '99'
            self.object['spec']['template'] = {'concurrent_update': True}
            self.version_race = False
        self.operations.append(args)
        if args[0] == 'scale':
            # Old unsafe implementation can mutate the replacement because the
            # original replica count is identical. Keep this to prove RED.
            value = next(value for value in args if value.startswith('--replicas='))
            self.object['spec']['replicas'] = int(value.split('=')[1])
        elif args[0] == 'patch':
            patch = json.loads(args[args.index('-p') + 1])
            candidate = deepcopy(self.object)
            for operation in patch:
                parent = candidate
                pieces = operation['path'].strip('/').split('/')
                for piece in pieces[:-1]:
                    parent = parent[piece]
                key = pieces[-1]
                if operation['op'] == 'test':
                    if parent[key] != operation['value']:
                        raise AssertionError('API rejected stale JSONPatch precondition')
                elif operation['op'] == 'replace':
                    parent[key] = operation['value']
                else:
                    raise AssertionError('Unexpected patch operation')
            candidate['metadata']['resourceVersion'] = str(int(candidate['metadata']['resourceVersion']) + 1)
            self.object = candidate
        else:
            raise AssertionError('Unexpected Kubernetes mutation')
        return json.dumps(self.object)


def runtime():
    api = FakeKubernetes()
    acceptance = generic_failures.Acceptance.__new__(generic_failures.Acceptance)
    acceptance.args = SimpleNamespace(case='smtp', timeout=1)
    acceptance.state = {'faults': []}
    acceptance.persisted = []
    acceptance.persist = lambda: acceptance.persisted.append(deepcopy(acceptance.state))
    acceptance.passed = lambda *args, **kwargs: None
    acceptance.ready = lambda *args: deepcopy(api.object)
    acceptance.get = lambda *args: deepcopy(api.object)
    acceptance.controlled_pods = lambda *args: []
    acceptance.kube = api.invoke
    return acceptance, api


class GenericFaultOwnershipBehavior(unittest.TestCase):
    def test_replacement_between_snapshot_and_down_patch_is_not_mutated(self):
        acceptance, api = runtime()
        api.race = True
        with self.assertRaises(AssertionError):
            with acceptance.outage():
                self.fail('Replacement workload must never enter outage body')
        self.assertEqual(api.object['metadata']['uid'], 'replacement-workload')
        self.assertEqual(api.object['spec']['replicas'], 2, 'Foreign replacement was scaled down')
        self.assertFalse(acceptance.state['faults'][0]['restored'])
        self.assertEqual(acceptance.persisted[0]['faults'][0]['original_replicas'], 2)

    def test_replacement_between_restore_read_and_patch_is_not_mutated(self):
        acceptance, api = runtime()
        with self.assertRaises(AssertionError):
            with acceptance.outage():
                self.assertEqual(api.object['spec']['replicas'], 0)
                api.race = True
        self.assertEqual(api.object['metadata']['uid'], 'replacement-workload')
        self.assertEqual(api.object['spec']['replicas'], 0, 'Foreign replacement was scaled up')
        self.assertFalse(acceptance.state['faults'][0]['restored'])

    def test_successful_outage_restores_original_replicas_and_journal(self):
        acceptance, api = runtime()
        original = deepcopy(api.object['spec'])
        with acceptance.outage():
            self.assertEqual(api.object['spec']['replicas'], 0)
            self.assertFalse(acceptance.state['faults'][0]['restored'])
        self.assertEqual(api.object['spec'], original)
        self.assertTrue(acceptance.state['faults'][0]['restored'])

    def test_concurrent_write_between_read_and_down_patch_is_preserved(self):
        acceptance, api = runtime()
        api.version_race = True
        with self.assertRaises(AssertionError):
            with acceptance.outage():
                self.fail('Stale workload snapshot must not enter outage body')
        self.assertEqual(api.object['spec']['replicas'], 2)
        self.assertEqual(api.object['spec']['template'], {'concurrent_update': True})

    def test_concurrent_write_between_restore_read_and_patch_is_preserved(self):
        acceptance, api = runtime()
        with self.assertRaises(AssertionError):
            with acceptance.outage():
                api.version_race = True
        self.assertEqual(api.object['spec']['replicas'], 0)
        self.assertEqual(api.object['spec']['template'], {'concurrent_update': True})
        self.assertFalse(acceptance.state['faults'][0]['restored'])

    def test_operator_scale_before_restore_read_is_not_overwritten(self):
        acceptance, api = runtime()
        with self.assertRaises(AssertionError):
            with acceptance.outage():
                api.object['spec']['replicas'] = 3
                api.object['metadata']['resourceVersion'] = '80'
        self.assertEqual(api.object['spec']['replicas'], 3)
        self.assertFalse(acceptance.state['faults'][0]['restored'])

    def test_operator_spec_edit_before_restore_read_is_not_mutated(self):
        acceptance, api = runtime()
        with self.assertRaises(AssertionError):
            with acceptance.outage():
                api.object['spec']['template'] = {'operator_edit': True}
                api.object['metadata']['resourceVersion'] = '80'
        self.assertEqual(api.object['spec']['replicas'], 0)
        self.assertEqual(api.object['spec']['template'], {'operator_edit': True})
        self.assertFalse(acceptance.state['faults'][0]['restored'])

    def test_cancellation_unwinds_lock_and_restores_actual_original_replicas(self):
        import signal
        import tempfile
        acceptance, api = runtime()
        previous = signal.getsignal(signal.SIGTERM)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(KeyboardInterrupt):
                with generic_failures.fault_lifecycle.exclusive(Path(directory)):
                    with acceptance.outage():
                        signal.raise_signal(signal.SIGTERM)
            with generic_failures.fault_lifecycle.exclusive(Path(directory)):
                pass
        self.assertEqual(api.object['spec']['replicas'], 2)
        self.assertTrue(acceptance.state['faults'][0]['restored'])
        self.assertEqual(signal.getsignal(signal.SIGTERM), previous)

    def test_external_sigterm_child_restores_journal_before_exit(self):
        import signal
        import subprocess
        program = '''
import json,pathlib,signal,sys,time
sys.path.insert(0,sys.argv[1])
from test_generic_failures import runtime,generic_failures
a,api=runtime()
root=pathlib.Path(sys.argv[2])
try:
    with generic_failures.fault_lifecycle.exclusive(root):
        with a.outage():
            print('FAULT_ACTIVE',flush=True)
            time.sleep(20)
except KeyboardInterrupt:
    (root/'result.json').write_text(json.dumps({'replicas':api.object['spec']['replicas'],'restored':a.state['faults'][0]['restored']}))
    sys.exit(130)
'''
        with tempfile.TemporaryDirectory() as directory:
            child = subprocess.Popen([sys.executable, '-c', program, str(Path(__file__).resolve().parent), directory],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                import select
                self.assertTrue(select.select([child.stdout], [], [], 5)[0], 'Child did not enter fault before deadline')
                self.assertEqual(child.stdout.readline().strip(), 'FAULT_ACTIVE')
                child.send_signal(signal.SIGTERM)
                self.assertEqual(child.wait(timeout=5), 130)
                result = json.loads((Path(directory) / 'result.json').read_text())
                self.assertEqual(result, {'replicas': 2, 'restored': True})
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=5)
                child.stdout.close()
                child.stderr.close()


class GenericFaultGuardBehavior(unittest.TestCase):
    def test_guard_binds_namespace_and_cluster_uids_and_rejects_proxy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / '.generic-local'
            root.mkdir()
            ca = root / 'ca.crt'
            ca.write_bytes(b'test-root')
            namespace = {'metadata': {'name': generic_failures.NS, 'uid': 'owned-namespace',
                                     'labels': {'platform.local/profile': 'generic'}}}
            config = {'clusters': [{'cluster': {'server': 'https://127.0.0.1:6445',
                                                'certificate-authority-data': 'test-root'}}],
                      'contexts': [{'name': generic_failures.CONTEXT}], 'current-context': generic_failures.CONTEXT,
                      'users': []}
            identity = {'schema': 1, 'context': generic_failures.CONTEXT, 'server': 'https://127.0.0.1:6445',
                        'cluster_uid': 'owned-cluster', 'namespace': generic_failures.NS, 'namespace_uid': 'owned-namespace'}
            import cluster_identity
            baseline = root / 'namespace-identity.json'
            baseline.write_text(json.dumps({'identity': identity, 'sha256': cluster_identity.digest(identity)}))
            baseline.chmod(0o400)
            acceptance = generic_failures.Acceptance.__new__(generic_failures.Acceptance)
            acceptance.args = SimpleNamespace(case='smtp', ca=ca)
            acceptance.ready = lambda *args: None
            acceptance.passed = lambda *args, **kwargs: None
            acceptance.credentials = {}
            cluster_uid = 'owned-cluster'
            def get(kind, name=None):
                if kind == 'namespace':
                    return {'metadata': {'uid': cluster_uid}} if name == 'kube-system' else deepcopy(namespace)
                if kind == 'secret':
                    return {'data': {'ca.crt': base64.b64encode(b'test-root').decode()}}
                raise AssertionError('Unexpected guard API call')
            acceptance.get = get
            acceptance.kube = lambda *args, **kwargs: json.dumps(config)
            with patch.object(generic_failures, 'ROOT', root):
                acceptance.guard()
                config['clusters'][0]['cluster']['proxy-url'] = 'http://127.0.0.1:9999'
                with self.assertRaises((AssertionError, RuntimeError)):
                    acceptance.guard()
                del config['clusters'][0]['cluster']['proxy-url']
                namespace['metadata']['uid'] = 'replacement-namespace'
                with self.assertRaises((AssertionError, RuntimeError)):
                    acceptance.guard()
                namespace['metadata']['uid'] = 'owned-namespace'
                cluster_uid = 'replacement-cluster'
                with self.assertRaises((AssertionError, RuntimeError)):
                    acceptance.guard()


if __name__ == '__main__':
    unittest.main()
