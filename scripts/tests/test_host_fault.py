"""Non-destructive regressions for Windows host-fault process and finalization boundaries."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('verify_docker_host', SCRIPTS / 'verify_docker_host.py')
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)
sys.path.insert(0, str(SCRIPTS / 'acceptance'))
import host_state


class OwnedApi:
    """Stateful API boundary: logout actually invalidates the saved session."""
    def __init__(self):
        self.revoked = False
        self.name = 'marker profile'
        self.logins = 0
        self.csrf = 'private'
        self.jar = []
        self.login_intents = []

    def bootstrap_csrf(self):
        self.csrf = 'bootstrap'

    def login(self, email, password):
        self.logins += 1
        self.revoked = False

    def call(self, method, path, body=None, **kwargs):
        sid = '00000000-0000-0000-0000-000000000001'
        actor = {'user': {'id': 'owner'}, 'session_id': sid}
        if path.endswith('/auth/login'):
            intent = json.loads(host_state.state_path().read_text())['acquisitions'][-1]
            self.login_intents.append(intent['state'])
            self.logins += 1
            self.revoked = False
            return 200, {**actor, 'status': 'authenticated', 'csrf_token': 'private'}, {}
        if self.revoked:
            if path.endswith('/auth/me'):
                if 401 not in kwargs.get('expected', (200,)):
                    raise AssertionError('GET /auth/me: expected 200, got 401')
                return 401, {}, {}
            raise RuntimeError('Session revoked')
        if path.endswith('/auth/me'):
            return 200, actor, {}
        if path.endswith('/users/me'):
            if method == 'PATCH':
                self.name = body['display_name']
            return 200, {'profile': {'user_id': 'owner', 'display_name': self.name}}, {}
        if path.endswith('/auth/sessions'):
            return 200, [{'session_id': sid}], {}
        if path.endswith('/auth/logout'):
            self.revoked = True
            return 200, {}, {}
        raise AssertionError('Unexpected API operation')


@unittest.skipUnless(sys.platform == 'linux', 'Fixture executes only in Ubuntu WSL; requires POSIX fchmod and directory fsync')
class FixtureCleanupTests(unittest.TestCase):
    def fixture(self, directory):
        value = {
            'run_id': '1' * 32, 'database': 'host_fault_' + '2' * 32,
            'marker': 'private', 'user_id': 'owner',
            'session_id': '00000000-0000-0000-0000-000000000001',
            'profile_name': 'marker profile', 'original_profile_name': 'original',
            'cleanup': {}, 'cleanup_session_ids': [],
        }
        (directory / 'host-fault-private.json').write_text(json.dumps(value))
        (directory / 'state.json').write_text(json.dumps({'probe': {'user_id': 'owner', 'email': 'owned@test', 'password': 'private'}}))
        return value

    def test_cleanup_retries_after_logout_and_database_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            value = self.fixture(directory)
            api = OwnedApi()
            with patch.object(host_state, 'STATE', directory), patch.object(host_state, 'saved_client', return_value=api), patch.object(host_state, 'Client', return_value=api), patch.object(host_state.cli, 'dbsql', side_effect=RuntimeError('DB down')):
                with self.assertRaisesRegex(RuntimeError, 'database_removed'):
                    host_state.cleanup(value['run_id'])
                self.assertTrue(api.revoked)
                self.assertEqual(api.name, 'original')
                self.assertTrue((directory / 'host-fault-private.json').exists())
            with patch.object(host_state, 'STATE', directory), patch.object(host_state, 'saved_client', return_value=api), patch.object(host_state, 'Client', return_value=api), patch.object(host_state.cli, 'dbsql', return_value=''):
                host_state.cleanup(value['run_id'])
            self.assertEqual(api.logins, 1)
            self.assertTrue(api.revoked)
            self.assertFalse((directory / 'host-fault-private.json').exists())

    def test_foreign_run_marker_blocks_before_database_or_api_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.fixture(directory)
            with patch.object(host_state, 'STATE', directory), patch.object(host_state.cli, 'dbsql') as sql, patch.object(host_state, 'saved_client') as client:
                with self.assertRaisesRegex(RuntimeError, 'predates'):
                    host_state.cleanup('3' * 32)
                sql.assert_not_called()
                client.assert_not_called()

    def test_cleanup_preserves_newer_profile_and_retains_marker_but_drains_owned_db(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            value = self.fixture(directory)
            api = OwnedApi()
            api.name = 'newer external change'
            with patch.object(host_state, 'STATE', directory), patch.object(host_state, 'saved_client', return_value=api), patch.object(host_state.cli, 'dbsql', return_value='') as sql:
                with self.assertRaisesRegex(RuntimeError, 'profile_restored'):
                    host_state.cleanup(value['run_id'])
                sql.assert_called_once_with('DROP DATABASE IF EXISTS ' + value['database'])
            self.assertEqual(api.name, 'newer external change')
            self.assertTrue(api.revoked)
            self.assertTrue((directory / 'host-fault-private.json').exists())

    def test_verify_uses_no_cleanup_login_when_original_session_revoked(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            value = self.fixture(directory)
            api = OwnedApi()
            api.revoked = True
            with patch.object(host_state, 'STATE', directory), patch.object(host_state, 'saved_client', return_value=api):
                with self.assertRaises(AssertionError):
                    host_state.verify(value['run_id'])
            self.assertEqual(api.logins, 0)

    def test_prepare_failure_after_login_response_has_durable_session_and_can_clean(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.fixture(directory)
            (directory / 'host-fault-private.json').unlink()
            api = OwnedApi()
            real_call = api.call

            def fail_profile(method, path, *args, **kwargs):
                if path.endswith('/users/me'):
                    raise ConnectionError('Profile unavailable after committed login')
                return real_call(method, path, *args, **kwargs)

            with patch.object(host_state, 'STATE', directory), patch.object(host_state, 'Client', return_value=api), patch.object(api, 'call', side_effect=fail_profile):
                with self.assertRaises(ConnectionError):
                    host_state.prepare('1' * 32)
                retained = json.loads((directory / 'host-fault-private.json').read_text())
                self.assertEqual(retained['session_id'], '00000000-0000-0000-0000-000000000001')
                self.assertEqual(retained['acquisitions'][-1]['state'], 'recorded')
                self.assertEqual(api.login_intents, ['intent'])
            with patch.object(host_state, 'STATE', directory), patch.object(host_state, 'saved_client', return_value=api), patch.object(host_state.cli, 'dbsql', return_value=''):
                host_state.cleanup('1' * 32)
            self.assertTrue(api.revoked)
            self.assertFalse((directory / 'host-fault-private.json').exists())

    def test_cleanup_login_publication_failure_revokes_received_session_and_keeps_intent(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            value = self.fixture(directory)
            api = OwnedApi()
            api.revoked = True
            real_publish = host_state.atomic_json

            def fail_recorded(path, document):
                if document.get('acquisitions') and document['acquisitions'][-1]['state'] == 'recorded':
                    raise OSError('Publication failed after login response')
                return real_publish(path, document)

            with patch.object(host_state, 'STATE', directory), patch.object(host_state, 'saved_client', return_value=api), patch.object(host_state, 'Client', return_value=api), patch.object(host_state.cli, 'dbsql', return_value=''), patch.object(host_state, 'atomic_json', side_effect=fail_recorded):
                with self.assertRaisesRegex(RuntimeError, 'cleanup_authentication'):
                    host_state.cleanup(value['run_id'])
            self.assertTrue(api.revoked)
            self.assertEqual(api.login_intents, ['intent'])
            self.assertTrue((directory / 'host-fault-private.json').exists())


@unittest.skipUnless(sys.platform == 'linux', 'Kafka fixture publishes POSIX-private state in Ubuntu WSL')
class KafkaHostFixtureTests(unittest.TestCase):
    def test_acknowledged_coordinates_and_existing_history_detect_changed_payload(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            value = {'run_id': '4' * 32}
            broker = KafkaBoundary()
            with patch.object(host_state, 'STATE', directory), patch.object(host_state, 'rpk', side_effect=broker.call), patch.object(host_state, 'broker_healthy'):
                host_state.prepare_kafka(value)
                self.assertEqual(len(value['kafka']['markers']), 6)
                self.assertEqual({record['partition'] for record in value['kafka']['markers']}, set(range(6)))
                host_state.verify_kafka(value)
                produced = broker.produced
                broker.records[('identity.events.v1', 0, 0)] = (b'original-key', b'changed-value')
                with self.assertRaisesRegex(RuntimeError, 'Kafka record hash'):
                    host_state.verify_kafka(value)
                self.assertEqual(broker.produced, produced)
                self.assertTrue(all('--group' not in call for call in broker.commands))

    def test_consumer_returning_next_offset_is_not_accepted(self):
        broker = KafkaBoundary()
        broker.shift_offset = True
        with patch.object(host_state, 'rpk', side_effect=broker.call):
            with self.assertRaisesRegex(RuntimeError, 'exact requested Kafka coordinate'):
                host_state.read_kafka_record('identity.events.v1', 0, 0, host_state.time.monotonic() + 10)

    def test_empty_existing_topic_is_not_counted_as_history_proof(self):
        with tempfile.TemporaryDirectory() as temporary:
            broker = KafkaBoundary()
            broker.records = {}
            with patch.object(host_state, 'STATE', Path(temporary)), patch.object(host_state, 'rpk', side_effect=broker.call), patch.object(host_state, 'broker_healthy'):
                with self.assertRaisesRegex(RuntimeError, 'no existing records'):
                    host_state.prepare_kafka({'run_id': '5' * 32})

    def test_ack_partition_mismatch_retains_topic_ownership_before_injection(self):
        with tempfile.TemporaryDirectory() as temporary:
            broker = KafkaBoundary()
            broker.bad_ack = True
            directory = Path(temporary)
            with patch.object(host_state, 'STATE', directory), patch.object(host_state, 'rpk', side_effect=broker.call), patch.object(host_state, 'broker_healthy'):
                with self.assertRaisesRegex(RuntimeError, 'acknowledgment'):
                    host_state.prepare_kafka({'run_id': '6' * 32})
            retained = json.loads((directory / 'host-fault-private.json').read_text())
            self.assertEqual(retained['kafka']['topic'], 'acceptance-host-' + '6' * 32)
            self.assertEqual(retained['kafka']['retention_ms'], 86400000)


class KafkaBoundary:
    """Stateful broker boundary: actual consumer coordinates depend on stored log."""
    def __init__(self):
        self.records = {(topic, partition, offset): (b'original-key', ('original-' + str(offset)).encode()) for topic in ('identity.events.v1', 'notification.commands.v1') for partition in range(6) for offset in range(2)}
        self.commands = []
        self.produced = 0
        self.shift_offset = self.bad_ack = False

    def call(self, arguments, *, data=None, deadline=None):
        self.commands.append(arguments)
        action, topic = arguments[1:3]
        if action == 'create':
            self.assert_intent(topic)
            return ''
        if action == 'describe':
            partitions = []
            for partition in range(6):
                offsets = [offset for name, part, offset in self.records if name == topic and part == partition]
                partitions.append({'partition': partition, 'replicas': [0, 1, 2], 'log_start_offset': min(offsets) if offsets else 0, 'high_watermark': max(offsets) + 1 if offsets else 0})
            return json.dumps([{'summary': {'name': topic, 'partitions': 6, 'replicas': 3}, 'partitions': partitions}])
        if action == 'produce':
            partition = int(arguments[arguments.index('--partition') + 1])
            key = arguments[arguments.index('--key') + 1].encode()
            self.records[(topic, partition, 0)] = (key, data.rstrip(b'\n'))
            self.produced += 1
            return json.dumps({'partition': partition + (1 if self.bad_ack else 0), 'offset': 0})
        if action == 'consume':
            partition = int(arguments[arguments.index('--partitions') + 1])
            offset = int(arguments[arguments.index('--offset') + 1])
            key, value = self.records[(topic, partition, offset)]
            return json.dumps({'partition': partition, 'offset': offset + (1 if self.shift_offset else 0), 'key_hex': key.hex(), 'value_hex': value.hex()})
        raise AssertionError('Unexpected Kafka operation')

    def assert_intent(self, topic):
        marker = json.loads(host_state.state_path().read_text())
        if marker['kafka']['topic'] != topic or marker['kafka']['creation_state'] != 'intent':
            raise AssertionError('Topic creation lacks prior durable ownership')


class HostFaultTests(unittest.TestCase):
    def test_native_stderr_is_data_not_failure(self):
        result = host.native([sys.executable, '-c', 'import sys;sys.stderr.write("diagnostic\\n");print("200")'], 3)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), '200')
        self.assertEqual(result.stderr.strip(), 'diagnostic')

    def test_real_blocked_process_is_killed_before_deadline(self):
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            host.native([sys.executable, '-c', 'import time;time.sleep(60)'], 0.2)
        self.assertLess(time.monotonic() - started, 5)

    def test_exhausted_budget_never_launches_process(self):
        with patch.object(host.subprocess, 'run') as run:
            with self.assertRaises(TimeoutError):
                host.native([sys.executable, '-c', 'raise SystemExit(0)'], 0)
            run.assert_not_called()

    def test_finalization_continues_after_failed_action_and_prevents_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            fault = host.HostFault(host.REPOSITORY)
            fault.evidence_file = Path(directory) / 'evidence.json'
            fault.recovered = True
            fault.business_verified = True
            fault.evidence['injection_completed'] = True
            fault.evidence['observations'].append({'phase': 'post_injection', 'available': False})
            actions = []
            fault.attempt_final('cleanup', lambda: (_ for _ in ()).throw(RuntimeError('unavailable')))
            fault.attempt_final('timer_restore', lambda: actions.append('restored'))
            fault.finish()
            evidence = json.loads(fault.evidence_file.read_text())
            self.assertEqual(actions, ['restored'])
            self.assertEqual(evidence['result'], 'FAIL')
            self.assertEqual(evidence['finalization']['cleanup']['status'], 'FAIL')
            self.assertEqual(evidence['finalization']['timer_restore']['status'], 'PASS')

    def test_baseline_failure_is_not_injected_outage(self):
        with tempfile.TemporaryDirectory() as directory:
            fault = host.HostFault(host.REPOSITORY)
            fault.evidence_file = Path(directory) / 'evidence.json'
            fault.evidence['observations'].append({'phase': 'baseline', 'available': False})
            fault.finish()
            self.assertFalse(json.loads(fault.evidence_file.read_text())['outage_observed'])

    def test_preexisting_fixture_blocks_before_native_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '.local/acceptance').mkdir(parents=True)
            marker = root / '.local/acceptance/host-fault-private.json'
            marker.write_text('{"owner":"older run"}')
            fault = host.HostFault(host.REPOSITORY)
            with patch.object(fault, 'resolve_repository', return_value=root), patch.object(fault, 'platform') as platform:
                with self.assertRaisesRegex(RuntimeError, 'predates'):
                    fault.initialize()
                platform.assert_not_called()
            self.assertEqual(marker.read_text(), '{"owner":"older run"}')

    def test_timer_restoration_failure_overrules_completed_business_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            fault = host.HostFault(host.REPOSITORY)
            fault.evidence_file = Path(directory) / 'evidence.json'
            fault.recovered = fault.business_verified = True
            fault.evidence['injection_completed'] = True
            fault.evidence['observations'].append({'phase': 'post_injection', 'available': False})
            fault.attempt_final('timer_restore', lambda: (_ for _ in ()).throw(TimeoutError()))
            self.assertEqual(fault.finish(), 1)
            self.assertEqual(json.loads(fault.evidence_file.read_text())['result'], 'FAIL')

    def test_platform_timeout_propagates_to_linux_children_and_windows_client(self):
        fault = host.HostFault(host.REPOSITORY)
        with patch.object(fault, 'command', return_value=subprocess.CompletedProcess([], 0)) as command:
            fault.helper('readiness', 11)
        arguments, timeout = command.call_args.args
        self.assertEqual(timeout, 11)
        self.assertIn('--kill-after=1s', arguments)
        self.assertIn('8s', arguments)
        self.assertIn('ACCEPTANCE_BASE=https://localhost:8448', arguments)

    def test_cluster_start_program_preserves_home_go_bin_fallback(self):
        with patch('shutil.which', return_value=None), patch.object(Path, 'home', return_value=Path('/owned-home')), patch('subprocess.call', return_value=0) as call, patch.object(sys, 'argv', ['-c', 'sso-remediation', '180s']):
            with self.assertRaises(SystemExit) as exit_result:
                exec(host.CLUSTER_START_PROGRAM, {})
        self.assertEqual(exit_result.exception.code, 0)
        self.assertEqual(call.call_args.args[0], [str(Path('/owned-home/go/bin/k3d')), 'cluster', 'start', 'sso-remediation', '--wait', '--timeout', '180s'])

    def test_explicit_cluster_start_retries_known_cgroup_admission_failure(self):
        fault = host.HostFault(host.REPOSITORY)
        results = iter([
            subprocess.CompletedProcess([], 1, '', 'runc create failed: write /sys/fs/cgroup/docker/id/cgroup.procs: device or resource busy'),
            subprocess.CompletedProcess([], 0, 'existing nodes started', ''),
        ])
        calls = []

        def platform(arguments, timeout, check):
            calls.append(arguments)
            return next(results)

        with patch.object(fault, 'platform', side_effect=platform), patch.object(host.time, 'sleep'):
            fault.start_existing_cluster()
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(call[:4] == ['-c', host.CLUSTER_START_PROGRAM, 'sso-remediation', '180s'] for call in calls))
        attempts = fault.evidence['existing_cluster_start_attempts']
        self.assertEqual(attempts[0]['failure_class'], 'cgroup_admission_busy')
        self.assertEqual(attempts[1]['exit_code'], 0)
        self.assertEqual(fault.evidence['recovery_procedure'], 'Explicit existing-cluster start; not Docker restart-policy-only recovery')

    def test_unknown_cluster_start_failure_is_not_retried_or_accepted(self):
        fault = host.HostFault(host.REPOSITORY)
        result = subprocess.CompletedProcess([], 1, '', 'unknown cluster configuration error')
        with patch.object(fault, 'platform', return_value=result) as platform:
            with self.assertRaisesRegex(RuntimeError, 'existing-cluster start failed'):
                fault.start_existing_cluster()
        self.assertEqual(platform.call_count, 1)
        self.assertEqual(fault.evidence['existing_cluster_start_attempts'][0]['failure_class'], 'other_start_failure')

    def test_desktop_start_waits_for_daemon_before_explicit_cluster_start(self):
        fault = host.HostFault(host.REPOSITORY)
        daemon = iter([subprocess.CompletedProcess([], 1, '', 'starting'), subprocess.CompletedProcess([], 0, '{}', '')])
        events = []

        def command(arguments, timeout, **kwargs):
            events.append(arguments[1:])
            if arguments[1] == 'info':
                return next(daemon)
            return subprocess.CompletedProcess([], 0, '', '')

        with patch.object(fault, 'command', side_effect=command), patch.object(fault, 'start_existing_cluster', side_effect=lambda: events.append(['owned_cluster_start'])), patch.object(host.time, 'sleep'):
            fault.start_desktop()
        self.assertEqual(events[-1], ['owned_cluster_start'])
        self.assertEqual(sum(event[0] == 'info' for event in events), 2)

    def test_missing_approval_does_not_resolve_or_write(self):
        with patch.object(host.HostFault, 'execute') as execute:
            self.assertEqual(host.main(['-Repository', host.REPOSITORY]), 1)
            execute.assert_not_called()


if __name__ == '__main__':
    unittest.main()
