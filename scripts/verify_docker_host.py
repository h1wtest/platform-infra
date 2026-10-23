"""Windows-owned observer for explicitly approved Docker Desktop WSL VM termination.

Every native process is bounded; PASS is published only after owned finalization.
This is not a Windows reboot, physical power-loss, or independent-host HA test.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

REPOSITORY = '/home/bpqvg/dev/h1wtest-remediation/platform-infra'
BASE = 'https://localhost:8448'
TIMER = 'sso-remediation-backup.timer'
CONTAINERS = ['k3d-sso-remediation-server-' + str(i) for i in range(3)] + ['k3d-sso-remediation-serverlb', 'dsh-hindsight']
# Invoke the supported existing-cluster operation directly; never up/build/migrate.
CLUSTER_START_PROGRAM = 'import pathlib,shutil,subprocess,sys;k3d=shutil.which("k3d") or str(pathlib.Path.home()/"go/bin/k3d");raise SystemExit(subprocess.call([k3d,"cluster","start",sys.argv[1],"--wait","--timeout",sys.argv[2]]))'


def now():
    return datetime.now(timezone.utc).isoformat()


def native(arguments, timeout):
    if timeout <= 0:
        raise TimeoutError('Native operation has no remaining time budget')
    return subprocess.run(arguments, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=timeout, check=False)


def atomic_evidence(path, value):
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, url):
        return None


class HostFault:
    def __init__(self, repository):
        self.repository = repository
        self.run_id = uuid.uuid4().hex
        self.started = time.monotonic()
        self.stage = 'initialize'
        self.errors = []
        self.evidence_file = None
        self.root = None
        self.ca = None
        self.timer_active = False
        self.fixture_owned = False
        self.recovered = False
        self.business_verified = False
        self.before = {}
        self.evidence = {
            'run_id': self.run_id, 'started_at': now(),
            'scope': 'Entire Docker Desktop WSL VM termination; not Windows reboot or physical power loss',
            'injection_command': ['wsl.exe', '--terminate', 'docker-desktop'],
            'injection_attempted': False, 'injection_completed': False,
            'unrelated_workload_interruption_explicitly_authorized': True,
            'observations': [], 'operations': [], 'finalization': {},
        }

    def command(self, arguments, timeout, *, check=True):
        entry = {'stage': self.stage, 'program': arguments[0], 'started_at': now()}
        self.evidence['operations'].append(entry)
        try:
            result = native(arguments, timeout)
        except (subprocess.TimeoutExpired, TimeoutError):
            entry['timed_out'] = True
            raise TimeoutError('Operation timed out at ' + self.stage) from None
        entry['exit_code'] = result.returncode
        if check and result.returncode:
            raise RuntimeError('Native command failed at ' + self.stage + ': exit ' + str(result.returncode))
        return result

    def wsl(self, arguments, timeout=20, *, check=True):
        return self.command(['wsl.exe', '-d', 'Ubuntu', '-e', *arguments], timeout, check=check)

    def platform(self, arguments, timeout=120, *, check=True):
        # Linux timeout also bounds children if Windows terminates its wsl.exe client.
        if timeout <= 3:
            raise TimeoutError('Platform operation has no remaining time budget')
        seconds = max(1, int(timeout - 3))
        return self.command([
            'wsl.exe', '-d', 'Ubuntu', '--cd', self.repository, '-e',
            'timeout', '--signal=TERM', '--kill-after=1s', str(seconds) + 's',
            'env', 'ACCEPTANCE_BASE=' + BASE,
            'ACCEPTANCE_CA=' + self.repository + '/.local/ca.crt',
            'ACCEPTANCE_DIRECTORY=' + self.repository + '/.local/acceptance',
            '/home/bpqvg/.local/bin/uv', 'run', '--no-project', 'python', *arguments,
        ], timeout, check=check)

    def helper(self, mode, timeout=120, *, check=True):
        return self.platform(['scripts/acceptance/host_state.py', mode, '--run-id', self.run_id], timeout, check=check)

    def resolve_repository(self):
        result = self.wsl(['wslpath', '-w', self.repository])
        path = Path(result.stdout.strip())
        if not path.is_dir():
            raise RuntimeError('Cannot resolve isolated workspace')
        return path

    def initialize(self):
        self.root = self.resolve_repository()
        directory = self.root / '.local/acceptance'
        marker = directory / 'host-fault-private.json'
        if marker.exists():
            raise RuntimeError('Owned fixture predates this invocation; explicit verify/cleanup required before injection')
        if not directory.is_dir():
            raise RuntimeError('Existing acceptance directory and private probe state required')
        self.evidence_file = directory / 'docker-host-fault.json'
        # Private local Windows storage remains accessible when docker-desktop is down.
        descriptor, temporary = tempfile.mkstemp(prefix='sso-host-ca-', suffix='.crt')
        os.close(descriptor)
        self.ca = Path(temporary)
        shutil.copyfile(self.root / '.local/ca.crt', self.ca)
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(self.ca))))

    def observe(self, phase, remaining=10):
        if remaining <= 0:
            return False
        entry = {'phase': phase, 'timestamp': now(), 'available': False}
        try:
            with self.opener.open(BASE + '/.well-known/openid-configuration', timeout=min(3, remaining / 3)) as response:
                entry['http_status'] = response.status
                entry['available'] = response.status == 200
        except urllib.error.HTTPError as error:
            entry['http_status'] = error.code
            entry['error_type'] = 'HTTPError'
            error.close()
        except (OSError, urllib.error.URLError) as error:
            # No exception body: it can include untrusted URLs or environment details.
            entry['error_type'] = type(error).__name__
        self.evidence['observations'].append(entry)
        return entry['available']

    def inventory(self):
        result = self.command(['docker.exe', 'inspect', '--format', '{{json .}}', *CONTAINERS], 20)
        values = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        return {value['Name'].lstrip('/'): {
            'running': value['State']['Running'],
            'restart_policy': value['HostConfig']['RestartPolicy']['Name'],
        } for value in values}

    def start_existing_cluster(self):
        self.evidence['recovery_procedure'] = 'Explicit existing-cluster start; not Docker restart-policy-only recovery'
        attempts = self.evidence.setdefault('existing_cluster_start_attempts', [])
        deadline = time.monotonic() + 240
        for attempt in range(3):
            remaining = deadline - time.monotonic()
            if remaining <= 5:
                raise TimeoutError('Existing-cluster start recovery deadline exceeded')
            entry = {'started_at': now(), 'attempt': attempt + 1}
            attempts.append(entry)
            try:
                result = self.platform(['-c', CLUSTER_START_PROGRAM, 'sso-remediation', str(min(180, max(1, int(remaining - 5)))) + 's'], min(190, remaining), check=False)
            except BaseException as error:
                entry.update(error_type=type(error).__name__, finished_at=now())
                raise
            entry.update(exit_code=result.returncode, finished_at=now())
            if result.returncode == 0:
                return
            diagnostics = result.stdout + '\n' + result.stderr
            known_busy = 'cgroup.procs' in diagnostics and 'device or resource busy' in diagnostics.lower()
            entry['failure_class'] = 'cgroup_admission_busy' if known_busy else 'other_start_failure'
            if not known_busy or attempt == 2:
                raise RuntimeError('Explicit existing-cluster start failed; no destructive recovery attempted')
            time.sleep(min(3, max(0, deadline - time.monotonic())))

    def start_desktop(self):
        self.command(['docker.exe', 'desktop', 'start', '--timeout', '300'], 310)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                result = self.command(['docker.exe', 'info', '--format', '{{json .ServerVersion}}'], min(10, deadline - time.monotonic()), check=False)
            except TimeoutError:
                continue
            if result.returncode == 0:
                self.evidence['docker_daemon_ready_at'] = now()
                break
            time.sleep(min(2, max(0, deadline - time.monotonic())))
        else:
            raise TimeoutError('Docker daemon did not become ready after Desktop start')
        self.start_existing_cluster()

    def wait_recovery(self, seconds=600):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if self.observe('recovery', deadline - time.monotonic()):
                remaining = deadline - time.monotonic()
                try:
                    result = self.helper('readiness', min(90, remaining), check=False)
                    if result.returncode == 0:
                        after = self.inventory() if deadline - time.monotonic() > 20 else {}
                        if set(after) == set(self.before) and all(not previous['running'] or after[name]['running'] for name, previous in self.before.items()):
                            readiness = json.loads((self.root / '.local/acceptance/host-fault-readiness.json').read_text())
                            if readiness['run_id'] != self.run_id:
                                raise RuntimeError('Readiness evidence does not belong to current host-fault run')
                            self.evidence['readiness'] = readiness
                            self.evidence['workloads_after'] = after
                            self.recovered = True
                            return
                except TimeoutError:
                    pass
            time.sleep(min(3, max(0, deadline - time.monotonic())))
        raise TimeoutError('Required controllers, nodes, control plane, quorum or preexisting workloads did not recover within deadline')

    def pause_timer(self):
        result = self.wsl(['systemctl', '--user', 'show', TIMER, '--property=LoadState', '--property=ActiveState'])
        properties = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
        if properties.get('LoadState') != 'loaded' or properties.get('ActiveState') not in ('active', 'inactive'):
            raise RuntimeError('Cannot establish original owned backup timer state')
        self.timer_active = properties['ActiveState'] == 'active'
        self.evidence['backup_timer_was_active'] = self.timer_active
        if self.timer_active:
            self.wsl(['systemctl', '--user', 'stop', TIMER])
            result = self.wsl(['systemctl', '--user', 'is-active', '--quiet', TIMER], check=False)
            if result.returncode != 3:
                raise RuntimeError('Owned backup timer did not become inactive')

    def restore_timer(self):
        self.wsl(['systemctl', '--user', 'start', TIMER])
        self.wsl(['systemctl', '--user', 'is-active', '--quiet', TIMER])

    def run_fault(self):
        self.stage = 'baseline_readiness'
        self.helper('readiness')
        if not self.observe('baseline'):
            raise RuntimeError('Baseline API unavailable; fault not injected')
        self.before = self.inventory()
        if set(self.before) != set(CONTAINERS) or not all(row['running'] for row in self.before.values()):
            raise RuntimeError('All inventoried pre-fault workloads must be running')
        self.evidence['workloads_before'] = self.before
        self.stage = 'pause_backup_timer'
        self.pause_timer()
        self.stage = 'backup'
        self.platform(['scripts/cli.py', 'backup'], 1800)
        self.stage = 'prepare'
        # Helper cleanup validates run_id, even if prepare times out after writing its marker.
        self.fixture_owned = True
        self.helper('prepare', 420)
        self.stage = 'terminate_docker_vm'
        self.evidence['injection_attempted'] = True
        self.evidence['injection_attempted_at'] = now()
        self.command(['wsl.exe', '--terminate', 'docker-desktop'], 30)
        self.evidence['injection_completed'] = True
        self.evidence['injection_completed_at'] = now()
        self.stage = 'observe_outage'
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if not self.observe('post_injection', deadline - time.monotonic()):
                break
            time.sleep(min(0.5, max(0, deadline - time.monotonic())))
        else:
            raise RuntimeError('No actual HTTPS outage observed after VM termination')
        self.stage = 'desktop_start'
        self.start_desktop()
        self.stage = 'service_recovery'
        self.wait_recovery()
        self.stage = 'business_verification'
        self.helper('verify', 210)
        business = json.loads((self.root / '.local/acceptance/host-fault-business.json').read_text())
        if business['run_id'] != self.run_id:
            raise RuntimeError('Business evidence does not belong to current host-fault run')
        self.evidence['business'] = business
        self.business_verified = True

    def attempt_final(self, name, action):
        self.stage = name
        entry = {'started_at': now()}
        self.evidence['finalization'][name] = entry
        try:
            action()
            entry['status'] = 'PASS'
        except BaseException as error:
            entry.update(status='FAIL', error_type=type(error).__name__)
            self.errors.append({'stage': name, 'error_type': type(error).__name__})
        entry['finished_at'] = now()

    def cleanup_fixture(self):
        marker = self.root / '.local/acceptance/host-fault-private.json'
        if marker.exists():
            self.helper('cleanup', 180)
        if marker.exists():
            raise RuntimeError('Owned fixture remains; cleanup must be retried explicitly')

    def emergency_recovery(self):
        self.start_desktop()
        self.wait_recovery(180)

    def finish(self):
        self.evidence.update(
            finished_at=now(), elapsed_seconds=round(time.monotonic() - self.started, 3),
            outage_observed=any(row['phase'] == 'post_injection' and not row['available'] for row in self.evidence['observations']),
            services_recovered=self.recovered, business_verified=self.business_verified,
            errors=self.errors,
        )
        if self.root:
            self.evidence['owned_fixture_remaining'] = (self.root / '.local/acceptance/host-fault-private.json').exists()
            if self.fixture_owned and self.evidence['owned_fixture_remaining']:
                self.evidence['deferred_cleanup'] = 'scripts/acceptance/host_state.py cleanup --run-id ' + self.run_id
                self.errors.append({'stage': 'cleanup', 'error_type': 'OwnedFixtureRemaining'})
        passed = (not self.errors and self.evidence['injection_completed'] and self.evidence['outage_observed'] and self.recovered and self.business_verified)
        self.evidence['result'] = 'PASS' if passed else 'FAIL'
        if self.evidence_file:
            atomic_evidence(self.evidence_file, self.evidence)
        return 0 if passed else 1

    def execute(self):
        try:
            self.initialize()
            self.run_fault()
        except BaseException as error:
            self.errors.append({'stage': self.stage, 'error_type': type(error).__name__})
            print('FAIL host-fault stage=' + self.stage + ' error=' + type(error).__name__, file=sys.stderr)
        finally:
            if self.evidence['injection_attempted'] and not self.recovered:
                self.attempt_final('emergency_recovery', self.emergency_recovery)
            if self.fixture_owned:
                self.attempt_final('cleanup', self.cleanup_fixture)
            if self.timer_active:
                self.attempt_final('timer_restore', self.restore_timer)
            if self.ca:
                self.attempt_final('temporary_ca_remove', lambda: self.ca.unlink(missing_ok=True))
        try:
            result = self.finish()
        except BaseException as error:
            print('FAIL final evidence publication: ' + type(error).__name__, file=sys.stderr)
            return 1
        print(self.evidence['result'] + ' whole Docker-host WSL VM fault; no Windows reboot/physical power-loss tolerance claimed')
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-Repository', required=True)
    parser.add_argument('-AllowSharedHostOutage', action='store_true')
    args = parser.parse_args(argv)
    if not args.AllowSharedHostOutage:
        print('HOST_OUTAGE_APPROVAL_REQUIRED: every Docker Desktop workload is interrupted', file=sys.stderr)
        return 1
    if args.Repository != REPOSITORY:
        print('Host verification is restricted to the isolated SSO workspace', file=sys.stderr)
        return 1
    if sys.platform != 'win32':
        print('External Windows observer required', file=sys.stderr)
        return 1
    return HostFault(args.Repository).execute()


if __name__ == '__main__':
    raise SystemExit(main())
