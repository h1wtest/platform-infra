"""Exercise real Profile Helm releases under an authenticated session; local stand only."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cli
import helm_release
from fault_lifecycle import exclusive
from private_files import atomic_json
from e2e import Client
from common import BASE, CA, STATE


def deployments():
    items = json.loads(cli.kube('get', 'deployments', '-o', 'json').stdout)['items']
    return {item['metadata']['name']: {'uid': item['metadata']['uid'],
            'template': item['spec']['template']} for item in items}


def pods(service):
    items = json.loads(cli.kube('get', 'pods', '-l', 'app=' + service, '-o', 'json').stdout)['items']
    return [item for item in items
            if any(owner.get('kind') == 'ReplicaSet' and owner.get('controller') is True
                   for owner in item['metadata'].get('ownerReferences', []))]


def ready_endpoints(service):
    items = json.loads(cli.kube('get', 'endpointslices', '-l', 'kubernetes.io/service-name=' + service, '-o', 'json').stdout)['items']
    return sorted(endpoint['targetRef']['uid'] for item in items for endpoint in item.get('endpoints', [])
                  if endpoint.get('conditions', {}).get('ready') and endpoint.get('targetRef'))


def run():
    if BASE != 'https://localhost:8448' or cli.CONTEXT != 'k3d-sso-remediation':
        raise RuntimeError('Rolling acceptance is restricted to original isolated local stand')
    service = 'profile-service'
    state = json.loads((STATE / 'state.json').read_text())['probe']
    client = Client(BASE, str(CA))
    client.login(state['email'], state['password'])
    original_values = helm_release.current_values(cli, service)
    original_image = original_values['image']
    original_revision = int(helm_release.history(cli, service)[-1]['revision'])
    initial = deployments()
    original_uids = {item['metadata']['uid'] for item in pods(service)}
    output = {'service': service, 'initial_revision': original_revision, 'initial_image': original_image,
              'initial_ready_endpoints': ready_endpoints(service), 'phases': [],
              'scope': 'Real Profile executable in distinct packaging image; no application behavior/version change claimed'}
    done = threading.Event()
    samples = []
    phase = ['success']
    def monitor():
        while not done.is_set():
            sample = {'at': time.time(), 'phase': phase[0]}
            try:
                status, body, _ = client.call('GET', '/api/v1/users/me')
                if body['profile']['email'] != state['email']:
                    raise AssertionError('Profile identity mismatch')
                sample['status'] = status
            except Exception as error:
                sample['error'] = type(error).__name__
            samples.append(sample)
            done.wait(0.25)
    thread = threading.Thread(target=monitor)
    thread.start()
    candidate = None
    try:
        with tempfile.TemporaryDirectory(dir=cli.STATE) as directory:
            staging = Path(directory)
            (staging / 'Dockerfile').write_text('FROM ' + original_image + '\nLABEL local.rolling.acceptance="' + uuid.uuid4().hex + '"\n')
            tag = 'sso-remediation/profile:rolling-' + uuid.uuid4().hex
            cli.run(['docker', 'build', '--pull=false', '-t', tag, str(staging)], timeout=300)
            image_id = json.loads(cli.run(['docker', 'image', 'inspect', tag]).stdout)[0]['Id']
            candidate = 'sso-remediation/profile:sha256-' + image_id.split(':')[1]
            cli.run(['docker', 'tag', tag, candidate])
            cli.run(['docker', 'image', 'rm', tag])
        probe = [sys.executable, str(Path(__file__).with_name('run.py')), 'probe']
        import shlex
        command = shlex.join(probe)
        cli.run([sys.executable, cli.ROOT / 'scripts/cli.py', 'release', '--service', service,
                 '--image', candidate, '--probe', command, '--timeout', '180'], timeout=600)
        updated = pods(service)
        output['success_observation'] = {
            'at': time.time(), 'candidate_image': candidate,
            'ready_endpoint_uids': ready_endpoints(service),
            'pods': [{'uid': item['metadata']['uid'], 'name': item['metadata']['name'],
                      'image': item['spec']['containers'][0]['image'],
                      'phase': item.get('status', {}).get('phase'),
                      'terminating': bool(item['metadata'].get('deletionTimestamp')),
                      'owners': item['metadata'].get('ownerReferences', [])}
                     for item in updated],
        }
        live = [item for item in updated if not item['metadata'].get('deletionTimestamp')]
        assert live and all(item['spec']['containers'][0]['image'] == candidate for item in live)
        assert not original_uids.intersection(item['metadata']['uid'] for item in live)
        assert len(ready_endpoints(service)) >= 2
        current = deployments()
        assert {k: v for k, v in initial.items() if k != service} == {k: v for k, v in current.items() if k != service}
        output['phases'].append({'name': 'success', 'candidate_image': candidate, 'new_pod_uids': [p['metadata']['uid'] for p in live],
                                 'ready_endpoints': ready_endpoints(service), 'siblings_unchanged': True})
        phase[0] = 'readiness_failure'
        stable_values = helm_release.current_values(cli, service)
        prior_revision = int(helm_release.history(cli, service)[-1]['revision'])
        stable_endpoints = ready_endpoints(service)
        if len(stable_endpoints) < 2:
            raise AssertionError('Readiness failure requires two original ready endpoints')
        broken = copy.deepcopy(stable_values)
        # Same real process and database; only the ordinary health configuration changes.
        broken['readinessPath'] = '/acceptance/not-ready-' + uuid.uuid4().hex
        observation_done = threading.Event()
        observations = []
        failure_evidence = {'name': 'readiness_failure', 'prior_revision': prior_revision,
                            'stable_endpoint_uids': stable_endpoints, 'rollback_deployed': False,
                            'injected_readiness_path': broken['readinessPath'], 'observations': observations}
        output['phases'].append(failure_evidence)
        def observe_readiness():
            while not observation_done.is_set():
                observation = {'at': time.time()}
                try:
                    observation['ready_endpoint_uids'] = ready_endpoints(service)
                    observed_pods = []
                    for item in pods(service):
                        container = item['spec']['containers'][0]
                        if container.get('readinessProbe', {}).get('httpGet', {}).get('path') != broken['readinessPath']:
                            continue
                        observed_pods.append({'uid': item['metadata']['uid'], 'image': container['image'],
                            'terminating': bool(item['metadata'].get('deletionTimestamp')),
                            'ready': any(condition.get('type') == 'Ready' and condition.get('status') == 'True'
                                         for condition in item.get('status', {}).get('conditions', []))})
                    observation['injected_pods'] = observed_pods
                except Exception as error:
                    observation['error'] = type(error).__name__
                observations.append(observation)
                observation_done.wait(0.5)
        observer = threading.Thread(target=observe_readiness)
        observer.start()
        deployment_error = None
        try:
            with exclusive(cli.STATE, timeout=300):
                try:
                    helm_release.deploy(cli, service, {'chart': 'platform-service', 'values': broken}, timeout=35, rollback=True)
                except RuntimeError as error:
                    deployment_error = type(error).__name__
                    failure_evidence['deployment_error_type'] = deployment_error
        finally:
            observation_done.set()
            observer.join(timeout=30)
            if observer.is_alive():
                raise AssertionError('Readiness observer did not stop; evidence incomplete')
        records = helm_release.history(cli, service)
        new_records = [record for record in records if int(record['revision']) > prior_revision]
        failure_evidence['new_history'] = new_records
        if deployment_error is None:
            raise AssertionError('Non-ready upgrade unexpectedly reported success')
        if [(int(record['revision']), record['status']) for record in new_records] != [
                (prior_revision + 1, 'failed'), (prior_revision + 2, 'deployed')]:
            raise AssertionError('Failure did not create a failed Helm revision followed by deployed rollback')
        if not observations or any('error' in item for item in observations):
            raise AssertionError('Readiness observation failed; rollout evidence incomplete')
        if not all(set(stable_endpoints).issubset(item['ready_endpoint_uids']) for item in observations):
            raise AssertionError('Original ready endpoints disappeared during failed rollout')
        unready = {item['uid'] for observation in observations for item in observation['injected_pods']
                   if not item['ready'] and not item['terminating'] and item['image'] == stable_values['image']
                   and item['uid'] not in stable_endpoints}
        failure_evidence['observed_unready_pod_uids'] = sorted(unready)
        if not unready:
            raise AssertionError('No new non-ready pod with the injected health path was observed')
        if helm_release.current_values(cli, service) != stable_values:
            raise AssertionError('Rollback did not restore previous application values')
        final_endpoints = ready_endpoints(service)
        if not set(stable_endpoints).issubset(final_endpoints):
            raise AssertionError('Original endpoints not retained after rollback')
        failure_evidence.update(rollback_deployed=True, ready_endpoints=final_endpoints)
        phase[0] = 'business_failure'
        # CLI probe runs twice. First executes genuine business scenario; second deliberately
        # reports application acceptance failure after Kubernetes readiness has succeeded.
        with tempfile.TemporaryDirectory(dir=cli.STATE) as directory:
            staging = Path(directory)
            probe_file = staging / 'business_probe.py'
            marker = staging / 'first-complete'
            probe_file.write_text('import pathlib,subprocess,sys\np=pathlib.Path(' + repr(str(marker)) + ')\n'
                                  'if p.exists(): sys.exit(7)\n'
                                  'subprocess.run(' + repr(probe) + ',check=True)\np.write_text("complete")\n')
            prior = int(helm_release.history(cli, service)[-1]['revision'])
            result = cli.run([sys.executable, cli.ROOT / 'scripts/cli.py', 'release', '--service', service,
                              '--image', original_image, '--probe', shlex.join([sys.executable, str(probe_file)]),
                              '--timeout', '180'], timeout=600, check=False)
            assert result.returncode != 0, 'Business failure must remain a failed release command'
            assert helm_release.current_values(cli, service)['image'] == candidate
            assert int(helm_release.history(cli, service)[-1]['revision']) > prior
            output['phases'].append({'name': 'business_failure', 'command_failed': True, 'previous_image_restored': True})
        output['status'] = 'passed'
    except BaseException as error:
        output['status'] = 'failed'
        output['failure_type'] = type(error).__name__
        raise
    finally:
        phase[0] = 'restore'
        try:
            if candidate is not None:
                import shlex
                command = shlex.join([sys.executable, str(Path(__file__).with_name('run.py')), 'probe'])
                cli.run([sys.executable, cli.ROOT / 'scripts/cli.py', 'release', '--service', service,
                         '--image', original_image, '--probe', command, '--timeout', '180'], timeout=600)
        finally:
            done.set()
            thread.join(timeout=20)
            output['samples'] = samples
            output['failures'] = sum('error' in item for item in samples)
            if output['failures'] or any(not any(sample['phase'] == name for sample in samples) for name in ('success', 'readiness_failure', 'business_failure')):
                output['status'] = 'failed'
            atomic_json(STATE / 'rolling.json', output)
            try:
                client.call('POST', '/api/v1/auth/logout', {})
            except Exception:
                pass
    for name in ('success', 'readiness_failure', 'business_failure'):
        selected = [sample for sample in samples if sample['phase'] == name]
        assert selected and all(sample.get('status') == 200 for sample in selected), 'Business interruption during ' + name
    assert output['failures'] == 0, 'Business requests failed during rolling/recovery'
    print('PASS real Profile rolling update, readiness failure and business-gate recovery; authenticated requests uninterrupted; siblings unchanged')


if __name__ == '__main__':
    run()
