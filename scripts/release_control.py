"""Independent application update; no sibling apply and no automatic data rollback."""
import copy
import re
import shlex
import time
import uuid


def immutable_image(value):
    registry = r'[a-zA-Z0-9][a-zA-Z0-9._:/-]*@sha256:[a-f0-9]{64}'
    local = r'sso-remediation/[a-z0-9-]+:sha256-[a-f0-9]{64}'
    if not isinstance(value, str) or not re.fullmatch(f'(?:{registry}|{local})', value):
        raise ValueError('Image must be a digest-pinned registry reference or a verified local content-addressed tag')
    return value


def probe(runtime, command):
    result = runtime.run(shlex.split(command), timeout=180, check=False)
    if result.returncode:
        raise RuntimeError('Business probe failed; output withheld because it can contain credentials')


def service_image(runtime, service, image):
    immutable_image(image)
    target = runtime.manifests.APPS[service][0] if service in runtime.manifests.APPS else service
    if image.startswith('sso-remediation/') and image.split('/')[1].split(':')[0] != target:
        raise ValueError('Local image must use the canonical selected service target: ' + target)
    return image


def selected_images(runtime, images, *, reconcile=False):
    import json
    from release_values import APPLICATION_RELEASES
    path = runtime.STATE / 'release-images.json'
    overrides = json.loads(path.read_text()) if path.exists() else {}
    if not isinstance(overrides, dict) or set(overrides) - set(APPLICATION_RELEASES):
        raise RuntimeError('Invalid selected release image manifest')
    result = dict(images)
    changed = False
    for service, image in overrides.items():
        if reconcile:
            import helm_release
            status = helm_release.status(runtime, service)
            if status is None or status['status'] != 'deployed':
                raise RuntimeError('Selected Helm release requires explicit recovery before full up: ' + service)
            current = helm_release.current_values(runtime, service)['image']
            changed = changed or current != image
            image = current
            overrides[service] = current
        service_image(runtime, service, image)
        target = runtime.manifests.APPS[service][0] if service in runtime.manifests.APPS else service
        result[target] = image
        if image.startswith('sso-remediation/'):
            result[target + '_id'] = 'sha256:' + image.rsplit('sha256-', 1)[1]
    if changed:
        from private_files import atomic_json
        atomic_json(path, overrides)
    return result


def specs(runtime, images):
    from release_values import release_specs
    from api_network import discover
    result = release_specs(selected_images(runtime, images), runtime.STATE, runtime.ROOT)
    result['platform-config']['values']['apiNetworkPolicy'] = discover(runtime)
    return result


def adopt(runtime):
    import helm_release
    from cluster_identity import guard
    guard(runtime)
    images = runtime.load_images()
    desired = specs(runtime, images)
    helm_release.adopt(runtime, desired)
    print('Original local resource ownership adopted; no workload or volume recreated. Run make up to install release records.')


def update(runtime, service, image, command, timeout=240):
    import helm_release
    from cluster_identity import guard
    from release_values import APPLICATION_RELEASES
    from private_files import atomic_json
    if service not in APPLICATION_RELEASES:
        raise ValueError('Only an application release can be updated independently')
    service_image(runtime, service, image)
    guard(runtime)
    previous = helm_release.history(runtime, service)
    if not previous or previous[-1]['status'] != 'deployed':
        raise RuntimeError('Selected release is not deployed; inspect Helm history and recover it before updating')
    revision = int(previous[-1]['revision'])
    values = copy.deepcopy(helm_release.current_values(runtime, service))
    values['image'] = image
    probe(runtime, command)
    if image.startswith('sso-remediation/'):
        target = runtime.manifests.APPS[service][0] if service in runtime.manifests.APPS else service
        runtime.verify_local_image(target, image, 'sha256:' + image.rsplit('sha256-', 1)[1])
    else:
        runtime.run(['docker', 'pull', image], timeout=900)
    runtime.run(['k3d', 'image', 'import', image, '-c', runtime.CLUSTER], timeout=600)
    evidence = {'service': service, 'image': image, 'previous_revision': revision,
                'started_at': time.time(), 'migration_rollback': False}
    path = runtime.STATE / 'acceptance' / ('release-' + service + '-' + uuid.uuid4().hex + '.json')
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        if service in runtime.manifests.APPS and runtime.manifests.APPS[service][0] != 'worker':
            images = runtime.load_images()
            images[runtime.manifests.APPS[service][0]] = image
            runtime.migration_jobs(images, selected=service)
        helm_release.deploy(runtime, service, {'chart': 'platform-service', 'values': values}, timeout=timeout, rollback=True)
        try:
            probe(runtime, command)
            import json
            selection_path = runtime.STATE / 'release-images.json'
            selection = json.loads(selection_path.read_text()) if selection_path.exists() else {}
            selection[service] = image
            atomic_json(selection_path, selection)
        except BaseException:
            helm_release.rollback(runtime, service, revision, timeout=timeout)
            evidence['post_deploy_rollback'] = True
            raise
        evidence['status'] = 'passed'
        print('PASS selected Helm release updated and business probe passed: ' + service)
    except BaseException:
        evidence['status'] = 'failed'
        raise
    finally:
        evidence['finished_at'] = time.time()
        atomic_json(path, evidence)


def rollback(runtime, service, revision, command, timeout=240):
    import helm_release
    from cluster_identity import guard
    guard(runtime)
    helm_release.rollback(runtime, service, revision, timeout=timeout)
    probe(runtime, command)
    print('PASS application configuration restored and business probe passed: ' + service)


def status(runtime):
    import helm_release
    from release_values import RELEASE_ORDER
    for name in RELEASE_ORDER:
        records = helm_release.history(runtime, name)
        if not records:
            print(name + ': not installed')
        else:
            latest = records[-1]
            print(f'{name}: revision={latest["revision"]} status={latest["status"]}')
