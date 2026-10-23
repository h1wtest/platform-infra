"""Namespace-scoped overlay of the authenticated CloudNativePG 1.30.1 release.

Uses the upstream Helm commonRules/clusterwideRules split, not a watch filter as
an authorization boundary. The release file is never rewritten. Unknown release
bytes, privileges, bindings or image references fail before changing the API.

References:
https://cloudnative-pg.io/docs/1.30/installation_upgrade/
https://github.com/cloudnative-pg/charts/blob/main/charts/cloudnative-pg/templates/_helpers.tpl
https://github.com/cloudnative-pg/charts/blob/main/charts/cloudnative-pg/templates/rbac.yaml
https://github.com/cloudnative-pg/cloudnative-pg/blob/v1.30.1/pkg/multicache/multinamespaced_cache.go
https://github.com/cloudnative-pg/cloudnative-pg/blob/v1.30.1/pkg/certs/k8s.go
"""
import copy
import hashlib
import json
import re

UPSTREAM_SHA256 = '37237f145d8138256ea25ae830f87759255665ff08f8d552fdd8224a5ec032fb'
UPSTREAM_IMAGE = 'ghcr.io/cloudnative-pg/cloudnative-pg:1.30.1'
OPERATOR_NAMESPACE = 'cnpg-system'
RBAC_GROUP = 'rbac.authorization.k8s.io'
SUBJECT = {'kind': 'ServiceAccount', 'name': 'cnpg-manager', 'namespace': OPERATOR_NAMESPACE}


def _rule(group, resources, verbs, names=None):
    result = {'apiGroups': [group], 'resources': resources.split(), 'verbs': verbs.split()}
    if names is not None:
        result['resourceNames'] = names
    return result


# Exact upstream manager rules, including mixed-scope image catalog rule. An
# upgrade needs an explicit privilege review rather than a permissive fallback.
EXPECTED_RULES = [
    _rule('', 'configmaps secrets services', 'create delete get list patch update watch'),
    _rule('', 'configmaps/status secrets/status', 'get patch update'),
    _rule('', 'events', 'create patch'),
    _rule('', 'nodes', 'get list watch'),
    _rule('', 'persistentvolumeclaims pods pods/exec', 'create delete get list patch watch'),
    _rule('', 'pods/status', 'get'),
    _rule('', 'serviceaccounts', 'create get list patch update watch'),
    _rule('admissionregistration.k8s.io', 'mutatingwebhookconfigurations validatingwebhookconfigurations', 'get patch'),
    _rule('apps', 'deployments', 'create delete get list patch update watch'),
    _rule('batch', 'jobs', 'create delete get list patch watch'),
    _rule('coordination.k8s.io', 'leases', 'create get list update watch'),
    _rule('discovery.k8s.io', 'endpointslices', 'get list watch'),
    _rule('monitoring.coreos.com', 'podmonitors', 'create delete get list patch watch'),
    _rule('policy', 'poddisruptionbudgets', 'create delete get list patch update watch'),
    _rule('postgresql.cnpg.io', 'backups clusters databaseroles databases poolers publications scheduledbackups subscriptions', 'create delete get list patch update watch'),
    _rule('postgresql.cnpg.io', 'backups/status databases/status publications/status scheduledbackups/status subscriptions/status', 'get patch update'),
    _rule('postgresql.cnpg.io', 'clusterimagecatalogs imagecatalogs', 'get list watch'),
    _rule('postgresql.cnpg.io', 'clusters/finalizers databaseroles/finalizers poolers/finalizers', 'update'),
    _rule('postgresql.cnpg.io', 'clusters/status databaseroles/status failoverquorums/status poolers/status', 'get patch update watch'),
    _rule('postgresql.cnpg.io', 'failoverquorums', 'create delete get list watch'),
    _rule(RBAC_GROUP, 'rolebindings roles', 'create get list patch update watch'),
    _rule('snapshot.storage.k8s.io', 'volumesnapshots', 'create get list patch watch'),
]


def _namespace(namespace):
    if not isinstance(namespace, str) or not re.fullmatch(r'[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?', namespace) or namespace == OPERATOR_NAMESPACE:
        raise RuntimeError('CNPG requires one explicit operand namespace distinct from cnpg-system')


def _object(kind, name, namespace=None, **body):
    metadata = {'name': name, 'annotations': {'platform.local/cnpg-upstream-sha256': UPSTREAM_SHA256}}
    if namespace is not None:
        metadata['namespace'] = namespace
    return {'apiVersion': RBAC_GROUP + '/v1', 'kind': kind, 'metadata': metadata, **body}


def _binding(kind, name, role, namespace=None):
    return _object(kind, name, namespace, roleRef={'apiGroup': RBAC_GROUP, 'kind': 'ClusterRole' if kind == 'ClusterRoleBinding' else 'Role', 'name': role}, subjects=[copy.deepcopy(SUBJECT)])


def rbac_objects(rules, namespace):
    """Return actual grants, refusing additions, omissions and unknown rule keys."""
    _namespace(namespace)
    if rules != EXPECTED_RULES:
        raise RuntimeError('Unrecognized CNPG 1.30.1 privilege shape; review the authenticated release')
    operand = []
    cluster = []
    for original in rules:
        rule = copy.deepcopy(original)
        group = rule['apiGroups'][0]
        if group == '' and rule['resources'] == ['nodes']:
            cluster.append(rule)
        elif group == 'admissionregistration.k8s.io':
            for resource, name in [('mutatingwebhookconfigurations', 'cnpg-mutating-webhook-configuration'), ('validatingwebhookconfigurations', 'cnpg-validating-webhook-configuration')]:
                cluster.append(_rule(group, resource, 'get patch', [name]))
        elif group == 'postgresql.cnpg.io' and 'clusterimagecatalogs' in rule['resources']:
            cluster.append(_rule(group, 'clusterimagecatalogs', 'get list watch'))
            operand.append(_rule(group, 'imagecatalogs', 'get list watch'))
        else:
            operand.append(rule)

    # The supported multi-namespace cache also reads the operator namespace.
    # Keep only the original read verbs there, with no exec subresource access.
    # PKI uses an uncached client and needs create + named update of CA/leaf
    # secrets. Kubernetes cannot constrain create by resourceNames. It does not
    # need service routing writes or PostgreSQL operand mutation in this ns.
    operator = []
    for rule in operand:
        resources = [r for r in rule['resources'] if r != 'pods/exec']
        verbs = [v for v in rule['verbs'] if v in ('get', 'list', 'watch')]
        if resources and verbs:
            operator.append({'apiGroups': rule['apiGroups'][:], 'resources': resources, 'verbs': verbs})
    operator.extend([
        _rule('', 'secrets', 'create'),
        _rule('', 'secrets', 'update', ['cnpg-ca-secret', 'cnpg-webhook-cert']),
        _rule('', 'secrets', 'patch', ['cnpg-webhook-cert']),
        _rule('', 'events', 'create patch'),
        _rule('coordination.k8s.io', 'leases', 'create'),
        _rule('coordination.k8s.io', 'leases', 'update', ['db9c8771.cnpg.io']),
    ])
    return [
        _object('ClusterRole', 'cnpg-manager', rules=cluster),
        _binding('ClusterRoleBinding', 'cnpg-manager-rolebinding', 'cnpg-manager'),
        _object('Role', 'cnpg-manager-operands', namespace, rules=operand),
        _binding('RoleBinding', 'cnpg-manager-operands', 'cnpg-manager-operands', namespace),
        _object('Role', 'cnpg-manager-operator', OPERATOR_NAMESPACE, rules=operator),
        _binding('RoleBinding', 'cnpg-manager-operator', 'cnpg-manager-operator', OPERATOR_NAMESPACE),
    ]


def _release_rules(document):
    """Read only the flat scalar-list RBAC shape of the pinned release, not YAML."""
    header = 'apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: cnpg-manager\nrules:\n'
    if not document.startswith(header):
        raise RuntimeError('Unrecognized authenticated CNPG manager privilege shape')
    rules = []
    field = None
    for line in document[len(header):].splitlines():
        if line == '- apiGroups:':
            rules.append({'apiGroups': []})
            field = 'apiGroups'
        elif line in ('  resources:', '  verbs:'):
            field = line.strip()[:-1]
            if not rules or field in rules[-1]:
                raise RuntimeError('Unrecognized CNPG privilege shape')
            rules[-1][field] = []
        elif line.startswith('  - ') and field is not None:
            scalar = line[4:]
            if scalar == '""':
                scalar = ''
            elif not re.fullmatch(r'[a-z0-9./-]+', scalar):
                raise RuntimeError('Unrecognized CNPG privilege shape')
            rules[-1][field].append(scalar)
        else:
            raise RuntimeError('Unrecognized CNPG privilege shape')
    return rules


def _identity(document):
    kind = re.search(r'^kind: ([A-Za-z]+)$', document, re.MULTILINE)
    metadata = re.search(r'^metadata:\n((?:[ \t].*\n|\n)*(?:[ \t][^\n]*\Z)?)', document, re.MULTILINE)
    name = re.search(r'^  name: ([a-z0-9.-]+)$', metadata[1], re.MULTILINE) if metadata else None
    if not kind or not name:
        raise RuntimeError('Unrecognized authenticated CNPG document shape')
    return kind[1], name[1]


def render(content, expected_sha256, image, namespace):
    """Derive narrowed YAML; preserve all other official documents byte-for-byte."""
    _namespace(namespace)
    if expected_sha256 != UPSTREAM_SHA256 or hashlib.sha256(content).hexdigest() != UPSTREAM_SHA256:
        raise RuntimeError('CNPG manifest is not the authenticated pinned 1.30.1 release')
    if not isinstance(image, str) or not (re.fullmatch(re.escape(UPSTREAM_IMAGE) + r'@sha256:[a-f0-9]{64}', image) or re.fullmatch(r'sso-remediation/cnpg-operator:sha256-[a-f0-9]{64}', image)):
        raise RuntimeError('CNPG operator image must be immutable and explicitly selected')
    documents = content.decode('utf-8').split('\n---\n')
    output = []
    seen = set()
    rules = None
    for document in documents:
        identity = _identity(document)
        if identity in seen:
            raise RuntimeError('Duplicate authenticated CNPG resource')
        seen.add(identity)
        if identity == ('ClusterRole', 'cnpg-manager'):
            rules = _release_rules(document)
            continue
        if identity == ('ClusterRoleBinding', 'cnpg-manager-rolebinding'):
            continue
        if identity == ('Deployment', 'cnpg-controller-manager'):
            old_image = '        image: ' + UPSTREAM_IMAGE + '\n'
            old_env = '        - name: OPERATOR_IMAGE_NAME\n          value: ' + UPSTREAM_IMAGE + '\n'
            env_anchor = '        - name: OPERATOR_NAMESPACE\n'
            old_policy = '        imagePullPolicy: Always\n'
            if document.count(old_image) != 1 or document.count(old_env) != 1 or document.count(env_anchor) != 1 or document.count(old_policy) != 1 or 'WATCH_NAMESPACE' in document:
                raise RuntimeError('Unrecognized authenticated CNPG deployment image/config shape')
            document = document.replace(old_image, '        image: ' + image + '\n')
            document = document.replace(old_env, '        - name: OPERATOR_IMAGE_NAME\n          value: ' + image + '\n')
            document = document.replace(env_anchor, '        - name: WATCH_NAMESPACE\n          value: ' + namespace + '\n' + env_anchor)
            if image.startswith('sso-remediation/'):
                document = document.replace(old_policy, '        imagePullPolicy: IfNotPresent\n')
        output.append(document)
    if not {('ClusterRole', 'cnpg-manager'), ('ClusterRoleBinding', 'cnpg-manager-rolebinding'), ('Deployment', 'cnpg-controller-manager')}.issubset(seen):
        raise RuntimeError('Authenticated CNPG release lacks required resources')
    output.extend(json.dumps(obj, sort_keys=True) for obj in rbac_objects(rules, namespace))
    return ('\n---\n'.join(output) + '\n').encode()


# Kubernetes v1.35 bootstrap policy. Default binding names alone are not proof:
# inspect their actual referenced rules and reject any added resource grants.
BUILTIN_RULES = {
    'system:discovery': [{'verbs': ['get'], 'nonResourceURLs': ['/livez', '/readyz', '/healthz', '/version', '/version/', '/openapi', '/openapi/*', '/api', '/api/*', '/apis', '/apis/*']}],
    'system:public-info-viewer': [{'verbs': ['get'], 'nonResourceURLs': ['/livez', '/readyz', '/healthz', '/version', '/version/']}],
    'system:basic-user': [
        _rule('authorization.k8s.io', 'selfsubjectaccessreviews selfsubjectrulesreviews', 'create'),
        _rule('authentication.k8s.io', 'selfsubjectreviews', 'create'),
    ],
    'system:service-account-issuer-discovery': [{'verbs': ['get'], 'nonResourceURLs': ['/.well-known/openid-configuration', '/.well-known/openid-configuration/', '/openid/v1/jwks', '/openid/v1/jwks/']}],
}


def _canonical_rules(rules):
    return sorted(json.dumps({key: sorted(value) for key, value in rule.items()}, sort_keys=True) for rule in rules)


def validate_bindings(bindings, namespace, builtin_roles=None):
    """Reject other authority sources rather than delete arbitrary user RBAC."""
    expected = {(o['kind'], o['metadata'].get('namespace'), o['metadata']['name']): o for o in rbac_objects(EXPECTED_RULES, namespace) if o['kind'].endswith('Binding')}
    for binding in bindings:
        relevant = any((s.get('kind') == 'ServiceAccount' and s.get('name') == 'cnpg-manager' and s.get('namespace', binding['metadata'].get('namespace')) == OPERATOR_NAMESPACE) or (s.get('kind') == 'User' and s.get('name') == 'system:serviceaccount:cnpg-system:cnpg-manager') or (s.get('kind') == 'Group' and s.get('name') in ('system:serviceaccounts', 'system:serviceaccounts:cnpg-system', 'system:authenticated')) for s in binding.get('subjects', []))
        if not relevant:
            continue
        key = (binding['kind'], binding['metadata'].get('namespace'), binding['metadata']['name'])
        wanted = expected.get(key)
        if key[0] == 'ClusterRoleBinding' and key[2] in BUILTIN_RULES:
            name = key[2]
            groups = {'system:serviceaccounts'} if name == 'system:service-account-issuer-discovery' else {'system:authenticated', 'system:unauthenticated'} if name == 'system:public-info-viewer' else {'system:authenticated'}
            if binding.get('roleRef') != {'apiGroup': RBAC_GROUP, 'kind': 'ClusterRole', 'name': name} or not binding.get('subjects') or not all(s.get('kind') == 'Group' and s.get('name') in groups for s in binding['subjects']):
                raise RuntimeError('Unexpected CNPG built-in authority binding ' + name)
            role = (builtin_roles or {}).get(name)
            if role is None or role.get('aggregationRule') or _canonical_rules(role.get('rules', [])) != _canonical_rules(BUILTIN_RULES[name]):
                raise RuntimeError('Unexpected or unavailable CNPG built-in authority role ' + name)
            continue
        if wanted is None or binding.get('roleRef') != wanted['roleRef'] or binding.get('subjects') != wanted['subjects']:
            raise RuntimeError('Unexpected CNPG authority binding ' + '/'.join(str(x) for x in key if x is not None))


def install(api, images):
    """Install through cli's guarded context; atomically replace known RBAC rules.

    The existing manager ClusterRole is reused with *only* cluster rules. This
    removes the legacy broad grant without deleting its stable binding or any
    database resources. replace, not additive apply, removes old field owners'
    extra rules. An optimistic resourceVersion conflict fails closed.
    """
    content = (api.STATE / 'cnpg-operator.yaml').read_bytes()
    manifest = render(content, images['operator_sha256'], images['cnpg-operator'], api.NS)
    prefix = ['kubectl', '--context', api.CONTEXT]

    def get(*args):
        content = api.run([*prefix, 'get', *args, '-o', 'json']).stdout
        return json.loads(content) if content.strip() else None

    cluster_bindings = get('clusterrolebindings')['items']
    role_bindings = get('rolebindings', '--all-namespaces')['items']
    builtin_roles = {name: get('clusterrole', name) for name in BUILTIN_RULES if any(binding.get('metadata', {}).get('name') == name for binding in cluster_bindings)}
    validate_bindings(cluster_bindings + role_bindings, api.NS, builtin_roles)
    wanted = rbac_objects(EXPECTED_RULES, api.NS)
    changes = []
    for obj in wanted:
        args = [obj['kind'].lower(), obj['metadata']['name']]
        if obj['metadata'].get('namespace'):
            args.extend(['-n', obj['metadata']['namespace']])
        current = get(*args, '--ignore-not-found')
        if current:
            if not current.get('metadata', {}).get('resourceVersion'):
                raise RuntimeError('CNPG RBAC object lacks optimistic concurrency identity')
            # A foreign bounded-name object must not be stolen. Only the
            # original authenticated manager role or our exact scoped policy
            # is eligible for replacement.
            if obj['kind'].endswith('Binding'):
                if current.get('subjects') != obj['subjects'] or current.get('roleRef') != obj['roleRef']:
                    raise RuntimeError('Unexpected existing CNPG binding shape')
            elif current.get('rules') != obj['rules'] and not (obj['kind'] == 'ClusterRole' and current.get('rules') == EXPECTED_RULES):
                raise RuntimeError('Unexpected existing CNPG privilege shape')
            obj['metadata']['resourceVersion'] = current['metadata']['resourceVersion']
        changes.append(('replace' if current else 'create', obj))

    # install_operator precedes infrastructure rendering on a fresh cluster.
    # Apply only namespace identities before creating their bounded policies.
    # Existing namespace labels/security controls are not replaced or deleted.
    namespaces = [{'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': name}} for name in (api.NS, OPERATOR_NAMESPACE)]
    api.run([*prefix, 'apply', '--server-side', '--field-manager=platform-cnpg-namespaces', '-f', '-'], input=json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': namespaces}).encode())
    # Establish scoped authority before narrowing the original role, avoiding
    # a gap in operand permissions. No broad policy is reapplied on any path.
    # A partial failure is surfaced; the caller must not claim closure then.
    for verb, obj in sorted(changes, key=lambda change: change[1]['kind'] not in ('Role', 'RoleBinding')):
        api.run([*prefix, verb, '-f', '-'], input=json.dumps(obj).encode())
    # Use the original kubectl SSA manager: changing managers would conflict
    # with authenticated release deployment fields rather than replace them.
    api.run([*prefix, 'apply', '--server-side', '-f', '-'], input=manifest)
    api.run([*prefix, '-n', OPERATOR_NAMESPACE, 'rollout', 'status', 'deployment/cnpg-controller-manager', '--timeout=180s'])
