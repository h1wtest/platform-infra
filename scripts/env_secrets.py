"""Canonical owner-repository dotenv credentials and byte-exact derived private mounts.

Only explicit ``migrate`` reads the old manifest. ``load`` never falls back to it.
The initialized marker contains no credentials and prevents deleted environments
from being mistaken for a new installation.
"""
import json
import os
from pathlib import Path
import re
import tempfile

INFRA = 'platform-infra'
IDENTITY = 'identity-service'
GO = 'user-notification-service'
REPOSITORIES = (INFRA, IDENTITY, GO)
PURPOSE_KEYS = ('mfa_encryption_key', 'delivery_encryption_key', 'profile_quarantine_key',
                'notification_quarantine_key', 'admin_quarantine_key')
OWNERS = {
    'postgres_password': INFRA, 'gateway_token': INFRA, 'grafana_password': INFRA,
    'kafka_bootstrap_password': INFRA,
    'identity_token': IDENTITY, 'identity_runtime_password': IDENTITY,
    'identity_migration_password': IDENTITY, 'kafka_identity_password': IDENTITY,
    'mfa_encryption_key': IDENTITY, 'delivery_encryption_key': IDENTITY,
    'admin_email': IDENTITY, 'admin_password': IDENTITY, 'encryption_key': IDENTITY,
    'profile_token': GO, 'notification_token': GO, 'admin_token': GO,
    'telegram_bot_token': GO, 'telegram_webhook_secret': GO,
    'profile_runtime_password': GO, 'profile_migration_password': GO,
    'notification_runtime_password': GO, 'notification_migration_password': GO,
    'audit_runtime_password': GO, 'audit_migration_password': GO,
    'profile_quarantine_key': GO, 'notification_quarantine_key': GO,
    'admin_quarantine_key': GO, 'kafka_profile_password': GO,
    'kafka_notification_password': GO, 'kafka_admin_password': GO,
}
OPTIONAL_KEYS = ('telegram_bot_token', 'encryption_key')
REQUIRED_KEYS = tuple(key for key in OWNERS if key not in OPTIONAL_KEYS)
PRIVATE_FILES = {
    'ca.key': (INFRA, 'CA_PRIVATE_KEY'),
    'tls.key': (INFRA, 'TLS_PRIVATE_KEY'),
    'backup.key': (INFRA, 'BACKUP_ENCRYPTION_KEY'),
    'signing.pem': (IDENTITY, 'SIGNING_PRIVATE_KEY'),
    'certificates/identity-service/tls.key': (IDENTITY, 'IDENTITY_SERVICE_TLS_PRIVATE_KEY'),
    'certificates/profile-service/tls.key': (GO, 'PROFILE_SERVICE_TLS_PRIVATE_KEY'),
    'certificates/notification-service/tls.key': (GO, 'NOTIFICATION_SERVICE_TLS_PRIVATE_KEY'),
    'certificates/notification-worker/tls.key': (GO, 'NOTIFICATION_WORKER_TLS_PRIVATE_KEY'),
    'certificates/admin-audit-service/tls.key': (GO, 'ADMIN_AUDIT_SERVICE_TLS_PRIVATE_KEY'),
    'certificates/gateway/tls.key': (INFRA, 'GATEWAY_TLS_PRIVATE_KEY'),
    'certificates/redpanda/tls.key': (INFRA, 'REDPANDA_TLS_PRIVATE_KEY'),
}
MARKER = '.env-secrets.initialized'
_MARKER_BYTES = b'repository-env-v1\n'
_ASSIGNMENT = re.compile(r'(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*(.*)')


def _regular(path):
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise RuntimeError('Credential path must be a regular file: ' + path.name)


def _read(path):
    _regular(path)
    try:
        return path.read_bytes()
    except FileNotFoundError:
        raise RuntimeError('Missing saved credential material: ' + path.name) from None


def _parse(path):
    """Return exact original lines and parsed assignments, with secret-free errors."""
    _regular(path)
    if not path.exists():
        return [], {}
    try:
        text = path.read_bytes().decode('utf-8')
    except UnicodeError:
        raise RuntimeError('Invalid UTF-8 in repository .env') from None
    lines = text.splitlines(keepends=True)
    values = {}
    parsed = []
    for number, line in enumerate(lines, 1):
        body = line.rstrip('\r\n').strip(' \t')
        if not body or body.startswith('#'):
            parsed.append((None, line))
            continue
        match = _ASSIGNMENT.fullmatch(body)
        if not match:
            raise RuntimeError(f'Malformed repository .env assignment at line {number}')
        key, raw = match.groups()
        if key in values:
            raise RuntimeError(f'Duplicate repository .env key at line {number}')
        try:
            if raw.startswith('"'):
                value, end = json.JSONDecoder().raw_decode(raw)
                if not isinstance(value, str):
                    raise ValueError()
                tail = raw[end:].lstrip(' \t')
                if tail and not tail.startswith('#'):
                    raise ValueError()
            elif raw.startswith("'"):
                end = raw.find("'", 1)
                if end == -1:
                    raise ValueError()
                value = raw[1:end]
                tail = raw[end + 1:].lstrip(' \t')
                if tail and not tail.startswith('#'):
                    raise ValueError()
            else:
                value = '' if raw.startswith('#') else re.split(r'[ \t]+#', raw, maxsplit=1)[0].rstrip(' \t')
            # NUL cannot be passed to runtime environment variables or mount tools.
            if '\x00' in value:
                raise ValueError()
            value.encode('utf-8')
        except (ValueError, UnicodeError):
            raise RuntimeError(f'Malformed repository .env value at line {number}') from None
        values[key] = value
        parsed.append((key, line))
    return parsed, values


def _documents(state):
    workspace = Path(state).parent.parent
    return {owner: (workspace / owner / '.env', *_parse(workspace / owner / '.env'))
            for owner in REPOSITORIES}


def _validate(values):
    if not isinstance(values, dict) or any(key not in OWNERS for key in values):
        raise RuntimeError('Unrecognized saved credential fields; explicit mapping required')
    if any(not isinstance(value, str) or '\x00' in value for value in values.values()):
        raise RuntimeError('Saved credential values must be strings without NUL')
    try:
        for value in values.values():
            value.encode('utf-8')
    except UnicodeError:
        raise RuntimeError('Saved credential values must contain valid Unicode') from None
    missing = [key for key in REQUIRED_KEYS if not values.get(key)]
    # Old shared-key states can only pass through the explicit fenced rekey path.
    if values.get('encryption_key'):
        missing = [key for key in missing if key not in PURPOSE_KEYS]
    if missing:
        raise RuntimeError('Missing required repository credential: ' + missing[0].upper())
    if 'encryption_key' in values and not values['encryption_key']:
        raise RuntimeError('Empty legacy encryption key; explicit recovery required')


def _values(documents):
    values = {key: documents[owner][2][key.upper()] for key, owner in OWNERS.items()
              if key.upper() in documents[owner][2]}
    values.setdefault('telegram_bot_token', '')
    _validate(values)
    return values


def _private(documents):
    result = {}
    for relative, (owner, key) in PRIVATE_FILES.items():
        value = documents[owner][2].get(key)
        if not value:
            raise RuntimeError('Missing required private repository material: ' + key)
        try:
            result[relative] = value.encode('utf-8')
        except UnicodeError:
            raise RuntimeError('Invalid private repository material: ' + key) from None
    return result


def _disk_private(state):
    result = {}
    for relative in PRIVATE_FILES:
        data = _read(Path(state) / relative)
        if not data:
            raise RuntimeError('Empty saved private material: ' + relative)
        try:
            data.decode('utf-8')
        except UnicodeError:
            raise RuntimeError('Private material is not UTF-8: ' + relative) from None
        result[relative] = data
    return result


def _sync_directory(directory):
    if os.name == 'posix':
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _atomic(path, data):
    _regular(path)
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _sync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _plan(documents, updates, removals=()):
    """Validate and render all owners before publishing any of them."""
    plans = []
    for owner in REPOSITORIES:
        path, lines, existing = documents[owner]
        if not path.parent.is_dir():
            raise RuntimeError('Missing credential owner repository: ' + owner)
        changes = updates.get(owner, {})
        removed = set(removals.get(owner, ())) if removals else set()
        rendered = []
        remaining = dict(changes)
        for key, original in lines:
            if key in removed:
                continue
            if key in changes:
                remaining.pop(key, None)
                # Preserve original spelling, whitespace and comments if unchanged.
                if existing[key] == changes[key]:
                    rendered.append(original)
                else:
                    newline = '\r\n' if original.endswith('\r\n') else '\n'
                    body = original.rstrip('\r\n')
                    raw = _ASSIGNMENT.fullmatch(body.strip(' \t')).group(2)
                    comment = ''
                    if raw.startswith('"'):
                        _, end = json.JSONDecoder().raw_decode(raw)
                        tail = raw[end:]
                        if tail.lstrip(' \t').startswith('#'):
                            comment = tail if tail.startswith((' ', '\t')) else ' ' + tail
                    elif raw.startswith("'"):
                        tail = raw[raw.find("'", 1) + 1:]
                        if tail.lstrip(' \t').startswith('#'):
                            comment = tail if tail.startswith((' ', '\t')) else ' ' + tail
                    elif raw.startswith('#'):
                        comment = ' ' + raw
                    else:
                        match = re.search(r'[ \t]+#', raw)
                        if match:
                            comment = raw[match.start():]
                    rendered.append(key + '=' + json.dumps(changes[key], ensure_ascii=True) + comment + newline)
            else:
                rendered.append(original)
        if remaining and rendered and not rendered[-1].endswith(('\n', '\r')):
            rendered.append('\n')
        rendered.extend(key + '=' + json.dumps(value, ensure_ascii=True) + '\n'
                        for key, value in remaining.items())
        plans.append((path, ''.join(rendered).encode('utf-8')))
    return plans


def _publish(plans):
    for path, data in plans:
        _atomic(path, data)


def _credential_updates(values):
    updates = {owner: {} for owner in REPOSITORIES}
    removals = {owner: set() for owner in REPOSITORIES}
    for key, owner in OWNERS.items():
        if key in values:
            updates[owner][key.upper()] = values[key]
        else:
            removals[owner].add(key.upper())
    return updates, removals


def _add_private(updates, private):
    for relative, data in private.items():
        owner, key = PRIVATE_FILES[relative]
        updates[owner][key] = data.decode('utf-8')


def _marker(state):
    path = Path(state) / MARKER
    _regular(path)
    if not path.exists():
        return False
    if _read(path) != _MARKER_BYTES:
        raise RuntimeError('Invalid repository credential initialization marker; restore saved state')
    return True


def exists(state):
    """Whether saved installation artifacts prohibit generating a new identity."""
    state = Path(state)
    if _marker(state) or (state / 'secrets.json').exists():
        return True
    artifacts = tuple(PRIVATE_FILES) + ('ca.crt', 'tls.crt')
    return any((state / relative).exists() or (state / relative).is_symlink() for relative in artifacts)


def initial_values(state):
    """Read draft bootstrap preferences, ignoring blank required placeholders."""
    documents = _documents(state)
    if any(documents[owner][2].get(key) for owner, key in PRIVATE_FILES.values()):
        raise RuntimeError('Saved private .env material requires restoring matching certificate state; fresh key generation refused')
    return {key: documents[owner][2][key.upper()] for key, owner in OWNERS.items()
            if key.upper() in documents[owner][2]
            and (documents[owner][2][key.upper()] or key == 'telegram_bot_token')}


def load(state):
    """Load canonical owner dotenv values only; never import or regenerate."""
    _marker(state)
    return _values(_documents(state))


def save(state, values):
    """Replace mapped credentials, preserving unrelated config and private keys."""
    _validate(values)
    updates, removals = _credential_updates(values)
    _publish(_plan(_documents(state), updates, removals))


def capture_private(state):
    """Persist freshly generated private bytes, never repair initialized env loss."""
    documents = _documents(state)
    private = _disk_private(state)
    if _marker(state):
        if _private(documents) != private:
            raise RuntimeError('Derived private material mismatch; restore matching saved state')
        return
    updates = {owner: {} for owner in REPOSITORIES}
    _add_private(updates, private)
    for owner, values in updates.items():
        for key, value in values.items():
            existing = documents[owner][2].get(key)
            if existing and existing != value:
                raise RuntimeError('Private repository material conflict: ' + key)
    _publish(_plan(documents, updates))


def materialize(state):
    """Restore missing private mounts after preflighting every existing mount."""
    state = Path(state)
    private = _private(_documents(state))
    for relative, data in private.items():
        path = state / relative
        _regular(path)
        if path.exists() and _read(path) != data:
            raise RuntimeError('Derived private material mismatch: ' + relative)
    for relative, data in private.items():
        path = state / relative
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not path.exists():
            _atomic(path, data)
        else:
            os.chmod(path, 0o600)


def initialize(state):
    """Commit a complete canonical store without keeping credentials in marker."""
    documents = _documents(state)
    _values(documents)
    private = _private(documents)
    if private != _disk_private(state):
        raise RuntimeError('Derived private material mismatch during initialization')
    if not _marker(state):
        state = Path(state)
        state.mkdir(parents=True, exist_ok=True, mode=0o700)
        _atomic(state / MARKER, _MARKER_BYTES)


def read_legacy(state):
    """Explicit recovery/rekey reader; not a runtime fallback."""
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError()
            result[key] = value
        return result
    try:
        values = json.loads(_read(Path(state) / 'secrets.json').decode('utf-8'), object_pairs_hook=unique)
    except (ValueError, UnicodeError):
        raise RuntimeError('Invalid legacy credential manifest; restore original saved state') from None
    if not isinstance(values, dict) or any(key not in OWNERS for key in values):
        raise RuntimeError('Unrecognized legacy credential fields; explicit mapping required')
    if any(not isinstance(value, str) or '\x00' in value for value in values.values()):
        raise RuntimeError('Invalid legacy credential value types')
    return values


def migrate(state):
    """Resume a verified import; remove its source only after durable commit.

    Partial multi-file publication is safe to resume because the old manifest
    remains authoritative until every value and private byte has been reread.
    Once initialized, missing .env files always fail closed, even if an old
    manifest survived an interrupted unlink.
    """
    state = Path(state)
    legacy = state / 'secrets.json'
    if _marker(state):
        values = load(state)
        private = _private(_documents(state))
        if legacy.exists():
            original = read_legacy(state)
            original.setdefault('telegram_bot_token', '')
            _validate(original)
            if values != original or private != _disk_private(state):
                raise RuntimeError('Initialized repository credentials conflict with legacy import; explicit recovery required')
            legacy.unlink()
            _sync_directory(state)
        return values
    original = read_legacy(state)
    original.setdefault('telegram_bot_token', '')
    _validate(original)
    private = _disk_private(state)
    public = ('ca.crt', 'tls.crt') + tuple(relative[:-3] + 'crt' for relative in PRIVATE_FILES
                                          if relative.startswith('certificates/'))
    for relative in public:
        if not _read(state / relative):
            raise RuntimeError('Empty saved certificate: ' + relative)
    documents = _documents(state)
    updates, removals = _credential_updates(original)
    _add_private(updates, private)
    for owner, values in updates.items():
        for key, value in values.items():
            existing = documents[owner][2].get(key)
            if existing and existing != value:
                raise RuntimeError('Repository credential conflict during legacy import: ' + key)
    _publish(_plan(documents, updates, removals))
    if load(state) != original or _private(_documents(state)) != private:
        raise RuntimeError('Repository credential import verification failed; legacy source retained')
    initialize(state)
    legacy.unlink()
    _sync_directory(state)
    return original
