"""Storage edits must never silently rotate credentials backing persisted state."""
import base64
import binascii
import hmac
import json

from env_secrets import PURPOSE_KEYS
from manifests import DBS

IMMUTABLE_KEYS = ('postgres_password', 'kafka_bootstrap_password', *PURPOSE_KEYS,
                  *(database + '_' + role + '_password' for database in DBS
                    for role in ('runtime', 'migration')))


def verify(runtime, values):
    """Read existing runtime material before any Secret apply; never mutate it."""
    body = runtime.kube('get', 'secret', 'platform-secrets', '--ignore-not-found=true', '-o', 'json').stdout
    if not body.strip():
        return
    try:
        document = json.loads(body)
        data = document['data']
        if not isinstance(data, dict):
            raise ValueError()
        previous = {}
        for key in IMMUTABLE_KEYS:
            encoded = data[key]
            if not isinstance(encoded, str):
                raise ValueError()
            previous[key] = base64.b64decode(encoded, validate=True)
            if not previous[key]:
                raise ValueError()
    except (KeyError, TypeError, ValueError, binascii.Error):
        raise RuntimeError('Existing stateful credentials are incomplete or malformed; explicit recovery required') from None
    for key, original in previous.items():
        current = values.get(key)
        if not isinstance(current, str) or not hmac.compare_digest(original, current.encode('utf-8')):
            raise RuntimeError('Stateful credential change refused: ' + key.upper() + '; explicit rotation required')
