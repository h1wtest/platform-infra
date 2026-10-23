"""Crash-safe publication for local credential manifests on the same filesystem."""
import json
import os
from pathlib import Path
import tempfile


def atomic_json(path, value, *, before_replace=None):
    path = Path(path)
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            json.dump(value, stream)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        if before_replace:
            before_replace()
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def preserve_key_manifest(state, values, *, name):
    destination = Path(state) / name
    atomic_json(destination, {'keys': dict(values), 'purpose': 'Crash recovery key manifest; contains legacy and all target purpose keys'})
    return destination
