"""Bind Docker/OCI archive config identity to the exact inspected image digest."""
import hashlib
import json
import tarfile


def config_identity(path, image_id):
    with tarfile.open(path) as archive:
        def read(name):
            member = archive.getmember(name)
            if not member.isfile():
                raise RuntimeError('Image archive metadata must be a regular file')
            return archive.extractfile(member).read()

        def blob(digest):
            if not digest.startswith('sha256:') or len(digest) != 71 or any(c not in '0123456789abcdef' for c in digest[7:]):
                raise RuntimeError('Image archive contains an invalid digest')
            content = read('blobs/sha256/' + digest[7:])
            if 'sha256:' + hashlib.sha256(content).hexdigest() != digest:
                raise RuntimeError('Image archive blob differs from its declared digest')
            return content

        manifests = json.loads(read('manifest.json'))
        if len(manifests) != 1:
            raise RuntimeError('Image archive must contain exactly one runnable image')
        config = read(manifests[0]['Config'])
        config_id = 'sha256:' + hashlib.sha256(config).hexdigest()
        if image_id == config_id:
            return config_id
        # Containerd-backed Docker reports an OCI index/manifest ID rather than the config ID.
        index = json.loads(read('index.json'))
        if image_id not in [item.get('digest') for item in index.get('manifests', [])]:
            raise RuntimeError('Image archive root differs from the inspected image ID')
        pending = [image_id]
        visited = set()
        while pending:
            digest = pending.pop()
            if digest in visited:
                continue
            visited.add(digest)
            node = json.loads(blob(digest))
            if node.get('config', {}).get('digest') == config_id:
                if blob(config_id) != config:
                    raise RuntimeError('Image archive config association is inconsistent')
                return config_id
            pending.extend(item['digest'] for item in node.get('manifests', []))
        raise RuntimeError('Image archive does not bind the inspected image ID to the scanned config')
