"""Explicit local certificate repair: retain CA/service private keys, subjects and leaf SANs."""
import os
from pathlib import Path
import tempfile
import uuid


def atomic_bytes(path, content):
    descriptor, name = tempfile.mkstemp(dir=path.parent, prefix='.' + path.name + '.')
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(content); stream.flush(); os.fsync(stream.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        if os.path.exists(name): os.unlink(name)


def repair(runtime):
    state = runtime.STATE
    run = runtime.run
    # Strict check is idempotent; old CA lacking keyUsage fails even if permissive clients accepted it.
    leaves = [(state / 'tls.crt', state / 'tls.key', state / 'tls.csr')]
    leaves += [(directory / 'tls.crt', directory / 'tls.key', directory / 'tls.csr') for directory in sorted((state / 'certificates').iterdir()) if directory.is_dir()]
    valid = all(run(['openssl', 'verify', '-x509_strict', '-CAfile', state / 'ca.crt', certificate], check=False).returncode == 0 for certificate, _, _ in leaves)
    if valid:
        print('Existing authority and service certificates already satisfy strict X509 verification; no changes.')
        return
    archive = state / ('certificate-repair-' + uuid.uuid4().hex)
    archive.mkdir(mode=0o700)
    serial = run(['openssl', 'x509', '-in', state / 'ca.crt', '-noout', '-serial']).stdout.decode().strip().split('=', 1)[1]
    subject = run(['openssl', 'x509', '-in', state / 'ca.crt', '-noout', '-subject', '-nameopt', 'compat']).stdout.decode().strip().split('=', 1)[1].strip()
    if not subject.startswith('/'):
        raise RuntimeError('Unexpected CA subject representation; refusing implicit identity change')
    with tempfile.TemporaryDirectory(dir=state) as directory:
        staging = Path(directory)
        ca = staging / 'ca.crt'
        run(['openssl', 'req', '-new', '-x509', '-sha256', '-days', '365', '-key', state / 'ca.key', '-subj', subject, '-set_serial', '0x' + serial, '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-addext', 'subjectKeyIdentifier=hash', '-addext', 'authorityKeyIdentifier=keyid:always', '-out', ca])
        originals = []
        for index, (certificate, key, _) in enumerate(leaves):
            sans = run(['openssl', 'x509', '-in', certificate, '-noout', '-ext', 'subjectAltName']).stdout.decode().splitlines()[1:]
            san = ''.join(sans).strip().replace('IP Address:', 'IP:')
            leaf_subject = run(['openssl', 'x509', '-in', certificate, '-noout', '-subject', '-nameopt', 'compat']).stdout.decode().strip().split('=', 1)[1].strip()
            leaf_serial = run(['openssl', 'x509', '-in', certificate, '-noout', '-serial']).stdout.decode().strip().split('=', 1)[1]
            extensions = staging / f'{index}.ext'
            extensions.write_text('subjectAltName=' + san + '\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\nextendedKeyUsage=serverAuth\n')
            csr = staging / f'{index}.csr'; output = staging / f'{index}.crt'
            run(['openssl', 'req', '-new', '-key', key, '-subj', leaf_subject, '-out', csr])
            run(['openssl', 'x509', '-req', '-in', csr, '-CA', ca, '-CAkey', state / 'ca.key', '-set_serial', '0x' + leaf_serial, '-days', '90', '-sha256', '-extfile', extensions, '-out', output])
            run(['openssl', 'verify', '-x509_strict', '-CAfile', ca, output])
            originals.append((certificate, output))
        # Reissuing certs with the same CA public key preserves issuer identity and all private material.
        atomic_bytes(archive / 'ca.crt', (state / 'ca.crt').read_bytes())
        for index, (certificate, output) in enumerate(originals):
            atomic_bytes(archive / f'leaf-{index}.crt', certificate.read_bytes())
            atomic_bytes(certificate, output.read_bytes())
        atomic_bytes(state / 'ca.crt', ca.read_bytes())
    print('Reissued strict X509 CA/leaves with identical private keys, subjects and serials; no global trust changes. Reapply TLS Secrets and roll workloads before acceptance.')
