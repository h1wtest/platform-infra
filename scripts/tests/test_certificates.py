import pathlib
import ssl
import sys
import tempfile
import types
import unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import cli
from certificate_repair import repair


class StrictCertificateBehavior(unittest.TestCase):
    def test_strict_ca_and_leaf_generation_preserves_private_key_on_repair(self):
        with tempfile.TemporaryDirectory() as directory:
            state = pathlib.Path(directory)
            cli.create_secrets(state)
            leaf = state / 'certificates/gateway/tls.crt'
            private = (state / 'ca.key').read_bytes()
            leaf_private = (state / 'certificates/gateway/tls.key').read_bytes()
            cli.run(['openssl', 'verify', '-x509_strict', '-CAfile', state / 'ca.crt', '-verify_hostname', 'localhost', leaf])
            # Reproduce the old permissive CA by reissuing the SAME private identity without keyUsage.
            cli.run(['openssl', 'req', '-x509', '-new', '-sha256', '-days', '365', '-key', state / 'ca.key', '-subj', '/CN=SSO Remediation Local CA', '-out', state / 'ca.crt'])
            with self.assertRaises(RuntimeError):
                cli.run(['openssl', 'verify', '-x509_strict', '-CAfile', state / 'ca.crt', leaf])
            repair(types.SimpleNamespace(STATE=state, run=cli.run))
            self.assertEqual(private, (state / 'ca.key').read_bytes())
            self.assertEqual(leaf_private, (state / 'certificates/gateway/tls.key').read_bytes())
            cli.run(['openssl', 'verify', '-x509_strict', '-CAfile', state / 'ca.crt', '-verify_hostname', 'localhost', leaf])
            certificate = leaf.read_bytes()
            repair(types.SimpleNamespace(STATE=state, run=cli.run))
            self.assertEqual(certificate, leaf.read_bytes())


if __name__ == '__main__': unittest.main()
