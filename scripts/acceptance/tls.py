#!/usr/bin/env python3
"""Validate real gateway trust and refuse an unrelated trust root."""
import argparse
import ssl
import urllib.error
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument('--base', default='https://localhost:8448')
parser.add_argument('--ca', required=True)
args = parser.parse_args()
with urllib.request.urlopen(args.base + '/.well-known/openid-configuration', context=ssl.create_default_context(cafile=args.ca), timeout=10) as response:
    assert response.status == 200
try:
    urllib.request.urlopen(args.base + '/.well-known/openid-configuration', context=ssl.create_default_context(), timeout=10)
except urllib.error.URLError as error:
    assert isinstance(error.reason, ssl.SSLCertVerificationError), 'Failure was not certificate trust rejection'
else:
    raise AssertionError('Untrusted local CA was unexpectedly accepted by default trust store')
print('PASS actual HTTPS gateway validates only explicit local CA; system trust unchanged')
