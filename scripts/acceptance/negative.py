#!/usr/bin/env python3
"""Boundary authorization acceptance against real services, no framework mocks."""
import argparse
import json
from pathlib import Path
import urllib.error
import urllib.request

from e2e import Client


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base', default='https://localhost:8448')
    parser.add_argument('--state', required=True)
    parser.add_argument('--ca')
    args = parser.parse_args()
    account = json.loads(Path(args.state).read_text())['probe']
    client = Client(args.base, args.ca)
    client.login(account['email'], account['password'])
    _, original, _ = client.call('GET', '/api/v1/users/me')
    original_name = original['profile'].get('display_name')
    request = urllib.request.Request(args.base + '/api/v1/users/me',
        data=json.dumps({'display_name': 'Cross-origin must never persist'}).encode(),
        headers={'Origin': 'https://attacker.example.invalid', 'Content-Type': 'application/json',
                 'X-CSRF-Token': client.csrf}, method='PATCH')
    try:
        response = client.opener.open(request, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    assert response.code == 403, f'Cross-origin mutation accepted: {response.code}'
    response.read()
    _, after, _ = client.call('GET', '/api/v1/users/me')
    assert after['profile'].get('display_name') == original_name
    # An ordinary user may never turn a permission-shaped request into admin access.
    client.call('POST', '/api/v1/admin/users/' + account['user_id'] + '/ban',
                {'reason': 'Must not be executed', 'roles': ['super_admin']}, expected=(403,))
    client.call('GET', '/api/v1/users/me')
    # Signed-looking but invalid bearers must not be treated as opaque cookie sessions.
    anonymous = Client(args.base, args.ca)
    from e2e import b64url
    forged = b64url(json.dumps({'alg': 'none', 'typ': 'JWT'}).encode()) + '.' + b64url(json.dumps({'sub': 'untrusted-fixture', 'exp': 4000000000}).encode()) + '.'
    anonymous.call('GET', '/api/v1/users/me', bearer=forged, expected=(401,))
    anonymous.call('GET', '/oauth/userinfo', bearer=forged, expected=(401,))
    client.call('GET', '/api/v1/users/me', bearer=forged, expected=(401,))
    client.call('GET', '/api/v1/auth/me', bearer=forged, expected=(401,))
    client.call('GET', '/api/v1/users/me')
    # Body parser rejects invalid JSON without exposing internal failure details.
    malformed = urllib.request.Request(args.base + '/api/v1/auth/login', data=b'{',
        headers={'Origin': args.base, 'Content-Type': 'application/json', 'X-CSRF-Token': client.csrf}, method='POST')
    try:
        response = client.opener.open(malformed, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    assert response.code in (400, 422), f'Malformed JSON became server error: {response.code}'
    body = response.read().decode(errors='replace').lower()
    assert not any(term in body for term in ('postgres://', 'password_hash', 'sqlx::', 'stacktrace'))
    client.call('POST', '/api/v1/auth/logout', {})
    print('PASS invalid Origin/CSRF/nonadmin mutation/forged bearer/malformed JSON boundaries')


if __name__ == '__main__':
    main()
