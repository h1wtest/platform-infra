#!/usr/bin/env python3
"""Concurrent OAuth redemption against real identity/SQL transactions."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import secrets
import threading
import urllib.parse

from e2e import Client, b64url


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base', default='https://localhost:8448')
    parser.add_argument('--state', required=True)
    parser.add_argument('--ca')
    args = parser.parse_args()
    user = json.loads(Path(args.state).read_text())['probe']
    authenticated = Client(args.base, args.ca)
    authenticated.login(user['email'], user['password'])
    verifier = secrets.token_urlsafe(48)
    callback = args.base.rstrip('/') + '/oidc/callback'
    authorize = {'client_id': 'web-demo', 'redirect_uri': callback, 'response_type': 'code',
                 'scope': 'openid email offline_access', 'nonce': secrets.token_urlsafe(24),
                 'state': secrets.token_urlsafe(24), 'code_challenge_method': 'S256',
                 'code_challenge': b64url(hashlib.sha256(verifier.encode()).digest())}
    _, _, headers = authenticated.call('GET', '/oauth/authorize?' + urllib.parse.urlencode(authorize), expected=(302, 303))
    location = headers.get('Location', headers.get('location'))
    code = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query)['code'][0]
    barrier = threading.Barrier(2)
    request = {'grant_type': 'authorization_code', 'client_id': 'web-demo', 'redirect_uri': callback,
               'code': code, 'code_verifier': verifier}

    def redeem():
        client = Client(args.base, args.ca)
        barrier.wait(timeout=10)
        return client.call('POST', '/oauth/token', request, form=True, expected=(200, 400))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: redeem(), range(2)))
    assert sorted(result[0] for result in results) == [200, 400], 'Authorization code issued two grants or neither'
    issued = next(result[1] for result in results if result[0] == 200)
    invalidated = Client(args.base, args.ca)
    invalidated.call('GET', '/oauth/userinfo', bearer=issued['access_token'], expected=(401,))
    authenticated.login(user['email'], user['password'])
    _, _, new_headers = authenticated.call('GET', '/oauth/authorize?' + urllib.parse.urlencode(authorize), expected=(302, 303))
    new_location = new_headers.get('Location', new_headers.get('location'))
    fresh_code = urllib.parse.parse_qs(urllib.parse.urlsplit(new_location).query)['code'][0]
    fresh_request = dict(request, code=fresh_code)
    _, issued, _ = invalidated.call('POST', '/oauth/token', fresh_request, form=True)
    refresh_request = {'grant_type': 'refresh_token', 'client_id': 'web-demo', 'refresh_token': issued['refresh_token']}
    refresh_barrier = threading.Barrier(2)

    def refresh():
        client = Client(args.base, args.ca)
        refresh_barrier.wait(timeout=10)
        return client.call('POST', '/oauth/token', refresh_request, form=True, expected=(200, 400))

    with ThreadPoolExecutor(max_workers=2) as pool:
        rotations = list(pool.map(lambda _: refresh(), range(2)))
    assert sorted(result[0] for result in rotations) == [200, 400], 'Refresh rotation produced two live branches or neither'
    rotated = next(result[1] for result in rotations if result[0] == 200)
    consumer = Client(args.base, args.ca)
    consumer.call('GET', '/oauth/userinfo', bearer=rotated['access_token'], expected=(401,))
    consumer.call('POST', '/oauth/token', {'grant_type': 'refresh_token', 'client_id': 'web-demo',
                  'refresh_token': rotated['refresh_token']}, form=True, expected=(400,))
    authenticated.call('POST', '/api/v1/auth/logout', {}, expected=(200, 401))
    print('PASS concurrent code-once/refresh-one-branch/reuse durably revokes entire family')


if __name__ == '__main__':
    main()
