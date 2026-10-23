#!/usr/bin/env python3
"""Real TLS/API/Mailpit acceptance; no mocked authentication or delivery.

Credentials live in an explicitly selected mode-0600 state file, never stdout.
Use isolated disposable users and --mode probe for infrastructure fault checks.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.cookiejar
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    def __init__(self, base: str, ca: str | None = None):
        self.base = base.rstrip('/')
        self.jar = http.cookiejar.CookieJar()
        # Strict TLS verification is mandatory, including acceptance.
        from common import CA
        context = ssl.create_default_context(cafile=ca or str(CA))
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context),
            urllib.request.HTTPCookieProcessor(self.jar), NoRedirect())
        self.csrf = ''

    def call(self, method, path, body=None, *, expected=(200,), form=False, bearer=None):
        headers = {'Accept': 'application/json', 'Origin': self.base}
        if bearer:
            headers['Authorization'] = 'Bearer ' + bearer
        if self.csrf:
            headers['X-CSRF-Token'] = self.csrf
        data = None
        if body is not None:
            if form:
                data = urllib.parse.urlencode(body).encode()
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
            else:
                data = json.dumps(body).encode()
                headers['Content-Type'] = 'application/json'
        request = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            response = self.opener.open(request, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        raw = response.read()
        try:
            result = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            result = {'non_json': True}
        status = response.code
        if status not in expected:
            # Do not print bodies: they may contain credentials or delivery tokens.
            code = result.get('code', 'none') if isinstance(result, dict) else 'non-object'
            raise AssertionError(f'{method} {path.split("?")[0]}: expected {expected}, got {status}, code={code}')
        return status, result, dict(response.headers)

    def bootstrap_csrf(self):
        _, body, _ = self.call('GET', '/api/v1/auth/csrf')
        self.csrf = body['csrf_token']

    def login(self, email, password, totp_secret=None):
        self.bootstrap_csrf()
        _, result, _ = self.call('POST', '/api/v1/auth/login', {
            'email': email, 'password': password, 'device_name': 'Real acceptance client'})
        if result.get('status') == 'mfa_required':
            assert totp_secret, 'MFA challenge requires actual TOTP secret'
            _, result, _ = self.call('POST', '/api/v1/auth/mfa/verify-login', {
                'challenge_id': result['challenge_id'], 'code': totp(totp_secret)})
        assert result.get('status') == 'authenticated', 'Login did not authenticate'
        self.bootstrap_csrf()
        return result


def totp(secret, timestamp=None):
    timestamp = int(time.time() if timestamp is None else timestamp)
    key = base64.b32decode(secret.upper() + '=' * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack('>Q', timestamp // 30), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return f'{(struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000:06d}'


def eventually(label, function, timeout=60):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            value = function()
            if value:
                return value
        except (AssertionError, OSError, ValueError, KeyError) as error:
            last = type(error).__name__
        time.sleep(0.5)
    raise AssertionError(f'Timed out: {label}; last failure type={last}')


def mail_json(base, path):
    with urllib.request.urlopen(base.rstrip('/') + path, timeout=10) as response:
        return json.load(response)


def find_mail(base, email, purpose, timeout=60):
    def fetch():
        listing = mail_json(base, '/api/v1/messages')
        for entry in listing.get('messages', []):
            recipients = entry.get('To', [])
            if not any(recipient.get('Address', '').lower() == email.lower() for recipient in recipients):
                continue
            message = mail_json(base, '/api/v1/message/' + entry['ID'])
            text = str(message.get('Text', '')) + '\n' + str(message.get('HTML', ''))
            if purpose == 'verification':
                match = re.search(r'(?<!\d)(\d{6})(?!\d)', text)
            else:
                match = re.search(r'(?:token=|reset/)([A-Za-z0-9_.~-]{20,})', text)
            if match:
                return match.group(1)
        return None
    return eventually(f'{purpose} delivery to disposable user', fetch, timeout)


def session_rows(result):
    return result if isinstance(result, list) else result['sessions']


def new_user(args, label):
    email = f'acceptance-{label}-{uuid.uuid4().hex}@example.invalid'
    password = secrets.token_urlsafe(24) + 'aA9!'
    client = Client(args.base, args.ca)
    client.bootstrap_csrf()
    _, registered, _ = client.call('POST', '/api/v1/auth/register', {
        'email': email, 'password': password}, expected=(201,))
    code = find_mail(args.mailpit, email, 'verification')
    client.call('POST', '/api/v1/auth/verify-email', {'user_id': registered['user_id'], 'code': code})
    client.login(email, password)
    def profile():
        _, data, _ = client.call('GET', '/api/v1/users/me', expected=(200, 404))
        return data.get('profile') if isinstance(data, dict) else None
    actual = eventually('profile created from real Kafka event', profile)
    assert actual['email'] == email
    return client, {'email': email, 'password': password, 'user_id': registered['user_id']}


def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()


def der(tag, data):
    size = len(data)
    length = bytes([size]) if size < 128 else bytes([0x80 + (size.bit_length() + 7) // 8]) + size.to_bytes((size.bit_length() + 7) // 8, 'big')
    return bytes([tag]) + length + data


def verify_rs256(token, jwks, issuer, audience, nonce=None):
    encoded_header, encoded_claims, signature = token.split('.')
    decode = lambda text: base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))
    header, claims = json.loads(decode(encoded_header)), json.loads(decode(encoded_claims))
    assert header['alg'] == 'RS256'
    key = next(key for key in jwks['keys'] if key['kid'] == header['kid'])
    assert key['kty'] == 'RSA' and 'd' not in key
    def integer(value):
        raw = decode(value).lstrip(b'\0') or b'\0'
        return der(2, (b'\0' if raw[0] & 0x80 else b'') + raw)
    rsa = der(0x30, integer(key['n']) + integer(key['e']))
    spki = der(0x30, bytes.fromhex('300d06092a864886f70d0101010500') + der(3, b'\0' + rsa))
    pem = b'-----BEGIN PUBLIC KEY-----\n' + base64.encodebytes(spki) + b'-----END PUBLIC KEY-----\n'
    with tempfile.TemporaryDirectory(prefix='sso-verify-') as directory:
        root = Path(directory)
        (root / 'key.pem').write_bytes(pem)
        (root / 'signature').write_bytes(decode(signature))
        (root / 'message').write_bytes((encoded_header + '.' + encoded_claims).encode())
        checked = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(root / 'key.pem'),
                                  '-signature', str(root / 'signature'), str(root / 'message')],
                                 capture_output=True, timeout=10)
        assert checked.returncode == 0, 'Real OpenSSL JWT signature verification failed'
    assert claims['iss'] == issuer
    assert audience == claims['aud'] or isinstance(claims['aud'], list) and audience in claims['aud']
    assert claims['exp'] > time.time() and claims['iat'] <= time.time() + 5
    if nonce is not None:
        assert claims['nonce'] == nonce
    return claims


def oidc(args, authenticated):
    _, discovery, _ = authenticated.call('GET', '/.well-known/openid-configuration')
    _, jwks, _ = authenticated.call('GET', '/.well-known/jwks.json')
    assert discovery['issuer'] == args.base.rstrip('/')
    verifier, nonce, state = secrets.token_urlsafe(48), secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    callback = args.base.rstrip('/') + '/oidc/callback'
    parameters = {'client_id': 'web-demo', 'redirect_uri': callback, 'response_type': 'code',
                  'scope': 'openid profile email offline_access', 'code_challenge': b64url(hashlib.sha256(verifier.encode()).digest()),
                  'code_challenge_method': 'S256', 'nonce': nonce, 'state': state}
    _, _, headers = authenticated.call('GET', '/oauth/authorize?' + urllib.parse.urlencode(parameters), expected=(302, 303))
    location = headers.get('Location', headers.get('location', ''))
    assert location.startswith(callback + '?'), 'OIDC must redirect to exact registered callback'
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query)
    assert query['state'] == [state]
    token_client = Client(args.base, args.ca)
    request = {'grant_type': 'authorization_code', 'client_id': 'web-demo', 'redirect_uri': callback,
               'code': query['code'][0], 'code_verifier': verifier}
    _, issued, _ = token_client.call('POST', '/oauth/token', request, form=True)
    claims = verify_rs256(issued['id_token'], jwks, discovery['issuer'], 'web-demo', nonce)
    assert claims['email_verified'] is True
    _, info, _ = token_client.call('GET', '/oauth/userinfo', bearer=issued['access_token'])
    assert info['sub'] == claims['sub']
    refresh_request = {'grant_type': 'refresh_token', 'client_id': 'web-demo', 'refresh_token': issued['refresh_token']}
    _, rotated, _ = token_client.call('POST', '/oauth/token', refresh_request, form=True)
    assert rotated['refresh_token'] != issued['refresh_token']
    token_client.call('POST', '/oauth/token', refresh_request, form=True, expected=(400,))
    token_client.call('GET', '/oauth/userinfo', bearer=rotated['access_token'], expected=(401,))
    token_client.call('POST', '/oauth/token', request, form=True, expected=(400,))
    parameters['redirect_uri'] = 'https://example.invalid/steal'
    authenticated.call('GET', '/oauth/authorize?' + urllib.parse.urlencode(parameters), expected=(400,))
    print('PASS oidc real signature/issuer/audience/nonce/state/PKCE/code-once/refresh-reuse')


def save_state(path, state):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from private_files import atomic_json
    atomic_json(path, state)


def full(args):
    anonymous = Client(args.base, args.ca)
    anonymous.call('GET', '/api/v1/users/me', expected=(401,))
    anonymous.call('GET', '/api/v1/auth/sessions', expected=(401,))
    anonymous.bootstrap_csrf()
    anonymous.call('POST', '/api/v1/auth/register', {'email': 'not-email', 'password': 'x'}, expected=(400,))
    first, account = new_user(args, 'first')
    second, other = new_user(args, 'second')
    print('PASS register/actual email/verification/Kafka profile for two users')
    first.call('PATCH', '/api/v1/users/me', {'display_name': 'Acceptance retained profile'})
    _, profile, _ = first.call('GET', '/api/v1/users/me')
    assert profile['profile']['display_name'] == 'Acceptance retained profile'
    legitimate_csrf = first.csrf
    first.csrf = 'invalid-acceptance-csrf'
    first.call('PATCH', '/api/v1/users/me', {'display_name': 'Must not be written'}, expected=(403,))
    first.csrf = legitimate_csrf
    _, unchanged, _ = first.call('GET', '/api/v1/users/me')
    assert unchanged['profile']['display_name'] == 'Acceptance retained profile'
    second.call('GET', '/api/v1/admin/users', expected=(403,))
    _, rows, _ = second.call('GET', '/api/v1/auth/sessions')
    target = session_rows(rows)[0]['session_id']
    first.call('DELETE', '/api/v1/auth/sessions/' + target, expected=(403, 404))
    second.call('GET', '/api/v1/users/me')
    print('PASS profile persistence/admin denial/foreign session ownership')
    extra = Client(args.base, args.ca)
    extra.login(account['email'], account['password'])
    _, me, _ = extra.call('GET', '/api/v1/auth/me')
    first.call('DELETE', '/api/v1/auth/sessions/' + me['session_id'])
    extra.call('GET', '/api/v1/auth/me', expected=(401,))
    extra.call('GET', '/api/v1/users/me', expected=(401,))
    print('PASS session revoke enforced across identity and profile')
    oidc(args, first)
    first.login(account['email'], account['password'])
    first.call('POST', '/api/v1/auth/reauth', {'password': account['password']})
    _, setup, _ = first.call('POST', '/api/v1/auth/mfa/setup', {})
    secret = setup['secret']
    first.call('POST', '/api/v1/auth/mfa/enable', {'code': totp(secret)})
    first.call('POST', '/api/v1/auth/mfa/setup', {}, expected=(400, 403, 409))
    # A new setup must not silently disable the enabled factor.
    fresh = Client(args.base, args.ca)
    fresh.bootstrap_csrf()
    _, challenge, _ = fresh.call('POST', '/api/v1/auth/login', {'email': account['email'], 'password': account['password']})
    assert challenge['status'] == 'mfa_required'
    recovery = setup['recovery_codes'][0]
    fresh.call('POST', '/api/v1/auth/mfa/verify-login', {'challenge_id': challenge['challenge_id'], 'code': recovery})
    fresh.bootstrap_csrf()
    fresh.call('POST', '/api/v1/auth/mfa/verify-login', {'challenge_id': challenge['challenge_id'], 'code': recovery}, expected=(400, 401))
    replay = Client(args.base, args.ca)
    replay.bootstrap_csrf()
    _, next_challenge, _ = replay.call('POST', '/api/v1/auth/login', {'email': account['email'], 'password': account['password']})
    replay.call('POST', '/api/v1/auth/mfa/verify-login', {'challenge_id': next_challenge['challenge_id'], 'code': recovery}, expected=(400, 401))
    print('PASS MFA factor required/challenge once/recovery code once')
    # Retain a disposable MFA account for real browser verification, no stdout secrets.
    account['totp_secret'] = secret
    second.call('POST', '/api/v1/auth/password/forgot', {'email': other['email']}, expected=(200, 202))
    reset = find_mail(args.mailpit, other['email'], 'reset')
    new_password = secrets.token_urlsafe(24) + 'aA9!'
    anonymous.call('POST', '/api/v1/auth/password/reset', {'token': reset, 'password': new_password})
    second.call('GET', '/api/v1/users/me', expected=(401,))
    anonymous.call('POST', '/api/v1/auth/password/reset', {'token': reset, 'password': new_password}, expected=(400, 401))
    other['password'] = new_password
    second.login(other['email'], new_password)
    second.call('GET', '/api/v1/users/me')
    print('PASS actual password recovery email/token once/revoke previous session')
    previous_session = Client(args.base, args.ca)
    previous_session.login(other['email'], other['password'])
    second.call('POST', '/api/v1/auth/reauth', {'password': other['password']})
    changed_password = secrets.token_urlsafe(24) + 'aA9!'
    second.call('POST', '/api/v1/auth/password/change', {
        'current_password': other['password'], 'password': changed_password})
    previous_session.call('GET', '/api/v1/users/me', expected=(401,))
    old_login = Client(args.base, args.ca)
    old_login.bootstrap_csrf()
    old_login.call('POST', '/api/v1/auth/login', {'email': other['email'], 'password': other['password']}, expected=(401,))
    other['password'] = changed_password
    second.login(other['email'], changed_password)
    print('PASS password change rejects previous password and revokes other sessions')
    # Probe uses second non-MFA user, unaffected by the MFA replay tests.
    save_state(Path(args.state), {'probe': other, 'mfa_account': account})
    second.call('POST', '/api/v1/auth/logout', {})
    second.call('GET', '/api/v1/users/me', expected=(401,))
    print('PASS logout authoritative across services')
    print('PASS full API acceptance; infrastructure/admin/browser/fault gates are separate')


def probe(args):
    state = json.loads(Path(args.state).read_text())['probe']
    client = Client(args.base, args.ca)
    client.login(state['email'], state['password'])
    _, result, _ = client.call('GET', '/api/v1/users/me')
    assert result['profile']['email'] == state['email']
    client.call('POST', '/api/v1/auth/logout', {})
    print('PASS business probe: real login/profile/logout')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=('full', 'probe'), default='full')
    parser.add_argument('--base', default='https://localhost:8448')
    parser.add_argument('--mailpit', default='http://localhost:28026')
    parser.add_argument('--state', required=True)
    parser.add_argument('--ca')
    args = parser.parse_args()
    (full if args.mode == 'full' else probe)(args)


if __name__ == '__main__':
    main()
