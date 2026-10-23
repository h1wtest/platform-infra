#!/usr/bin/env python3
"""Exercise OWNER/ADMIN/SUPPORT against actual owner services, not UI role flags."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import uuid

from e2e import Client, save_state, totp


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', default='https://localhost:18448')
    parser.add_argument('--ca', required=True)
    parser.add_argument('--credentials', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    args = parser.parse_args()
    if args.base != 'https://localhost:18448':
        parser.error('isolated generic origin only')
    for path in (args.credentials, args.state):
        if path.is_symlink() or os.name != 'nt' and path.stat().st_mode & 0o077:
            parser.error('private regular credential/state input required')
    credentials, state = json.loads(args.credentials.read_text()), json.loads(args.state.read_text())
    owner = Client(args.base, args.ca)
    owner_secret = credentials.get('owner_totp_secret') or state.get('owner_totp_secret')
    owner.login(credentials['owner_email'], credentials['owner_password'], owner_secret)
    # TOTP steps are single-use: reauthentication must consume a later step,
    # rather than replaying the successful login factor.
    import time
    current_step = int(time.time()) // 30
    while int(time.time()) // 30 == current_step:
        time.sleep(0.2)
    owner.call('POST', '/api/v1/auth/reauth', {'password': credentials['owner_password'], 'code': totp(owner_secret)})
    _, authority, _ = owner.call('GET', '/api/v1/auth/me')
    owner_id = authority['user']['id']
    _, owner_roles, _ = owner.call('GET', '/api/v1/admin/users/' + owner_id + '/roles')
    owner.call('PUT', '/api/v1/admin/users/' + owner_id + '/roles', {
        'roles': [], 'expected_version': owner_roles['role_version'],
        'reason': 'Prove last owner cannot be removed'}, expected=(409,))
    checks = ['last_owner_protected']

    target = next(account for account in state['accounts'] if account['email'].startswith('generic-outsider-'))
    staff = Client(args.base, args.ca)
    staff.login(target['email'], target['password'])
    staff.call('POST', '/api/v1/auth/reauth', {'password': target['password']})
    _, setup, _ = staff.call('POST', '/api/v1/auth/mfa/setup', {})
    target['totp_secret'] = setup['secret']
    target['recovery_codes'] = setup['recovery_codes']
    save_state(args.state, state)
    staff.call('POST', '/api/v1/auth/mfa/enable', {'code': totp(setup['secret'])})
    staff.bootstrap_csrf()
    _, challenge, _ = staff.call('POST', '/api/v1/auth/login', {'email': target['email'], 'password': target['password']})
    staff.call('POST', '/api/v1/auth/mfa/verify-login', {
        'challenge_id': challenge['challenge_id'], 'code': setup['recovery_codes'][0]})
    staff.bootstrap_csrf()
    _, initial_roles, _ = owner.call('GET', '/api/v1/admin/users/' + target['user_id'] + '/roles')

    def assign(roles):
        _, current, _ = owner.call('GET', '/api/v1/admin/users/' + target['user_id'] + '/roles')
        return owner.call('PUT', '/api/v1/admin/users/' + target['user_id'] + '/roles', {
            'roles': roles, 'expected_version': current['role_version'],
            'reason': 'Disposable role matrix acceptance'})[1]

    try:
        assigned = assign(['support'])
        staff.call('GET', '/api/v1/admin/users')
        staff.call('GET', '/api/v1/admin/subscriptions')
        staff.call('GET', '/api/v1/admin/payments')
        staff.call('GET', '/api/v1/admin/payments/' + state['order_id'] + '/status')
        staff.call('GET', '/api/v1/admin/payments/' + state['order_id'], expected=(403,))
        staff.call('GET', '/api/v1/admin/roles', expected=(403,))
        staff.call('POST', '/api/v1/admin/catalog/products', {
            'key': 'forbidden-support', 'idempotency_key': str(uuid.uuid4())}, expected=(403,))
        staff.call('PUT', '/api/v1/admin/referrals/rate', {
            'rate_bps': 9999, 'expected_version': 1, 'idempotency_key': str(uuid.uuid4()),
            'reason': 'Must be denied'}, expected=(403,))
        owner.call('PUT', '/api/v1/admin/users/' + target['user_id'] + '/roles', {
            'roles': ['admin'], 'expected_version': initial_roles['role_version'],
            'reason': 'Stale concurrent edit must fail'}, expected=(409,))
        checks.append('support_limited_and_stale_role_edit_denied')
        assign(['admin'])
        staff.call('GET', '/api/v1/admin/catalog')
        staff.call('GET', '/api/v1/admin/payments')
        staff.call('GET', '/api/v1/admin/referrals/rate')
        staff.call('GET', '/api/v1/admin/roles', expected=(403,))
        staff.call('GET', '/api/v1/admin/oauth/clients', expected=(403,))
        checks.append('admin_business_access_without_owner_authority')
        assign([])
        staff.call('GET', '/api/v1/admin/catalog', expected=(403,))
        staff.call('GET', '/api/v1/admin/payments', expected=(403,))
        staff.call('GET', '/api/v1/admin/users', expected=(403,))
        checks.append('role_revoke_live_cross_owner')
    finally:
        assign(initial_roles['roles'])
    state['role_checks'] = checks
    save_state(args.state, state)
    print('PASS real role matrix: ' + ', '.join(checks))


if __name__ == '__main__':
    main()
