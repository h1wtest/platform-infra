#!/usr/bin/env python3
"""Real isolated identity/owner API security acceptance, no fabricated credentials.

Uses only disposable accounts from generic commerce state and records no raw tokens.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import uuid

from e2e import Client, oidc, save_state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', default='https://localhost:18448')
    parser.add_argument('--ca', required=True)
    parser.add_argument('--credentials', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    args = parser.parse_args()
    if args.base != 'https://localhost:18448':
        parser.error('only isolated generic local stand allowed')
    for path in (args.credentials, args.state):
        if path.is_symlink() or os.name != 'nt' and path.stat().st_mode & 0o077:
            parser.error('private regular credential/state file required')
    state = json.loads(args.state.read_text())
    credentials = json.loads(args.credentials.read_text())
    accounts = {account['email'].split('-')[1]: account for account in state['accounts']}
    customer_account, outsider_account = accounts['customer'], accounts['outsider']
    checks = []
    first = Client(args.base, args.ca)
    first.login(customer_account['email'], customer_account['password'])
    second = Client(args.base, args.ca)
    second.login(customer_account['email'], customer_account['password'])
    other = Client(args.base, args.ca)
    other.login(outsider_account['email'], outsider_account['password'])
    _, foreign_sessions, _ = other.call('GET', '/api/v1/auth/sessions')
    first.call('DELETE', '/api/v1/auth/sessions/' + foreign_sessions[0]['session_id'], expected=(403, 404))
    _, before, _ = first.call('GET', '/api/v1/auth/sessions')
    assert before and before[0]['is_current'] is True
    activity = {row['session_id']: row['last_active_at'] for row in before}
    assert all('expires_at' in row and 'browser' in row and 'os' in row for row in before)
    _, repeated, _ = first.call('GET', '/api/v1/auth/sessions')
    assert {row['session_id']: row['last_active_at'] for row in repeated} == activity
    first.call('POST', '/api/v1/auth/sessions/revoke-others', {})
    second.call('GET', '/api/v1/auth/me', expected=(401,))
    second.call('GET', '/api/v1/users/me', expected=(401,))
    second.call('GET', '/api/v1/orders', expected=(401,))
    second.call('GET', '/api/v1/subscriptions', expected=(401,))
    second.call('GET', '/api/v1/referrals', expected=(401,))
    first.call('GET', '/api/v1/auth/me')
    first.call('GET', '/api/v1/admin/roles', expected=(403,))
    first.call('GET', '/api/v1/admin/catalog', expected=(403,))
    first.call('GET', '/api/v1/admin/payments', expected=(403,))
    first.call('GET', '/api/v1/admin/referrals/payouts', expected=(403,))
    checks.append('sessions_current_metadata_foreign_denial_revoke_others_cross_owner')
    csrf = first.csrf
    first.csrf = 'deliberately-wrong-disposable-csrf'
    first.call('POST', '/api/v1/auth/sessions/revoke-others', {}, expected=(403,))
    first.call('POST', '/api/v1/orders', {'offer_id': state['offer_id'], 'kind': 'INITIAL',
                                       'network': 'USDTTRC20', 'idempotency_key': str(uuid.uuid4())}, expected=(403,))
    first.csrf = csrf
    checks.append('csrf_and_nonstaff_denials')
    oidc(args, first)
    # Reuse detection may revoke the originating session. Log in explicitly;
    # do not silently pass by treating a revoked session as authenticated.
    first.login(customer_account['email'], customer_account['password'])
    checks.append('real_oidc_signature_pkce_refresh_reuse')
    first.call('DELETE', '/api/v1/auth/sessions')
    first.call('GET', '/api/v1/auth/me', expected=(401,))
    first.call('GET', '/api/v1/subscriptions', expected=(401,))
    checks.append('revoke_all_includes_current')
    state['security_checks'] = checks
    save_state(args.state, state)
    print('PASS real security acceptance: ' + ', '.join(checks))


if __name__ == '__main__':
    main()
