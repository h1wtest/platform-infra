#!/usr/bin/env python3
"""Real administrative authorization/ban/audit acceptance on disposable users."""
import argparse
import json
import os
from pathlib import Path
import time

from e2e import Client, eventually, save_state, totp


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base', default='https://localhost:8448')
    parser.add_argument('--state', required=True)
    parser.add_argument('--admin-state', required=True)
    parser.add_argument('--ca')
    parser.add_argument('--replay-quarantine', action='store_true')
    args = parser.parse_args()
    email, password = os.environ.get('ADMIN_EMAIL'), os.environ.get('ADMIN_PASSWORD')
    if not email or not password:
        raise SystemExit('ADMIN_EMAIL and ADMIN_PASSWORD must be passed privately in environment')
    user = json.loads(Path(args.state).read_text())['probe']
    admin = Client(args.base, args.ca)
    previous = Path(args.admin_state)
    admin_secret = json.loads(previous.read_text()).get('totp_secret') if previous.exists() else None
    try:
        from mfa_login import login_admin
        login_admin(admin, email, password, previous)
    except AssertionError as error:
        if not admin_secret and 'actual TOTP secret' in str(error):
            raise SystemExit('Administrator already has MFA. Supply its existing protected --admin-state file (or restore your own acceptance-state backup); acceptance will not reset MFA or read secrets from the database.') from error
        raise
    if not admin_secret:
        # Administrator password alone must not authorize privileged operations.
        admin.call('GET', '/api/v1/admin/users', expected=(403,))
        admin.call('POST', '/api/v1/auth/reauth', {'password': password})
        _, setup, _ = admin.call('POST', '/api/v1/auth/mfa/setup', {})
        admin_secret = setup['secret']
        admin.call('POST', '/api/v1/auth/mfa/enable', {'code': totp(admin_secret)})
        save_state(previous, {'email': email, 'password': password, 'totp_secret': admin_secret})
        admin.call('POST', '/api/v1/auth/logout', {})
        login_admin(admin, email, password, previous)
    _, users, _ = admin.call('GET', '/api/v1/admin/users?query=' + user['email'])
    rows = users if isinstance(users, list) else users['users']
    assert any(str(row.get('id', row.get('user_id'))) == user['user_id'] for row in rows), 'Admin search missing actual user'
    victim = Client(args.base, args.ca)
    victim.login(user['email'], user['password'])
    admin.call('POST', f'/api/v1/admin/users/{user["user_id"]}/ban', {'reason': 'Disposable acceptance ban'})
    victim.call('GET', '/api/v1/auth/me', expected=(401, 403))
    victim.call('GET', '/api/v1/users/me', expected=(401, 403))
    victim.bootstrap_csrf()
    victim.call('POST', '/api/v1/auth/login', {'email': user['email'], 'password': user['password']}, expected=(401, 403))
    admin.call('POST', f'/api/v1/admin/users/{user["user_id"]}/unban', {})
    victim.login(user['email'], user['password'])
    victim.call('GET', '/api/v1/users/me')

    def audit_observed():
        _, response, _ = admin.call('GET', '/api/v1/admin/audit')
        records = response if isinstance(response, list) else response.get('events', response.get('audit', response.get('items', [])))
        event_types = {row.get('event_type') for row in records if str(row.get('aggregate_id', row.get('user_id'))) == user['user_id']}
        return 'identity.user_banned' in event_types and 'identity.user_unbanned' in event_types
    eventually('real Kafka audit ban and unban projection', audit_observed)
    admin.call('GET', '/api/v1/admin/deliveries')
    if args.replay_quarantine:
        from events import create_event
        _, quarantined, _ = admin.call('GET', '/api/v1/admin/quarantine?owner=notification')
        records = quarantined if isinstance(quarantined, list) else quarantined['items']
        from fixtures import owned_record
        record = owned_record(records)
        path = f'/api/v1/admin/quarantine/{record["id"]}/replay?owner=notification'
        admin.call('POST', path, {}, expected=(409,))
        event_id, encoded = create_event(user['user_id'])
        admin.call('POST', path, {'corrected_event': json.loads(encoded)})
        admin.call('POST', path, {'corrected_event': json.loads(encoded)}, expected=(404,))
        # Metadata intentionally omits event_id; validate immutable replay status instead.
        _, after_replay, _ = admin.call('GET', '/api/v1/admin/quarantine?owner=notification')
        after_rows = after_replay if isinstance(after_replay, list) else after_replay['items']
        assert not any(row['id'] == record['id'] and not row.get('replayed_at') for row in after_rows)
        print('PASS invalid poison replay rejected/corrected authorized replay once')
    victim.call('POST', '/api/v1/auth/logout', {})
    admin.call('POST', '/api/v1/auth/logout', {})
    print('PASS admin requires MFA/search/ban enforced across services/unban/audit/delivery authorization')


if __name__ == '__main__':
    main()
