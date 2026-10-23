#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real isolated HTTPS owner APIs -> Kafka -> notification worker -> Mailpit.

Private inputs/evidence only; no bot credentials, mocked owners, SQL writes or
provider-success substitution. Exit 2 means reachable checks passed but an
external integration/Telegram gate remains OPEN, never full acceptance PASS.
"""
from __future__ import annotations

import argparse
import base64
from copy import deepcopy
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from e2e import Client, eventually, find_mail, save_state, totp


SAFE_FIELDS = {'id', 'user_id', 'channel', 'status', 'attempts', 'next_attempt_at',
               'last_error', 'message_id', 'created_at', 'delivered_at', 'ambiguous'}


def private_json(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('Private input must be a regular non-symlink file')
    if os.name != 'nt' and path.stat().st_mode & 0o077:
        raise ValueError('Private input requires mode0600')
    return json.loads(path.read_text(encoding='utf-8'))


def uuid7():
    # Python 3.11+ compatible RFC9562 UUIDv7: milliseconds, version, variant,
    # independent random payload. ExternalEvent rejects UUIDv4 event IDs.
    value = ((time.time_ns() // 1_000_000) << 80) | (7 << 76)
    value |= secrets.randbits(12) << 64 | 2 << 62 | secrets.randbits(62)
    return str(uuid.UUID(int=value))


def header(headers, name):
    return next((value for key, value in headers.items() if key.lower() == name.lower()), '')


def history(client):
    result, cursor, seen = [], '', set()
    while True:
        query = '?limit=100' + ('&cursor=' + urllib.parse.quote(cursor, safe='') if cursor else '')
        _, rows, headers = client.call('GET', '/api/v1/notifications' + query)
        assert isinstance(rows, list), 'History must be an array, not invented empty results'
        for row in rows:
            assert set(row) <= SAFE_FIELDS and {'id', 'user_id', 'status', 'channel'} <= set(row), 'Unsafe history metadata'
            assert row['id'] not in seen, 'History keyset repeated a delivery'
            seen.add(row['id'])
            result.append(row)
        cursor = header(headers, 'X-Next-Cursor')
        if not cursor:
            return result
        assert len(result) < 10000, 'Unbounded disposable history'


def mail_matches(args, email, subject):
    with urllib.request.urlopen(args.mailpit.rstrip('/') + '/api/v1/messages', timeout=10) as response:
        listing = json.load(response)
    found = []
    for entry in listing.get('messages', []):
        if entry.get('Subject') != subject or not any(
                recipient.get('Address', '').lower() == email.lower() for recipient in entry.get('To', [])):
            continue
        with urllib.request.urlopen(args.mailpit.rstrip('/') + '/api/v1/message/' + entry['ID'], timeout=10) as response:
            found.append(json.load(response))
    return found


def delivered_mail(args, email, subject, text):
    def fetch():
        matches = mail_matches(args, email, subject)
        if not matches:
            return None
        assert len(matches) == 1, 'Duplicate local SMTP delivery on a non-ambiguous path'
        message = matches[0]
        assert str(message.get('Text', '')).replace('\r\n', '\n').rstrip('\n') == text.rstrip('\n'), 'Rendered email content differs'
        assert not message.get('Bcc'), 'Rendered variables injected a Bcc recipient'
        with urllib.request.urlopen(args.mailpit.rstrip('/') + '/api/v1/message/' + message['ID'] + '/raw', timeout=10) as response:
            parsed = BytesParser(policy=policy.default).parsebytes(response.read())
        assert parsed.get_all('Bcc') is None and parsed.get_all('Cc') is None, 'SMTP header injection'
        assert len(parsed.get_all('Subject', [])) == 1 and str(parsed['Subject']) == subject
        return {'mailpit_id': message['ID'], 'subject': subject}
    return eventually('actual SMTP message and safe MIME headers', fetch, timeout=args.timeout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', default='https://localhost:18448')
    parser.add_argument('--mailpit', default='http://localhost:38026')
    parser.add_argument('--ca', required=True)
    parser.add_argument('--credentials', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True, help='New private output; not the commerce/security/advanced input')
    parser.add_argument('--source-state', type=Path, help='Private advanced state containing a disposable active subscription')
    parser.add_argument('--account-user-id', help='Explicit disposable source account; defaults to integration_account_user_id')
    parser.add_argument('--subscription-id', help='Explicit disposable subscription; defaults to integration_subscription_id')
    parser.add_argument('--integration-config', type=Path, help='Private JSON registry exactly matching profile EXTERNAL_EVENT_INTEGRATIONS')
    parser.add_argument('--integration-id', default='acceptance-notifications')
    parser.add_argument('--restricted-integration-id', default='acceptance-notifications-readiness',
                        help='Second task-only sender allowing readiness_changed but not trading_alert')
    parser.add_argument('--ingress-base', help='Explicit isolated loopback forward to private gateway9443: https://localhost:18449')
    parser.add_argument('--timeout', type=int, default=120)
    args = parser.parse_args()
    if args.base != 'https://localhost:18448' or args.mailpit != 'http://localhost:38026':
        parser.error('Only the isolated generic origin18448 and Mailpit38026 are allowed')
    if args.ingress_base and args.ingress_base != 'https://localhost:18449':
        parser.error('Private ingress must use isolated loopback18449 forwarding to gateway9443')
    if args.state.exists() or args.state.is_symlink():
        parser.error('--state must be a new private evidence path')
    if args.timeout < 10 or args.timeout > 600:
        parser.error('--timeout must be10..600seconds')
    credentials = private_json(args.credentials)
    source = private_json(args.source_state) if args.source_state else {}
    registry = private_json(args.integration_config) if args.integration_config else {}
    state = {'checks': [], 'gates': {'telegram_real_provider': 'OPEN', 'external_ingress_delivery': 'OPEN'},
             'accounts': [], 'templates_before': {}, 'template_restoration': {}, 'deliveries': [],
             'limits': ['Local Mailpit SMTP evidence is not Telegram provider acceptance',
                        'No NOWPayments sandbox evidence is asserted by this script']}
    save_state(args.state, state)

    def checked(label):
        state['checks'].append(label)
        save_state(args.state, state)

    owner_secret = credentials.get('owner_totp_secret') or source.get('owner_totp_secret')
    if not owner_secret:
        raise ValueError('Fresh owner MFA prerequisite: supply owner_totp_secret privately; script never changes owner MFA')
    owner = Client(args.base, args.ca)
    owner.login(credentials['owner_email'], credentials['owner_password'], owner_secret)
    _, authority, _ = owner.call('GET', '/api/v1/auth/me')
    assert 'owner' in authority['user']['roles'] and authority['user']['mfa_verified'] is True

    customer = Client(args.base, args.ca)
    customer.bootstrap_csrf()
    account = {'email': 'generic-notifications-' + uuid.uuid4().hex + '@example.invalid',
               'password': secrets.token_urlsafe(24) + 'aA9!'}
    _, registered, _ = customer.call('POST', '/api/v1/auth/register', account, expected=(201,))
    account['user_id'] = registered['user_id']
    state['accounts'].append(account)
    save_state(args.state, state)
    code = find_mail(args.mailpit, account['email'], 'verification', timeout=args.timeout)
    customer.call('POST', '/api/v1/auth/verify-email', {'user_id': account['user_id'], 'code': code})
    initial_login_started = time.time()
    customer.login(account['email'], account['password'])
    eventually('fresh profile created through Kafka', lambda: customer.call('GET', '/api/v1/users/me')[1].get('profile'), timeout=args.timeout)
    checked('fresh_registration_verification_email_kafka_profile')

    _, fresh, _ = customer.call('GET', '/api/v1/users/me')
    assert fresh['capabilities']['telegram'] is False, 'This no-bot acceptance requires Telegram capability unavailable'
    _, before_link, _ = customer.call('GET', '/api/v1/users/me/telegram')
    assert not before_link['linked'] and not before_link['link_pending'] and not before_link['candidate_ready']
    _, unavailable, _ = customer.call('POST', '/api/v1/users/me/telegram/link', {}, expected=(503,))
    assert unavailable['code'] == 'telegram_unavailable' and 'link_token' not in unavailable and 'bot_url' not in unavailable
    for preference in ('telegram_login_alerts', 'telegram_security_alerts', 'telegram_subscription', 'telegram_trading'):
        _, denied, _ = customer.call('PATCH', '/api/v1/users/me/notifications', {preference: True}, expected=(409,))
        assert denied['code'] == 'telegram_link_required'
    _, after_link, _ = customer.call('GET', '/api/v1/users/me/telegram')
    assert after_link == before_link, 'Unavailable channel allocated a link or altered binding'
    checked('fresh_telegram_unavailable_no_fake_link_or_preference_enable')

    customer.call('PATCH', '/api/v1/users/me/notifications', {'email_login_alerts': False, 'email_security_alerts': False})
    customer.call('POST', '/api/v1/auth/password/forgot', {'email': account['email']}, expected=(200, 202))
    reset_token = find_mail(args.mailpit, account['email'], 'reset', timeout=args.timeout)
    assert reset_token and all(reset_token not in json.dumps(row) for row in history(customer)), 'Transactional secret leaked in history'
    checked('mandatory_password_reset_email_bypasses_optional_security_preferences_safe_history')

    _, all_templates, _ = owner.call('GET', '/api/v1/admin/templates')
    templates = {item['event_type']: item for item in all_templates['items']}
    for item in templates.values():
        assert set(item['locales']) == {'en', 'ru'}
        assert all(item['locales'][locale]['subject'] and item['locales'][locale]['body'] for locale in ('en', 'ru'))

    def settled_login(client, started, minimum=1):
        def fetch():
            rows = history(client)
            recent = [row for row in rows if datetime.fromisoformat(row['created_at'].replace('Z', '+00:00')).timestamp() >= started]
            return recent if len(recent) >= minimum and all(row['status'] in ('sent', 'failed') for row in recent) else None
        return eventually('actual login event consumed and worker settled', fetch, timeout=args.timeout)
    touched = {}
    external_client = None
    external_original = None
    event_type = 'identity.user_logged_in'
    marker = 'Notifications-' + uuid.uuid4().hex[:12]

    def publish(kind, locales, expected=None):
        current = touched.get(kind, templates[kind])
        _, result, _ = owner.call('PUT', '/api/v1/admin/templates/' + kind,
                                 {'expected_version': current['version'] if expected is None else expected, 'locales': locales})
        touched[kind] = result
        assert result['version'] == current['version'] + 1 and result['locales'] == locales
        save_state(args.state, state)
        return result

    def remember(kind):
        state['templates_before'][kind] = deepcopy(templates[kind])
        save_state(args.state, state)

    def new_job(client, old_ids):
        def fetch():
            rows = [row for row in history(client) if row['id'] not in old_ids and row['channel'] == 'email']
            assert len(rows) <= 1, 'Unexpected concurrent job for disposable account'
            return rows[0] if rows else None
        return eventually('real event consumed into own email job', fetch, timeout=args.timeout)

    def terminal_job(client, job_id, status, reason=None):
        def fetch():
            row = next((row for row in history(client) if row['id'] == job_id), None)
            if not row or row['status'] != status:
                return None
            if reason is not None:
                assert row['last_error'] == reason, 'Unexpected delivery denial reason'
            if status == 'sent':
                assert row['delivered_at'] and row['attempts'] >= 1
            state['deliveries'].append(row)
            save_state(args.state, state)
            return row
        return eventually('delivery worker terminal ' + status, fetch, timeout=args.timeout)

    def login_event(device):
        client = Client(args.base, args.ca)
        client.bootstrap_csrf()
        _, result, _ = client.call('POST', '/api/v1/auth/login', {
            'email': account['email'], 'password': account['password'], 'device_name': device})
        assert result['status'] == 'authenticated'
        return client

    try:
        remember(event_type)
        original = templates[event_type]
        customer.call('PUT', '/api/v1/admin/templates/' + event_type,
                      {'expected_version': original['version'], 'locales': original['locales']}, expected=(403,))
        invalids = [
            {'en': {'subject': 'Missing RU', 'body': '{{device_name}}'}},
            {'en': {'subject': 'Unknown', 'body': '{{reset_url}}'}, 'ru': {'subject': 'Ошибка', 'body': '{{device_name}}'}},
            {'en': {'subject': 'Unsafe', 'body': '<a href="javascript:alert(1)">click</a>'}, 'ru': {'subject': 'Ошибка', 'body': 'Текст'}},
            {'en': {'subject': 'Unsafe', 'body': 'data:text/html,unsafe'}, 'ru': {'subject': 'Ошибка', 'body': 'Текст'}},
            {'en': {'subject': 'CRLF\r\nBcc: nobody@example.invalid', 'body': 'Text'}, 'ru': {'subject': 'Ошибка', 'body': 'Текст'}},
        ]
        for locales in invalids:
            owner.call('PUT', '/api/v1/admin/templates/' + event_type,
                       {'expected_version': original['version'], 'locales': locales}, expected=(400,))
        _, unchanged, _ = owner.call('GET', '/api/v1/admin/templates')
        assert next(item for item in unchanged['items'] if item['event_type'] == event_type) == original, 'Invalid template changed a revision'
        checked('template_en_ru_required_unknown_variables_unsafe_urls_crlf_and_user_denial')
        locales = {'en': {'subject': marker + ' EN {{device_name}}', 'body': 'EN device={{device_name}}'},
                   'ru': {'subject': marker + ' RU {{device_name}}', 'body': 'RU устройство={{device_name}}'}}
        publish(event_type, locales)
        owner.call('PUT', '/api/v1/admin/templates/' + event_type,
                   {'expected_version': original['version'], 'locales': locales}, expected=(409,))
        checked('atomic_template_publish_expected_version_conflict')

        # Drain initial account login before measuring one actual event/job.
        settled_login(customer, initial_login_started, minimum=2)
        # A second profile fetch below is authoritative, not a cached projection.
        customer.call('PATCH', '/api/v1/users/me/notifications', {'email_login_alerts': True})
        for locale, device, escaped, body in (
                ('en', '<b>A&B</b>\r\nBcc: nobody', '&lt;b&gt;A&amp;B&lt;/b&gt; Bcc: nobody', 'EN device='),
                ('ru', '<i>Тест&RU</i>', '&lt;i&gt;Тест&amp;RU&lt;/i&gt;', 'RU устройство=')):
            customer.call('PATCH', '/api/v1/users/me', {'website_locale': 'ru' if locale == 'en' else 'en', 'notification_locale': locale})
            _, profile, _ = customer.call('GET', '/api/v1/users/me')
            assert profile['profile']['notification_locale'] == locale and profile['profile']['website_locale'] != locale
            old = {row['id'] for row in history(customer)}
            login_event(device)
            job = new_job(customer, old)
            terminal_job(customer, job['id'], 'sent')
            evidence = delivered_mail(args, account['email'], marker + ' ' + locale.upper() + ' ' + escaped, body + escaped)
            state.setdefault('mail_evidence', []).append(evidence)
        checked('independent_notification_locale_en_ru_html_escape_and_crlf_header_safety_actual_smtp')

        customer.call('PATCH', '/api/v1/users/me/notifications', {'email_login_alerts': False})
        _, disabled, _ = customer.call('GET', '/api/v1/users/me')
        assert disabled['notification_settings']['email_login_alerts'] is False
        old = {row['id'] for row in history(customer)}
        login_event('policy-' + marker)
        job = new_job(customer, old)
        terminal_job(customer, job['id'], 'failed', 'recipient_ineligible')
        old_subject = marker + ' RU policy-' + marker
        assert not mail_matches(args, account['email'], old_subject), 'Disabled policy delivered email'
        # Same immutable job is replayed after a new template revision, locale and
        # live recipient preference. A stale denial snapshot must not block it;
        # a mutable template/locale snapshot must not rewrite it.
        replacement = deepcopy(locales)
        replacement['ru'] = {'subject': marker + ' NEW {{device_name}}', 'body': 'NEW {{device_name}}'}
        publish(event_type, replacement)
        customer.call('PATCH', '/api/v1/users/me', {'notification_locale': 'en'})
        customer.call('PATCH', '/api/v1/users/me/notifications', {'email_login_alerts': True})
        owner.call('POST', '/api/v1/admin/deliveries/' + job['id'] + '/replay', {'reason': 'Disposable notification current-policy acceptance'})
        terminal_job(customer, job['id'], 'sent')
        delivered_mail(args, account['email'], old_subject, 'RU устройство=policy-' + marker)
        owner.call('POST', '/api/v1/admin/deliveries/' + job['id'] + '/replay', {'reason': 'Must reject already sent'}, expected=(409,))
        checked('current_recipient_preference_at_attempt_replay_and_immutable_template_locale_snapshot')

        # The capability test never pretends SMTP is a trading channel.
        customer.call('POST', '/internal/v1/external-events', {}, expected=(404,))
        checked('public_gateway_denies_private_external_ingress')
        if args.source_state and args.integration_config and args.ingress_base:
            user_id = args.account_user_id or source.get('integration_account_user_id')
            subscription_id = args.subscription_id or source.get('integration_subscription_id')
            if not user_id or not subscription_id:
                raise ValueError('Explicit disposable integration account/subscription prerequisite missing')
            source_account = next((item for item in source.get('accounts', []) if item.get('user_id') == user_id), None)
            if not source_account or not source_account['email'].startswith('generic-') or not source_account['email'].endswith('@example.invalid'):
                raise ValueError('Selected source account must be task-owned disposable generic account')
            external_client = Client(args.base, args.ca)
            source_login_started = time.time()
            external_client.login(source_account['email'], source_account['password'], source_account.get('totp_secret'))
            _, subscription, _ = external_client.call('GET', '/api/v1/subscriptions/' + subscription_id)
            assert subscription['user_id'] == user_id and subscription['state'] == 'ACTIVE'
            product_id = subscription['product_id']
            _, entitlement, _ = external_client.call('GET', '/api/v1/subscriptions/' + subscription_id + '/entitlement')
            assert entitlement['allowed'] is True, 'Active disposable entitlement required for trading ingress'
            integration = registry.get(args.integration_id)
            if not integration:
                raise ValueError('Requested integration absent from private registry')
            key = base64.b64decode(integration['secret'], validate=True)
            if len(key) != 32 or product_id not in integration['product_ids'] or not {'readiness_changed', 'trading_alert'} <= set(integration['event_types']):
                raise ValueError('Integration requires base6432-byte key, selected product and both event kinds')
            restricted = registry.get(args.restricted_integration_id)
            if not restricted or restricted.get('event_types') != ['readiness_changed'] or product_id not in restricted.get('product_ids', []):
                raise ValueError('Second task-only integration must allow readiness_changed only for selected product')
            restricted_key = base64.b64decode(restricted['secret'], validate=True)
            if len(restricted_key) != 32 or restricted_key == key:
                raise ValueError('Integrations require distinct32-byte signing keys')
            _, external_original, _ = external_client.call('GET', '/api/v1/users/me')
            state['integration_account_user_id'] = user_id
            state['integration_subscription_id'] = subscription_id
            state['integration_product_id'] = product_id
            save_state(args.state, state)

            def event(**changes):
                return {'event_id': uuid7(), 'user_id': user_id, 'subscription_id': subscription_id,
                        'product_id': product_id, 'event_kind': 'readiness_changed', 'status': 'ready',
                        'message': marker, 'occurred_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'), **changes}

            def ingress(payload, *, expected, sender=None, timestamp=None, nonce=None, bad_signature=False, code=None):
                raw = json.dumps(payload, separators=(',', ':'), ensure_ascii=False).encode()
                stamp, random_nonce = str(int(time.time()) if timestamp is None else timestamp), nonce or secrets.token_urlsafe(24)
                signing_key = restricted_key if sender == args.restricted_integration_id else key
                signature = hmac.new(signing_key, stamp.encode() + b'.' + random_nonce.encode() + b'.' + raw, hashlib.sha256).hexdigest()
                request = urllib.request.Request(args.ingress_base + '/internal/v1/external-events', method='POST', data=raw,
                    headers={'Content-Type': 'application/json', 'X-Integration-ID': sender or args.integration_id,
                             'X-Event-Timestamp': stamp, 'X-Event-Nonce': random_nonce,
                             'X-Event-Signature': '0' * 64 if bad_signature else signature})
                try:
                    response = external_client.opener.open(request, timeout=15)
                except urllib.error.HTTPError as error:
                    response = error
                with response:
                    result = json.load(response)
                    actual_status = response.code
                if actual_status not in expected:
                    raise AssertionError('External ingress unexpected status=' + str(actual_status) + ' code=' + str(result.get('code', 'none')))
                if code:
                    assert result.get('code') == code, 'Unexpected external ingress denial code'
                if actual_status == 202:
                    assert result == {'event_id': payload['event_id'], 'status': 'accepted'}
                    state.setdefault('external_accepted_event_ids', []).append(payload['event_id'])
                    save_state(args.state, state)
                return actual_status, result

            status, result = ingress(event(), expected=(401, 403), bad_signature=True)
            if status == 403 and result.get('code') == 'sender_denied':
                state['external_prerequisite'] = 'Task integration registry is not loaded into live profile process'
            else:
                assert status == 401 and result.get('code') == 'invalid_signature'
                ingress(event(), expected=(403,), sender='unknown-' + marker, code='sender_denied')
                for stamp in (int(time.time()) - 180, int(time.time()) + 180):
                    ingress(event(), expected=(401,), timestamp=stamp, code='invalid_signature')
                ingress(event(event_kind='trading_alert'), expected=(403,), sender=args.restricted_integration_id, code='scope_denied')
                ingress(event(product_id=str(uuid.uuid4())), expected=(403,), code='scope_denied')
                ingress(event(user_id=account['user_id']), expected=(403,), code='scope_denied')
                ingress(event(user_id=str(uuid.uuid4())), expected=(403,), code='recipient_denied')
                ingress(event(subscription_id=str(uuid.uuid4())), expected=(403,), code='scope_denied')
                ingress(event(event_kind='unsupported'), expected=(400,), code='invalid_event')
                checked('external_hmac_invalid_signature_timestamp_sender_product_user_subscription_scope')

                remember('external.readiness_changed')
                readiness_locales = {'en': {'subject': marker + ' readiness {{status}}', 'body': 'EN {{message}} {{subscription_id}}'},
                                     'ru': {'subject': marker + ' готовность {{status}}', 'body': 'RU {{message}} {{subscription_id}}'}}
                publish('external.readiness_changed', readiness_locales)
                external_client.call('PATCH', '/api/v1/users/me', {'notification_locale': 'en'})
                external_client.call('PATCH', '/api/v1/users/me/notifications', {'email_subscription': True})
                settled_login(external_client, source_login_started)
                old = {row['id'] for row in history(external_client)}
                accepted = event(message='<b>A&B</b>\r\nBcc: nobody')
                nonce = secrets.token_urlsafe(24)
                ingress(accepted, expected=(202,), nonce=nonce)
                ingress(accepted, expected=(202,), nonce=nonce)  # Exact event retry is deliberately idempotent202.
                ingress(event(), expected=(401,), nonce=nonce, code='nonce_replayed')
                ingress({**accepted, 'message': 'conflicting immutable event'}, expected=(409,), code='event_conflict')
                job = new_job(external_client, old)
                terminal_job(external_client, job['id'], 'sent')
                delivered_mail(args, source_account['email'], marker + ' readiness ready',
                               'EN &lt;b&gt;A&amp;B&lt;/b&gt; Bcc: nobody ' + subscription_id)
                checked('external_http_hmac_ingress_kafka_readiness_email_delivery_event_dedup_nonce_replay_conflict')

                # The optional email policy must suppress readiness too. Failed
                # job proves consumer/worker ran, stronger than waiting for no mail.
                external_client.call('PATCH', '/api/v1/users/me/notifications', {'email_subscription': False})
                old = {row['id'] for row in history(external_client)}
                ingress(event(status='disabled'), expected=(202,))
                denied_job = new_job(external_client, old)
                terminal_job(external_client, denied_job['id'], 'failed', 'recipient_ineligible')
                assert not mail_matches(args, source_account['email'], marker + ' readiness disabled')
                checked('external_readiness_current_subscription_email_preference_denial')
                # A real accepted trading event has no email plan. Without a
                # linked real private Telegram chat there can be no send proof.
                ingress(event(event_kind='trading_alert', status='signal'), expected=(202,))
                state['gates']['external_ingress_delivery'] = 'LOCAL_READINESS_EMAIL_PROVEN'
                state['trading_delivery'] = 'OPEN: accepted ingress only; real Telegram binding/send prerequisite missing'
        else:
            state['external_prerequisite'] = 'Requires --source-state with disposable ACTIVE subscription, --integration-config matching live profile registry, and --ingress-base https://localhost:18449 forwarding private gateway9443'
            if args.ingress_base:
                # An unknown sender must fail closed on the real private ingress;
                # public404 alone is not evidence of profile ingress authority.
                request = urllib.request.Request(args.ingress_base + '/internal/v1/external-events', data=b'{}', method='POST',
                                                 headers={'Content-Type': 'application/json', 'X-Integration-ID': 'unknown-' + marker})
                try:
                    response = customer.opener.open(request, timeout=15)
                except urllib.error.HTTPError as error:
                    response = error
                with response:
                    assert response.code == 403 and json.load(response).get('code') == 'sender_denied'
                checked('unconfigured_external_sender_fail_closed_only')

        # Real keyset traversal with interleaved insertion catches accidental
        # OFFSET pagination, missing gateway header forwarding and ownership leaks.
        all_rows = history(customer)
        assert len(all_rows) >= 3 and all(row['user_id'] == account['user_id'] for row in all_rows)
        _, first, headers = customer.call('GET', '/api/v1/notifications?limit=1')
        cursor = header(headers, 'X-Next-Cursor')
        assert len(first) == 1 and cursor, 'Gateway lost notification keyset header'
        snapshot_ids = {row['id'] for row in all_rows if (row['created_at'], row['id']) <= (first[0]['created_at'], first[0]['id'])}
        old = {row['id'] for row in all_rows}
        login_event('pagination-' + marker)
        new_job(customer, old)
        paged_ids = {first[0]['id']}
        while cursor:
            _, page, headers = customer.call('GET', '/api/v1/notifications?limit=1&cursor=' + urllib.parse.quote(cursor, safe=''))
            assert len(page) == 1 and page[0]['id'] not in paged_ids
            assert set(page[0]) <= SAFE_FIELDS and page[0]['user_id'] == account['user_id']
            paged_ids.add(page[0]['id'])
            cursor = header(headers, 'X-Next-Cursor')
        assert paged_ids == snapshot_ids, 'Concurrent insert skipped/repeated historical delivery'
        for query in ('?limit=0', '?limit=101', '?cursor=invalid', '?cursor=', '?cursor=a&cursor=b'):
            customer.call('GET', '/api/v1/notifications' + query, expected=(400,))
        _, staff_rows, staff_headers = owner.call('GET', '/api/v1/admin/deliveries?limit=1')
        assert len(staff_rows) == 1 and set(staff_rows[0]) <= SAFE_FIELDS and header(staff_headers, 'X-Next-Cursor')
        customer.call('GET', '/api/v1/admin/deliveries', expected=(403,))
        checked('own_history_safe_metadata_keyset_header_insertion_stability_cursor_validation_admin_forwarding')
    finally:
        # Restore changed global templates and borrowed disposable preferences,
        # retaining immutable revisions and recording restoration failures.
        restoration_errors = []
        for kind in reversed(list(touched)):
            try:
                result = publish(kind, state['templates_before'][kind]['locales'])
                state['template_restoration'][kind] = {'restored': True, 'version': result['version']}
            except Exception:
                state['template_restoration'][kind] = {'restored': False}
                restoration_errors.append('template restoration')
        if external_client is not None and external_original is not None:
            try:
                external_client.call('PATCH', '/api/v1/users/me', {'notification_locale': external_original['profile']['notification_locale']})
                settings = {name: external_original['notification_settings'][name] for name in (
                    'email_login_alerts', 'email_security_alerts', 'telegram_login_alerts', 'telegram_security_alerts',
                    'email_subscription', 'telegram_subscription', 'telegram_trading')}
                external_client.call('PATCH', '/api/v1/users/me/notifications', settings)
                state['source_preferences_restored'] = True
            except Exception:
                state['source_preferences_restored'] = False
                restoration_errors.append('source preference restoration')
        save_state(args.state, state)
        if restoration_errors:
            raise AssertionError('Private evidence records failed ' + ', '.join(restoration_errors))
    print('REACHABLE CHECKS PASSED: ' + ', '.join(state['checks']))
    print('OPEN: real Telegram bot credentials/public HTTPS webhook/private chat link/unlink/send; no Telegram success asserted.')
    if state['gates']['external_ingress_delivery'] != 'LOCAL_READINESS_EMAIL_PROVEN':
        print('OPEN: external integration registry and disposable ACTIVE subscription must be configured; see private evidence prerequisites.')
    else:
        print('LOCAL PROVEN: real signed HTTP ingress -> Kafka -> readiness SMTP/Mailpit; trading delivery remains Telegram-only and OPEN.')
    return 2


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (AssertionError, OSError, ValueError, KeyError, TypeError) as error:
        # Do not echo raw provider errors, paths/queries, bodies, credentials or
        # assertion values. Private evidence retains completed named checks.
        print('FAIL notification acceptance: ' + type(error).__name__ + '; inspect private evidence and owner diagnostics without exposing secrets.')
        raise SystemExit(1) from None
