#!/usr/bin/env python3
"""Real HTTPS/Kafka advanced lifecycle acceptance, explicit local provider fixture only.

Only newly created users/products/orders are mutated. Explicit test-clock consent
changes timestamps on those disposable records, never application decisions or money.
Boundary scenarios require --allow-disposable-clock plus an isolated kubeconfig.
Private evidence is create-only; credentials are input-only and are never printed.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import subprocess
import time
import urllib.parse
import urllib.request
import uuid

from e2e import Client, eventually, find_mail, save_state, totp


SECOND = timedelta(seconds=1)
DAY = timedelta(days=1)


def command(**fields):
    return {'idempotency_key': str(uuid.uuid4()), **fields}


def instant(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def micros(value):
    assert isinstance(value, str) and re.fullmatch(r'(0|[1-9][0-9]*)\.[0-9]{6}', value)
    return int(Decimal(value) * 1_000_000)


def money(value):
    return f'{value // 1_000_000}.{value % 1_000_000:06d}'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', default='https://localhost:18448')
    parser.add_argument('--mailpit', default='http://localhost:38026')
    parser.add_argument('--fixture', default='https://localhost:19444')
    parser.add_argument('--ca', required=True)
    parser.add_argument('--fixture-ca', required=True)
    parser.add_argument('--credentials', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--allow-disposable-clock', action='store_true',
                        help='Explicitly permit timestamp-only SQL for this run\'s new records')
    parser.add_argument('--kubeconfig', type=Path,
                        help='Required only with --allow-disposable-clock; isolated local cluster')
    args = parser.parse_args()
    if args.base != 'https://localhost:18448' or args.fixture != 'https://localhost:19444':
        parser.error('only isolated generic HTTPS origins 18448/19444 are allowed')
    if args.mailpit not in ('http://localhost:38026', 'http://127.0.0.1:38026'):
        parser.error('only isolated generic Mailpit 38026 is allowed')
    if not args.credentials.is_file() or args.credentials.is_symlink():
        parser.error('private regular credentials input required')
    if os.name != 'nt' and args.credentials.stat().st_mode & 0o077:
        parser.error('credentials must be owner-only')
    if args.state.exists() or args.state.is_symlink() or args.state.resolve() == args.credentials.resolve():
        parser.error('choose a NEW private advanced state path; existing commerce state is input-only')
    if not args.allow_disposable_clock or not args.kubeconfig:
        parser.error('full boundary acceptance requires --allow-disposable-clock and explicit --kubeconfig')
    credentials = json.loads(args.credentials.read_text(encoding='utf-8'))
    for field in ('owner_email', 'owner_password', 'owner_totp_secret', 'fixture_control_token'):
        if not isinstance(credentials.get(field), str) or not credentials[field]:
            parser.error('credentials require owner email/password/existing MFA and fixture control token')
    state = {'fixture_only': True, 'nowpayments_acceptance': 'OPEN', 'checks': [],
             'accounts': [], 'orders': [], 'clock_operations': [],
             'owner_totp_secret': credentials['owner_totp_secret'],
             'clock_mode': 'disposable_timestamp_shift'}
    save_state(args.state, state)

    def passed(label, **evidence):
        state['checks'].append(label)
        state.setdefault('evidence', {})[label] = evidence
        save_state(args.state, state)

    owner = Client(args.base, args.ca)
    owner.login(credentials['owner_email'], credentials['owner_password'], credentials['owner_totp_secret'])
    _, authority, _ = owner.call('GET', '/api/v1/auth/me')
    assert 'owner' in authority['user']['roles'] and authority['user']['mfa_verified']
    # Existing MFA only: never enroll/reset an existing commerce owner.
    assert len(totp(credentials['owner_totp_secret'])) == 6

    def register(label):
        account = {'label': label, 'email': 'generic-advanced-' + label + '-' + uuid.uuid4().hex + '@example.invalid',
                   'password': secrets.token_urlsafe(24) + 'aA9!', 'locale': 'en'}
        client = Client(args.base, args.ca)
        client.bootstrap_csrf()
        _, result, _ = client.call('POST', '/api/v1/auth/register',
                                   {key: account[key] for key in ('email', 'password', 'locale')}, expected=(201,))
        account['user_id'] = result['user_id']
        state['accounts'].append(account)
        save_state(args.state, state)
        code = find_mail(args.mailpit, account['email'], 'verification')
        client.call('POST', '/api/v1/auth/verify-email', {'user_id': account['user_id'], 'code': code})
        client.login(account['email'], account['password'])
        eventually('disposable profile projection', lambda: client.call('GET', '/api/v1/users/me')[1].get('profile'))
        return client, account

    _, product, _ = owner.call('POST', '/api/v1/admin/catalog/products',
                               command(key='advanced-' + uuid.uuid4().hex[:16]), expected=(201,))
    state['product_id'] = product['id']
    save_state(args.state, state)

    def publish(plan, price, generation):
        _, draft, _ = owner.call('POST', '/api/v1/admin/catalog/plans/' + plan['id'] + '/drafts',
                                 command(expected_version=plan['version']), expected=(201,))
        label = plan['key'] + '-' + generation
        _, draft, _ = owner.call('PUT', '/api/v1/admin/catalog/revisions/' + draft['id'],
                                 command(expected_version=draft['version'],
                                         name={'en': 'Advanced ' + label, 'ru': 'Приёмочный ' + label},
                                         description={'en': 'Disposable advanced acceptance', 'ru': 'Временная расширенная проверка'},
                                         features=[{'key': label, 'label': {'en': label, 'ru': label}}],
                                         offers=[{'duration_days': 30, 'price': price, 'currency': 'USDT'}]))
        _, revision, _ = owner.call('POST', '/api/v1/admin/catalog/revisions/' + draft['id'] + '/publish',
                                    command(expected_version=draft['version']))
        return revision

    plans = {}
    # Price difference 15_000_001 micros is coprime to 30 days in seconds:
    # every strictly partial remaining period requires genuine upward rounding.
    for key, rank, price in (('basic', 1, '10.000000'), ('premium', 2, '25.000001')):
        _, plan, _ = owner.call('POST', '/api/v1/admin/catalog/products/' + product['id'] + '/plans',
                                command(key=key, upgrade_rank=rank), expected=(201,))
        revision = publish(plan, price, 'one')
        plans[key] = {'plan': plan, 'revision': revision, 'offer_id': revision['offers'][0]['id']}
    state['plans'] = plans
    save_state(args.state, state)

    fixture = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=args.fixture_ca)), NoRedirect())

    def fixture_update(order, paid=None, send_callback=True):
        amount = order['amount'] if paid is None else paid
        micros(amount)
        request = urllib.request.Request(args.fixture + '/_fixture/payments/' + order['payment_attempt']['provider_payment_id'],
                                         data=json.dumps({'payment_status': 'finished', 'actually_paid': amount,
                                                          'send_callback': send_callback}).encode(), method='POST',
                                         headers={'Content-Type': 'application/json',
                                                  'X-Fixture-Control': credentials['fixture_control_token']})
        with fixture.open(request, timeout=15) as response:
            assert response.status == 200
            result = json.load(response)
        assert result['fixture'] is True and result['provider_acceptance'] is False
        assert result['callback_status'] == (202 if send_callback else None)
        assert result['create_count_for_order'] == 1
        assert Decimal(result['payment']['price_amount']) == Decimal(order['amount'])
        assert Decimal(result['payment']['pay_amount']) == Decimal(order['amount'])
        assert Decimal(result['payment']['actually_paid']) == Decimal(amount)
        return result

    def order_state(client, order_id, wanted, reason=None):
        def current():
            _, order, _ = client.call('GET', '/api/v1/orders/' + order_id)
            if order['state'] == wanted and (reason is None or order.get('fulfillment_error') == reason):
                return order
            return None
        return eventually('actual order ' + wanted, current, timeout=120)

    def checkout(client, offer_id, kind='INITIAL', sub=None, action=None):
        fields = {'offer_id': offer_id, 'kind': kind, 'network': 'USDTTRC20'}
        if sub:
            fields.update(subscription_id=sub['id'], expected_version=sub['version'])
        if action:
            fields['action_id'] = action['id']
        body = command(**fields)
        _, order, _ = client.call('POST', '/api/v1/orders', body, expected=(202,))
        state['orders'].append({'id': order['id'], 'user_id': order['user_id'], 'kind': kind})
        save_state(args.state, state)
        def ready():
            _, value, _ = client.call('GET', '/api/v1/orders/' + order['id'])
            return value if value['payment_attempt'].get('provider_payment_id') and value['payment_attempt'].get('pay_amount') else None
        order = eventually('actual provider fixture create', ready, timeout=120)
        assert order['offer_snapshot']['offer_id'] == offer_id
        assert isinstance(order['payment_attempt']['provider_payment_id'], str)
        assert int(order['payment_attempt']['provider_payment_id']) > 2**53
        if action:
            assert order['action_id'] == action['id'] and order['amount'] == action['amount']
            assert order['offer_snapshot'] == action['offer_snapshot']
        _, replay, _ = client.call('POST', '/api/v1/orders', body, expected=(202,))
        assert replay['id'] == order['id']
        return order

    def subscription(client, sid):
        return client.call('GET', '/api/v1/subscriptions/' + sid)[1]

    def entitlement(client, sid, allowed, features=None):
        _, value, _ = client.call('GET', '/api/v1/subscriptions/' + sid + '/entitlement')
        assert value['allowed'] is allowed
        if features is not None:
            assert value['features'] == features
        return value

    def purchase(label, tier='basic'):
        client, account = register(label)
        order = checkout(client, plans[tier]['offer_id'])
        fixture_update(order)
        order = order_state(client, order['id'], 'FULFILLED')
        sub = subscription(client, order['subscription_id'])
        assert sub['state'] == 'ACTIVE' and sub['current_offer_snapshot'] == order['offer_snapshot']
        assert instant(sub['current_period_end']) - instant(sub['current_period_start']) == 30 * DAY
        entitlement(client, sub['id'], True, sub['features'])
        account['subscription_id'] = sub['id']
        save_state(args.state, state)
        return client, account, sub, order

    def mutate(client, sub, operation, **fields):
        return client.call('POST', '/api/v1/subscriptions/' + sub['id'] + '/' + operation,
                           command(expected_version=sub['version'], **fields))[1]

    def error(client, method, path, body, code, status=409):
        _, value, _ = client.call(method, path, body, expected=(status,))
        assert value.get('code') == code

    def compensation(sub):
        _, preview, _ = owner.call('POST', '/api/v1/admin/subscriptions/compensations/preview',
                                   {'operation_id': str(uuid.uuid4()), 'subscription_ids': [sub['id']],
                                    'days': 1, 'reason': 'Invalidate disposable advanced quote'})
        _, applied, _ = owner.call('POST', '/api/v1/admin/subscriptions/compensations/' + preview['id'] + '/apply',
                                   command(expected_version=preview['version'], reason=preview['reason']))
        assert applied['state'] == 'APPLIED' and applied['recipients'][0]['state'] == 'APPLIED'

    def clock(kind, account, sub, action=None):
        # All identifiers are generated by this script and checked against its own
        # private account/product registry. No credentials or arbitrary SQL input.
        assert account in state['accounts'] and sub['user_id'] == account['user_id']
        assert sub['product_id'] == product['id'] and sub['state'] == 'ACTIVE'
        ids = [account['user_id'], product['id'], sub['id']]
        if action:
            ids.append(action['id'])
        for value in ids:
            assert str(uuid.UUID(value)) == value
        base = ['kubectl', '--kubeconfig', str(args.kubeconfig), '--context', 'k3d-sso-remediation']
        def invoke(argv, **kwargs):
            result = subprocess.run(argv, capture_output=True, text=True, timeout=30, **kwargs)
            assert result.returncode == 0, 'isolated disposable clock command failed (output withheld)'
            return result.stdout
        config = json.loads(invoke(base + ['config', 'view', '--minify', '-o', 'json']))
        cluster = config['clusters'][0]['cluster']
        server = urllib.parse.urlsplit(cluster['server'])
        assert server.scheme == 'https' and server.hostname in ('127.0.0.1', 'localhost', '::1')
        assert not cluster.get('insecure-skip-tls-verify') and not cluster.get('proxy-url')
        scope = f"user_id='{account['user_id']}'::uuid AND product_id='{product['id']}'::uuid"
        if kind == 'quote_expiry':
            assert action and action['subscription_id'] == sub['id'] and action['state'] == 'PREPARED'
            update = ("UPDATE subscription_actions SET expires_at=clock_timestamp()-interval '1 second' "
                      f"WHERE id='{action['id']}'::uuid AND subscription_id='{sub['id']}'::uuid AND {scope} "
                      "AND state='PREPARED'")
        else:
            assert kind == 'period_boundary'
            # Translate both paid boundaries by one interval. Do not insert paid
            # periods, set lifecycle states, alter versions, money, or snapshots.
            update = ("WITH selected AS (SELECT id,period_end-(clock_timestamp()-interval '1 second') delta "
                      f"FROM subscriptions WHERE id='{sub['id']}'::uuid AND {scope} "
                      f"AND state='ACTIVE' AND version={int(sub['version'])} FOR UPDATE) "
                      "UPDATE subscriptions s SET period_start=s.period_start-x.delta,period_end=s.period_end-x.delta,"
                      "pending_period=CASE WHEN s.pending_period IS NULL THEN NULL ELSE "
                      "jsonb_set(jsonb_set(s.pending_period,'{period_start}',"
                      "to_jsonb((s.pending_period->>'period_start')::timestamptz-x.delta)),"
                      "'{period_end}',to_jsonb((s.pending_period->>'period_end')::timestamptz-x.delta)) END "
                      "FROM selected x WHERE s.id=x.id")
        sql = ("BEGIN; SET LOCAL lock_timeout='5s'; SET LOCAL statement_timeout='10s'; "
               "DO $clock$ DECLARE n integer; BEGIN " + update + "; "
               "GET DIAGNOSTICS n=ROW_COUNT; IF n<>1 THEN RAISE EXCEPTION 'disposable clock scope mismatch'; "
               "END IF; END; $clock$; COMMIT;")
        invoke(base + ['-n', 'generic-subscriptions', 'exec', '-i', 'postgres-0', '--', 'psql',
                       '-U', 'postgres', '-d', 'subscription_db', '-v', 'ON_ERROR_STOP=1', '-X', '-q'], input=sql)
        state['clock_operations'].append({'kind': kind, 'user_id': account['user_id'],
                                          'subscription_id': sub['id'], 'action_id': action['id'] if action else None})
        save_state(args.state, state)

    # Removing ceil-proration, moving the end on upgrade, or clearing cancellation
    # must fail these independent integer-money and immutable-boundary assertions.
    user, account, sub, initial = purchase('upgrade')
    cancelled = mutate(user, sub, 'cancel')
    assert cancelled['cancel_at_period_end'] is True
    error(user, 'POST', '/api/v1/subscriptions/' + sub['id'] + '/resume',
          command(expected_version=sub['version']), 'version_conflict')
    # Ensure this covers fractional-micro ceiling, not a whole full-period fee.
    time.sleep(2)
    quote = mutate(user, cancelled, 'upgrade-quote', offer_id=plans['premium']['offer_id'])
    assert quote['state'] == 'PREPARED' and quote['subscription_version'] == cancelled['version']
    old, new = cancelled['current_offer_snapshot'], quote['offer_snapshot']
    remaining = (instant(cancelled['current_period_end']) - datetime(1970, 1, 1, tzinfo=timezone.utc)) // SECOND
    remaining -= (instant(quote['quote_at']) - datetime(1970, 1, 1, tzinfo=timezone.utc)) // SECOND
    numerator = (micros(new['price']) * old['duration_days'] - micros(old['price']) * new['duration_days']) * remaining
    denominator = old['duration_days'] * new['duration_days'] * 86400
    assert 0 < remaining < old['duration_days'] * 86400 and numerator % denominator != 0
    exact = money((numerator + denominator - 1) // denominator)
    assert quote['amount'] == exact and micros(exact) > 0
    assert instant(quote['expires_at']) <= instant(quote['quote_at']) + timedelta(minutes=5)
    assert instant(quote['expires_at']) <= instant(cancelled['current_period_end'])
    assert subscription(user, sub['id']) == cancelled
    order = checkout(user, plans['premium']['offer_id'], 'UPGRADE', cancelled, quote)
    fixture_update(order)
    order_state(user, order['id'], 'FULFILLED')
    upgraded = subscription(user, sub['id'])
    assert upgraded['current_offer_snapshot'] == quote['offer_snapshot']
    assert upgraded['current_period_start'] == cancelled['current_period_start']
    assert upgraded['current_period_end'] == cancelled['current_period_end']
    assert upgraded['cancel_at_period_end'] is True
    entitlement(user, sub['id'], True, quote['offer_snapshot']['features'])
    fixture_update(order)
    assert subscription(user, sub['id']) == upgraded
    passed('upgrade_exact_ceil_charge_same_end_cancel_preserved', quote_id=quote['id'], amount=exact,
           order_id=order['id'], subscription_id=sub['id'])

    # A scheduled downgrade is not payment. Boundary must expire without access.
    user, account, sub, _ = purchase('downgrade-unpaid', 'premium')
    scheduled = mutate(user, sub, 'downgrade', offer_id=plans['basic']['offer_id'])
    assert scheduled['next_offer_id'] == plans['basic']['offer_id'] and scheduled['pending_period'] is None
    assert scheduled['current_offer_snapshot'] == sub['current_offer_snapshot']
    assert scheduled['current_period_end'] == sub['current_period_end']
    entitlement(user, sub['id'], True, sub['features'])
    clock('period_boundary', account, scheduled)
    entitlement(user, sub['id'], False, [])
    expired = eventually('unpaid scheduled downgrade expires', lambda: (
        value if (value := subscription(user, sub['id']))['state'] == 'EXPIRED' else None))
    assert expired['pending_period'] is None and expired['current_offer_snapshot'] == sub['current_offer_snapshot']
    passed('downgrade_unpaid_boundary_no_free_period', subscription_id=sub['id'])

    # Paying next period freezes its snapshot; current premium access survives until boundary.
    user, account, sub, _ = purchase('downgrade-paid', 'premium')
    scheduled = mutate(user, sub, 'downgrade', offer_id=plans['basic']['offer_id'])
    action = mutate(user, scheduled, 'renew', offer_id=plans['basic']['offer_id'])
    assert subscription(user, sub['id']) == scheduled
    order = checkout(user, plans['basic']['offer_id'], 'RENEW', scheduled, action)
    fixture_update(order)
    order_state(user, order['id'], 'FULFILLED')
    paid = subscription(user, sub['id'])
    assert paid['current_offer_snapshot'] == sub['current_offer_snapshot']
    assert paid['current_period_end'] == sub['current_period_end']
    assert paid['pending_period']['offer_snapshot'] == action['offer_snapshot']
    assert instant(paid['pending_period']['period_start']) == instant(sub['current_period_end'])
    assert instant(paid['pending_period']['period_end']) - instant(sub['current_period_end']) == 30 * DAY
    entitlement(user, sub['id'], True, sub['features'])
    error(user, 'POST', '/api/v1/subscriptions/' + sub['id'] + '/cancel',
          command(expected_version=paid['version']), 'action_conflict')
    clock('period_boundary', account, paid)
    entitlement(user, sub['id'], True, action['offer_snapshot']['features'])
    activated = subscription(user, sub['id'])
    assert activated['state'] == 'ACTIVE' and activated['pending_period'] is None
    assert activated['next_offer_id'] is None and activated['current_offer_snapshot'] == action['offer_snapshot']
    assert instant(activated['current_period_end']) - instant(activated['current_period_start']) == 30 * DAY
    passed('downgrade_paid_next_period_activates_only_at_boundary', subscription_id=sub['id'], order_id=order['id'])

    user, account, sub, _ = purchase('expired-quote')
    quote = mutate(user, sub, 'upgrade-quote', offer_id=plans['premium']['offer_id'])
    clock('quote_expiry', account, sub, quote)
    error(user, 'POST', '/api/v1/orders', command(offer_id=plans['premium']['offer_id'], kind='UPGRADE',
          subscription_id=sub['id'], action_id=quote['id'], expected_version=sub['version'], network='USDTTRC20'), 'quote_expired')
    assert subscription(user, sub['id']) == sub
    _, own_orders, _ = user.call('GET', '/api/v1/orders')
    assert len(own_orders['items']) == 1 and own_orders['items'][0]['kind'] == 'INITIAL'
    passed('expired_upgrade_quote_http409_no_checkout_no_access_change', quote_id=quote['id'])

    # Actual compensation invalidates a STARTED paid quote; money remains review,
    # rather than upgrading against the changed period/version or disappearing.
    user, account, sub, _ = purchase('version-conflict')
    quote = mutate(user, sub, 'upgrade-quote', offer_id=plans['premium']['offer_id'])
    order = checkout(user, plans['premium']['offer_id'], 'UPGRADE', sub, quote)
    compensation(sub)
    compensated = subscription(user, sub['id'])
    assert compensated['version'] == sub['version'] + 1
    assert instant(compensated['current_period_end']) - instant(sub['current_period_end']) == DAY
    fixture_update(order)
    reviewed = order_state(user, order['id'], 'REVIEW_REQUIRED', 'subscription_version_conflict')
    assert reviewed['accepted_at'] is not None and reviewed['payment_attempt']['state'] == 'ACCEPTED'
    retry_body = command(expected_version=reviewed['version'],
                         reason='Replay same paid action; retain immutable version conflict')
    _, retrying, _ = owner.call('POST', '/api/v1/admin/payments/' + order['id'] + '/retry-fulfillment', retry_body)
    assert retrying['action_id'] == quote['id'] and retrying['accepted_at'] == reviewed['accepted_at']
    owner.call('POST', '/api/v1/admin/payments/' + order['id'] + '/retry-fulfillment', retry_body)
    replay_review = order_state(user, order['id'], 'REVIEW_REQUIRED', 'subscription_version_conflict')
    assert replay_review['action_id'] == quote['id'] and replay_review['accepted_at'] == reviewed['accepted_at']
    assert subscription(user, sub['id']) == compensated
    entitlement(user, sub['id'], True, sub['features'])
    passed('paid_upgrade_version_conflict_retains_money_and_old_entitlement', order_id=order['id'])

    # Publish a new revision without changing the current paid snapshot. New
    # renewal pays the new revision, saved pending until the original boundary.
    user, account, sub, original_order = purchase('revision-renewal')
    basic = plans['basic']
    # Draft creation and publication each increment the plan version.
    next_plan = {**basic['plan'], 'version': basic['plan']['version'] + 2}
    revision = publish(next_plan, '12.000000', 'two')
    _, retained, _ = owner.call('GET', '/api/v1/admin/catalog/revisions/' + basic['revision']['id'])
    assert retained == basic['revision']
    assert subscription(user, sub['id']) == sub
    error(owner, 'PUT', '/api/v1/admin/catalog/revisions/' + retained['id'],
          command(expected_version=retained['version'], name=retained['name'], description=retained['description'],
                  features=retained['features'], offers=[{'duration_days': 30, 'price': '99.000000', 'currency': 'USDT'}]),
          'immutable_revision')
    new_offer = revision['offers'][0]['id']
    action = mutate(user, sub, 'renew', offer_id=new_offer)
    assert action['amount'] == '12.000000' and action['offer_snapshot']['revision_id'] == revision['id']
    order = checkout(user, new_offer, 'RENEW', sub, action)
    fixture_update(order)
    order_state(user, order['id'], 'FULFILLED')
    pending = subscription(user, sub['id'])
    assert pending['current_offer_snapshot'] == sub['current_offer_snapshot']
    assert pending['current_period_end'] == sub['current_period_end']
    assert pending['pending_period']['offer_snapshot'] == action['offer_snapshot']
    assert pending['pending_period']['period_start'] == sub['current_period_end']
    assert instant(pending['pending_period']['period_end']) - instant(sub['current_period_end']) == 30 * DAY
    _, old_order, _ = user.call('GET', '/api/v1/orders/' + original_order['id'])
    assert old_order['offer_snapshot'] == original_order['offer_snapshot'] and old_order['amount'] == '10.000000'
    _, history, _ = user.call('GET', '/api/v1/subscriptions/' + sub['id'] + '/history')
    assert history['next_cursor'] is None
    assert history['items'][0]['subscription']['current_offer_snapshot'] == sub['current_offer_snapshot']
    clock('period_boundary', account, pending)
    entitlement(user, sub['id'], True, action['offer_snapshot']['features'])
    renewed = subscription(user, sub['id'])
    assert renewed['current_offer_snapshot'] == action['offer_snapshot'] and renewed['pending_period'] is None
    _, old_order_after, _ = user.call('GET', '/api/v1/orders/' + original_order['id'])
    assert old_order_after == old_order
    passed('new_revision_renewal_and_historical_snapshots_immutable', subscription_id=sub['id'],
           original_order_id=original_order['id'], renewal_order_id=order['id'])

    # Real provider underpayment -> review. Exercise evidence validation, reject,
    # reverify and positive-evidence manual accept, not merely a denial status.
    for label, external in (('manual-evidence', False), ('manual-external', True)):
        user, account = register(label)
        order = checkout(user, new_offer)
        fixture_update(order, '0.000001')
        order = order_state(user, order['id'], 'REVIEW_REQUIRED', 'underpaid_finished')
        _, subscriptions, _ = user.call('GET', '/api/v1/subscriptions')
        assert subscriptions['items'] == []
        path = '/api/v1/admin/payments/' + order['id']
        user.call('GET', path, expected=(403,))
        error(user, 'POST', path + '/accept', command(expected_version=order['version'], reason='Forbidden own review'),
              'access_denied', status=403)
        _, detail, _ = owner.call('GET', path)
        evidence = next(item for item in detail['evidence'] if item['source'] == 'STATUS'
                        and Decimal(item['payload'].get('actually_paid') or '0') > 0)
        assert evidence['payload']['payment_id'] == order['payment_attempt']['provider_payment_id']
        assert detail['order']['accepted_at'] is None
        error(owner, 'POST', path + '/accept', command(expected_version=order['version'], reason='Missing monetary evidence'),
              'invalid_evidence', status=422)
        error(owner, 'POST', path + '/accept', command(expected_version=order['version'], reason='Unrelated evidence',
              evidence_id=str(uuid.uuid4())), 'invalid_evidence', status=422)
        error(owner, 'POST', path + '/reject', command(expected_version=order['version'] + 1, reason='Stale version'),
              'version_conflict')
        rejected_body = command(expected_version=order['version'], reason='Retain disposable underpayment for manual investigation')
        _, rejected, _ = owner.call('POST', path + '/reject', rejected_body)
        _, replay, _ = owner.call('POST', path + '/reject', rejected_body)
        assert replay['id'] == rejected['id'] and replay['version'] == rejected['version']
        assert rejected['state'] == 'REVIEW_REQUIRED' and rejected['accepted_at'] is None
        assert rejected['payment_attempt']['actually_paid'] == order['payment_attempt']['actually_paid']
        assert rejected['fulfillment_error'].startswith('manual_rejected: ')
        _, still_empty, _ = user.call('GET', '/api/v1/subscriptions')
        assert still_empty['items'] == []
        # STATUS evidence is content-deduplicated: change only this known fixture
        # payment, without webhook, so the new STATUS must come from reverify GET.
        fixture_update(order, '0.000002', send_callback=False)
        _, reverified, _ = owner.call('POST', path + '/reverify',
                                     command(expected_version=rejected['version'], reason='Independently reverify disposable underpayment'))
        def independent_status():
            _, current_detail, _ = owner.call('GET', path)
            newer = [item for item in current_detail['evidence'] if item['source'] == 'STATUS'
                     and item['id'] != evidence['id']
                     and Decimal(item['payload'].get('actually_paid') or '0') == Decimal('0.000002')]
            return current_detail if newer and current_detail['order']['version'] > reverified['version'] else None
        detail = eventually('manual reverify independent provider GET', independent_status, timeout=120)
        current = detail['order']
        accept_fields = {'external_payment': {'amount': current['amount'], 'network': 'USDTTRC20',
                                             'reference': 'FIXTURE-ONLY-NO-TRANSFER-' + uuid.uuid4().hex}} if external else {'evidence_id': evidence['id']}
        accept_body = command(expected_version=current['version'],
                              reason='Explicit disposable fixture manual exception; no external transfer', **accept_fields)
        _, accepted, _ = owner.call('POST', path + '/accept', accept_body)
        _, replay, _ = owner.call('POST', path + '/accept', accept_body)
        assert replay['id'] == accepted['id'] and replay['accepted_at'] == accepted['accepted_at']
        fulfilled = order_state(user, order['id'], 'FULFILLED')
        sub = subscription(user, fulfilled['subscription_id'])
        entitlement(user, sub['id'], True, fulfilled['offer_snapshot']['features'])
        _, final_detail, _ = owner.call('GET', path)
        decisions = final_detail['decisions']
        assert sum(item['operation'] == 'admin:accept' for item in decisions) == 1
        assert sum(item['operation'] == 'admin:reject' for item in decisions) == 1
        assert sum(item['operation'] == 'admin:reverify' for item in decisions) == 1
        acceptance = next(item for item in decisions if item['operation'] == 'admin:accept')
        assert acceptance['actor_user_id'] == authority['user']['id'] and acceptance['reason'] == accept_body['reason']
        assert acceptance['evidence_id'] and fulfilled['amount'] == current['amount']
        if external:
            assert any(item['id'] == acceptance['evidence_id'] and item['source'] == 'MANUAL' for item in final_detail['evidence'])
        else:
            assert acceptance['evidence_id'] == evidence['id']
        fixture_update(order, '0.000001')
        assert subscription(user, sub['id']) == sub
        account['subscription_id'] = sub['id']
        state['integration_account_user_id'] = account['user_id']
        state['integration_subscription_id'] = sub['id']
        passed('manual_review_' + ('external_settlement' if external else 'saved_positive_evidence') + '_accepted_once',
               order_id=order['id'], subscription_id=sub['id'])

    state['completed'] = True
    save_state(args.state, state)
    print('PASS local advanced lifecycle acceptance: ' + ', '.join(state['checks']))
    print('LIMIT: real owner HTTPS/Kafka with explicit local payment fixture; not NOWPayments sandbox or real transfers.')
    print('CLOCK: ' + state['clock_mode'] + '; timestamp operations are recorded privately, not real elapsed-month proof.')


if __name__ == '__main__':
    main()
