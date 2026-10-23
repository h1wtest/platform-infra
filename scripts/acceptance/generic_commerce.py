#!/usr/bin/env python3
"""Exercise real generic owner APIs/Kafka using an explicitly labelled HTTPS payment fixture.

This proves local commerce state transitions, not NOWPayments sandbox acceptance.
Creates only unique disposable accounts/products/orders and retains private evidence.
"""
from __future__ import annotations

import argparse
from decimal import Decimal
import json
import os
from pathlib import Path
import secrets
import ssl
import time
from types import SimpleNamespace
import urllib.request
import uuid

from e2e import Client, eventually, find_mail, save_state, totp


def command(**extra):
    return {'idempotency_key': str(uuid.uuid4()), **extra}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', default='https://localhost:18448')
    parser.add_argument('--mailpit', default='http://localhost:38026')
    parser.add_argument('--ca', required=True)
    parser.add_argument('--fixture', required=True)
    parser.add_argument('--fixture-ca', required=True)
    parser.add_argument('--credentials', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    args = parser.parse_args()
    if args.base != 'https://localhost:18448':
        parser.error('only isolated generic local origin18448 allowed')
    if args.credentials.is_symlink() or os.name != 'nt' and args.credentials.stat().st_mode & 0o077:
        parser.error('private credential file required')
    credentials = json.loads(args.credentials.read_text())
    state = {'fixture_only': True, 'nowpayments_acceptance': 'OPEN', 'checks': [], 'accounts': []}
    owner = Client(args.base, args.ca)
    owner.login(credentials['owner_email'], credentials['owner_password'], credentials.get('owner_totp_secret'))
    owner_secret = credentials.get('owner_totp_secret')
    if not owner_secret:
        owner.call('POST', '/api/v1/auth/reauth', {'password': credentials['owner_password']})
        _, setup, _ = owner.call('POST', '/api/v1/auth/mfa/setup', {})
        owner_secret = setup['secret']
        # Record generated secret privately before enabling; interruption must not
        # strand the disposable owner without its known recovery material.
        state['owner_totp_secret'] = owner_secret
        state['owner_recovery_codes'] = setup['recovery_codes']
        save_state(args.state, state)
        owner.call('POST', '/api/v1/auth/mfa/enable', {'code': totp(owner_secret)})
        owner.bootstrap_csrf()
        _, challenge, _ = owner.call('POST', '/api/v1/auth/login', {
            'email': credentials['owner_email'], 'password': credentials['owner_password']})
        if challenge.get('status') != 'mfa_required':
            raise AssertionError('enabled owner factor did not require MFA')
        owner.call('POST', '/api/v1/auth/mfa/verify-login', {
            'challenge_id': challenge['challenge_id'], 'code': setup['recovery_codes'][0]})
        owner.bootstrap_csrf()
    _, authority, _ = owner.call('GET', '/api/v1/auth/me')
    assert 'owner' in authority['user']['roles'] and authority['user']['mfa_verified']
    state['checks'].append('owner_mfa_authority')

    def register(label, referral_code=None):
        client = Client(args.base, args.ca)
        client.bootstrap_csrf()
        account = {'email': 'generic-' + label + '-' + uuid.uuid4().hex + '@example.invalid',
                   'password': secrets.token_urlsafe(24) + 'aA9!', 'locale': 'en'}
        body = dict(account)
        if referral_code:
            body['referral_code'] = referral_code
        _, result, _ = client.call('POST', '/api/v1/auth/register', body, expected=(201,))
        account['user_id'] = result['user_id']
        code = find_mail(args.mailpit, account['email'], 'verification')
        client.call('POST', '/api/v1/auth/verify-email', {'user_id': account['user_id'], 'code': code})
        client.login(account['email'], account['password'])
        eventually('registered profile Kafka projection', lambda: client.call('GET', '/api/v1/users/me')[1].get('profile'))
        state['accounts'].append(account)
        save_state(args.state, state)
        return client, account

    referrer, referrer_account = register('referrer')
    def referral_summary():
        _, summary, _ = referrer.call('GET', '/api/v1/referrals', expected=(200, 503))
        return summary if summary.get('code') and 'earned' in summary else None
    referrer_before = eventually('referral account created by identity event', referral_summary)
    _, rate, _ = owner.call('GET', '/api/v1/admin/referrals/rate')
    owner.call('PUT', '/api/v1/admin/referrals/rate', command(
        rate_bps=1000, expected_version=rate['version'], reason='Disposable local acceptance10percent'))
    customer, account = register('customer', referrer_before['code'])
    outsider, outsider_account = register('outsider')
    customer.call('PATCH', '/api/v1/users/me', {'website_locale': 'ru', 'notification_locale': 'en',
                                               'display_name': 'Disposable integrated customer'})
    _, profile, _ = customer.call('GET', '/api/v1/users/me')
    assert profile['profile']['website_locale'] == 'ru'
    assert profile['profile']['notification_locale'] == 'en'
    state['checks'].append('registration_referral_profile_locales')

    key = 'acceptance-' + uuid.uuid4().hex[:16]
    _, product, _ = owner.call('POST', '/api/v1/admin/catalog/products', command(key=key), expected=(201,))
    _, plan, _ = owner.call('POST', '/api/v1/admin/catalog/products/' + product['id'] + '/plans',
                             command(key='standard', upgrade_rank=1), expected=(201,))
    _, revision, _ = owner.call('POST', '/api/v1/admin/catalog/plans/' + plan['id'] + '/drafts',
                                 command(expected_version=plan['version']), expected=(201,))
    _, revision, _ = owner.call('PUT', '/api/v1/admin/catalog/revisions/' + revision['id'],
                                 command(expected_version=revision['version'],
                                         name={'en': 'Acceptance Standard', 'ru': 'Приёмочный Стандарт'},
                                         description={'en': 'Disposable subscription', 'ru': 'Временная подписка'},
                                         features=[{'key': 'access', 'label': {'en': 'Product access', 'ru': 'Доступ'}}],
                                         offers=[{'duration_days': 30, 'price': '10.000000', 'currency': 'USDT'}]))
    _, revision, _ = owner.call('POST', '/api/v1/admin/catalog/revisions/' + revision['id'] + '/publish',
                                 command(expected_version=revision['version']))
    offer_id = revision['offers'][0]['id']
    state['product_id'] = product['id']
    state['offer_id'] = offer_id
    customer.call('POST', '/api/v1/admin/catalog/products', command(key='forbidden'), expected=(403,))
    state['checks'].append('catalog_publish_and_admin_denial')

    fixture_context = ssl.create_default_context(cafile=args.fixture_ca)
    def fixture_settle(payment_id, paid='10.000000'):
        request = urllib.request.Request(args.fixture.rstrip('/') + '/_fixture/payments/' + payment_id,
                                         data=json.dumps({'payment_status': 'finished', 'actually_paid': paid,
                                                          'send_callback': True}).encode(), method='POST',
                                         headers={'Content-Type': 'application/json',
                                                  'X-Fixture-Control': credentials['fixture_control_token']})
        with urllib.request.urlopen(request, context=fixture_context, timeout=15) as response:
            result = json.load(response)
        assert result['provider_acceptance'] is False
        return result

    checkout_body = command(offer_id=offer_id, kind='INITIAL', network='USDTTRC20')
    _, order, _ = customer.call('POST', '/api/v1/orders', checkout_body, expected=(200, 202))
    _, duplicate, _ = customer.call('POST', '/api/v1/orders', checkout_body, expected=(200, 202))
    assert duplicate['id'] == order['id']
    outsider.call('GET', '/api/v1/orders/' + order['id'], expected=(403, 404))
    def order_ready():
        _, current, _ = customer.call('GET', '/api/v1/orders/' + order['id'])
        return current if current['payment_attempt'].get('provider_payment_id') else None
    order = eventually('actual provider HTTP creation', order_ready, timeout=90)
    payment_id = order['payment_attempt']['provider_payment_id']
    assert isinstance(payment_id, str) and int(payment_id) > 2**53
    settled = fixture_settle(payment_id)
    assert settled['create_count_for_order'] == 1
    def fulfilled():
        _, current, _ = customer.call('GET', '/api/v1/orders/' + order['id'])
        return current if current['state'] == 'FULFILLED' else None
    order = eventually('payment to subscription via real Kafka', fulfilled, timeout=120)
    subscription_id = order['subscription_id']
    _, subscription, _ = customer.call('GET', '/api/v1/subscriptions/' + subscription_id)
    assert subscription['state'] == 'ACTIVE'
    _, entitlement, _ = customer.call('GET', '/api/v1/subscriptions/' + subscription_id + '/entitlement')
    assert entitlement['allowed'] is True
    outsider.call('GET', '/api/v1/subscriptions/' + subscription_id, expected=(403, 404))
    state['checks'].append('idempotent_checkout_payment_kafka_subscription_entitlement')
    state['order_id'] = order['id']
    state['subscription_id'] = subscription_id
    fixture_settle(payment_id)
    def commission_ready():
        summary = referral_summary()
        return summary if summary and summary['earned'] == '1.000000' else None
    commission = eventually('exact referral commission after fulfillment', commission_ready, timeout=90)
    assert commission['available'] == '1.000000'
    state['checks'].append('one_commission_on_duplicate_payment')

    # Separate user: provider "finished" with insufficient funds must not grant.
    _, underpaid, _ = outsider.call('POST', '/api/v1/orders', command(
        offer_id=offer_id, kind='INITIAL', network='USDTTRC20'), expected=(200, 202))
    def underpaid_created():
        _, current, _ = outsider.call('GET', '/api/v1/orders/' + underpaid['id'])
        return current if current['payment_attempt'].get('provider_payment_id') else None
    underpaid = eventually('underpayment fixture creation', underpaid_created, timeout=90)
    fixture_settle(underpaid['payment_attempt']['provider_payment_id'], '0.000001')
    def underpayment_review():
        _, current, _ = outsider.call('GET', '/api/v1/orders/' + underpaid['id'])
        return current if current['state'] == 'REVIEW_REQUIRED' else None
    eventually('finished underpayment withheld for review', underpayment_review, timeout=90)
    _, outsider_subscriptions, _ = outsider.call('GET', '/api/v1/subscriptions')
    assert not any(item['product_id'] == product['id'] and item['state'] == 'ACTIVE'
                   for item in outsider_subscriptions['items'])
    state['checks'].append('provider_finished_underpaid_does_not_grant')

    _, payout, _ = referrer.call('POST', '/api/v1/referrals/payouts', command(
        network='tron', address='TJRabPrwbZy45sbavfcjinPJC18kjpRTv8'))
    assert payout['amount'] == '1.000000' and payout['state'] == 'PENDING'
    _, reserved, _ = referrer.call('GET', '/api/v1/referrals')
    assert reserved['available'] == '0.000000' and reserved['reserved'] == '1.000000'
    decision = command(decision='REJECTED', expected_version=payout['version'],
                       reason='Reject disposable request without transferring funds')
    owner.call('POST', '/api/v1/admin/referrals/payouts/' + payout['id'] + '/decision', decision)
    owner.call('POST', '/api/v1/admin/referrals/payouts/' + payout['id'] + '/decision', decision)
    _, released, _ = referrer.call('GET', '/api/v1/referrals')
    assert released['available'] == '1.000000' and released['reserved'] == '0.000000'
    state['checks'].append('payout_reservation_manual_rejection_releases_once')
    save_state(args.state, state)

    _, renewal_action, _ = customer.call('POST', '/api/v1/subscriptions/' + subscription_id + '/renew',
        command(expected_version=subscription['version'], offer_id=offer_id))
    _, renewal, _ = customer.call('POST', '/api/v1/orders', command(
        offer_id=offer_id, kind='RENEW', subscription_id=subscription_id,
        action_id=renewal_action['id'], expected_version=subscription['version'], network='USDTTRC20'), expected=(200, 202))
    def renewal_created():
        _, current, _ = customer.call('GET', '/api/v1/orders/' + renewal['id'])
        return current if current['payment_attempt'].get('provider_payment_id') else None
    renewal = eventually('prepared renewal reused by checkout', renewal_created, timeout=90)
    fixture_settle(renewal['payment_attempt']['provider_payment_id'])
    def renewal_fulfilled():
        _, current, _ = customer.call('GET', '/api/v1/orders/' + renewal['id'])
        return current if current['state'] == 'FULFILLED' else None
    eventually('renewal applied through Kafka once', renewal_fulfilled, timeout=120)
    _, renewed, _ = customer.call('GET', '/api/v1/subscriptions/' + subscription_id)
    from datetime import datetime
    parse_time = lambda value: datetime.fromisoformat(value.replace('Z', '+00:00'))
    assert (parse_time(renewed['current_period_end']) - parse_time(subscription['current_period_end'])).total_seconds() == 30 * 86400
    subscription = renewed
    state['checks'].append('renewal_extends_exact_period_without_duplicate_action')

    _, cancelled, _ = customer.call('POST', '/api/v1/subscriptions/' + subscription_id + '/cancel',
                                   command(expected_version=subscription['version']))
    assert cancelled['cancel_at_period_end'] is True
    _, resumed, _ = customer.call('POST', '/api/v1/subscriptions/' + subscription_id + '/resume',
                                 command(expected_version=cancelled['version']))
    assert resumed['cancel_at_period_end'] is False
    op = str(uuid.uuid4())
    _, compensation, _ = owner.call('POST', '/api/v1/admin/subscriptions/compensations/preview', {
        'operation_id': op, 'subscription_ids': [subscription_id], 'days': 2,
        'reason': 'Disposable local acceptance compensation'})
    apply_body = command(expected_version=compensation['version'], reason=compensation['reason'])
    _, applied, _ = owner.call('POST', '/api/v1/admin/subscriptions/compensations/' + compensation['id'] + '/apply', apply_body)
    owner.call('POST', '/api/v1/admin/subscriptions/compensations/' + compensation['id'] + '/apply', apply_body)
    _, extended, _ = customer.call('GET', '/api/v1/subscriptions/' + subscription_id)
    from datetime import datetime
    parse_time = lambda value: datetime.fromisoformat(value.replace('Z', '+00:00'))
    assert (parse_time(extended['current_period_end']) - parse_time(resumed['current_period_end'])).total_seconds() == 2 * 86400
    state['checks'].append('cancel_resume_idempotent_compensation')
    owner.call('POST', '/api/v1/admin/subscriptions/' + subscription_id + '/close',
               command(expected_version=extended['version'], reason='Close disposable acceptance subscription'))
    _, denied, _ = customer.call('GET', '/api/v1/subscriptions/' + subscription_id + '/entitlement')
    assert denied['allowed'] is False
    state['checks'].append('admin_close_denies_entitlement')
    save_state(args.state, state)
    print('PASS local commerce acceptance: ' + ', '.join(state['checks']))
    print('LIMIT: explicit HTTPS payment fixture; NOWPayments sandbox/Telegram gates not established by this run.')


if __name__ == '__main__':
    main()
