#!/usr/bin/env python3
"""TEST FIXTURE ONLY: real HTTPS NOWPayments wire path, never real provider proof.

Runs only on explicit --bind/--port with generated fixture credentials/TLS.
No wallet transfers, no production runtime import, no successful payment by default.
The controller must explicitly settle each known fixture payment.
"""
from __future__ import annotations

import argparse
from decimal import Decimal, InvalidOperation
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import ssl
import threading
import urllib.error
import urllib.parse
import urllib.request


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate key')
        result[key] = value
    return result


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


class FixtureServer(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, address, credentials, callback_ca, callback_origins, callback_target=None):
        super().__init__(address, FixtureHandler)
        self.credentials = credentials
        self.callback_context = ssl.create_default_context(cafile=callback_ca)
        self.callback_origins = frozenset(callback_origins)
        self.callback_target = callback_target
        self.payments = {}
        self.orders = {}
        self.sequence = 9_007_199_254_740_993
        self.lock = threading.Lock()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class FixtureHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'ExplicitLocalPaymentFixture/1'

    def log_message(self, *_):
        # URLs, x-api-key and webhook payloads must never appear in stdout.
        pass

    def send(self, status, value):
        body = canonical(value)
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def authorized(self, control=False):
        key = 'control_token' if control else 'api_key'
        header = 'X-Fixture-Control' if control else 'x-api-key'
        supplied = self.headers.get(header, '')
        if not supplied or not hmac.compare_digest(supplied, self.server.credentials[key]):
            self.send(401, {'code': 'fixture_unauthorized'})
            return False
        return True

    def body(self):
        size = int(self.headers.get('Content-Length', '-1'))
        if not 0 <= size <= 65536:
            raise ValueError('bounded body required')
        return json.loads(self.rfile.read(size), object_pairs_hook=unique_object,
                          parse_float=str, parse_int=str,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite')))

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == '/health/live':
            return self.send(200, {'fixture': True, 'provider_acceptance': False})
        if not self.authorized():
            return
        if path == '/v1/status':
            return self.send(200, {'message': 'OK', 'fixture': True})
        if path == '/v1/currencies':
            return self.send(200, {'currencies': ['usdttrc20', 'usdtbsc']})
        if path.startswith('/v1/payment/'):
            with self.server.lock:
                payment = self.server.payments.get(path.rsplit('/', 1)[1])
                payment = dict(payment) if payment else None
            return self.send(200, payment) if payment else self.send(404, {'code': 'payment_not_found'})
        self.send(404, {'code': 'fixture_not_found'})

    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        control = path.startswith('/_fixture/')
        if not self.authorized(control):
            return
        try:
            body = self.body()
            if not isinstance(body, dict):
                raise ValueError('object required')
            if path == '/v1/payment':
                return self.create(body)
            if path.startswith('/_fixture/payments/'):
                return self.update(path.rsplit('/', 1)[1], body)
            self.send(404, {'code': 'fixture_not_found'})
        except (ValueError, TypeError, InvalidOperation, KeyError):
            self.send(400, {'code': 'fixture_invalid_request'})

    def create(self, body):
        amount = Decimal(str(body['price_amount']))
        if not amount.is_finite() or amount <= 0:
            raise ValueError('positive exact amount required')
        order_id = body['order_id']
        currency = body['pay_currency'].lower()
        if not isinstance(order_id, str) or currency not in ('usdttrc20', 'usdtbsc'):
            raise ValueError('invalid order/currency')
        callback = body.get('ipn_callback_url')
        if callback:
            parsed = urllib.parse.urlsplit(callback)
            origin = parsed.scheme + '://' + parsed.netloc
            if origin not in self.server.callback_origins or parsed.username or parsed.password or parsed.fragment:
                raise ValueError('fixture callback outside exact allowlist')
        with self.server.lock:
            # The real provider is NOT assumed to deduplicate creation. This
            # fixture deliberately returns a new payment for every POST.
            self.server.sequence += 1
            payment_id = str(self.server.sequence)
            payment = {'payment_id': payment_id, 'parent_payment_id': None,
                       'payment_status': 'waiting', 'pay_address': 'TEST_FIXTURE_NOT_A_REAL_WALLET',
                       'payin_extra_id': None, 'price_amount': format(amount, 'f'),
                       'price_currency': body.get('price_currency', 'usdt').lower(),
                       'pay_amount': format(amount, 'f'), 'actually_paid': '0',
                       'pay_currency': currency, 'order_id': order_id,
                       'order_description': 'Explicit local acceptance fixture',
                       'purchase_id': payment_id, 'outcome_amount': '0',
                       'outcome_currency': currency, 'ipn_callback_url': callback}
            self.server.payments[payment_id] = payment
            self.server.orders.setdefault(order_id, []).append(payment_id)
        self.send(201, payment)

    def update(self, payment_id, body):
        status = body['payment_status']
        if status not in ('waiting', 'confirming', 'confirmed', 'sending', 'partially_paid', 'finished', 'failed', 'expired'):
            raise ValueError('invalid fixture status')
        with self.server.lock:
            previous = self.server.payments.get(payment_id)
            if not previous:
                return self.send(404, {'code': 'payment_not_found'})
            payment = dict(previous)
            payment['payment_status'] = status
            if 'actually_paid' in body:
                paid = Decimal(str(body['actually_paid']))
                if not paid.is_finite() or paid < 0:
                    raise ValueError('invalid paid amount')
                payment['actually_paid'] = format(paid, 'f')
                payment['outcome_amount'] = format(paid, 'f')
            self.server.payments[payment_id] = payment
        callback = payment.get('ipn_callback_url')
        callback_status = None
        if body.get('send_callback') is True and callback:
            payload = {key: value for key, value in payment.items() if key != 'ipn_callback_url'}
            raw = canonical(payload)
            signature = hmac.new(self.server.credentials['ipn_secret'].encode(), raw, hashlib.sha512).hexdigest()
            target = self.server.callback_target or callback
            request = urllib.request.Request(target, data=raw, method='POST',
                                             headers={'Content-Type': 'application/json', 'x-nowpayments-sig': signature})
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=self.server.callback_context), NoRedirect())
            try:
                with opener.open(request, timeout=10) as response:
                    response.read(4096)
                    callback_status = response.status
            except urllib.error.HTTPError as error:
                callback_status = error.code
            except OSError:
                callback_status = 'unavailable'
        self.send(200, {'payment': payment, 'callback_status': callback_status,
                        'create_count_for_order': len(self.server.orders[payment['order_id']]),
                        'fixture': True, 'provider_acceptance': False})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bind', default='127.0.0.1')
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--cert', required=True)
    parser.add_argument('--key', required=True)
    parser.add_argument('--credentials', type=Path, required=True)
    parser.add_argument('--callback-ca', required=True)
    parser.add_argument('--callback-origin', action='append', required=True)
    parser.add_argument('--callback-target', help='Explicit fixture-only internal HTTPS receiver for an allowlisted public callback origin')
    args = parser.parse_args()
    if args.credentials.is_symlink() or os.name != 'nt' and args.credentials.stat().st_mode & 0o077:
        parser.error('fixture credential file must be an owner-only regular file')
    credentials = json.loads(args.credentials.read_text())
    if not all(isinstance(credentials.get(k), str) and len(credentials[k]) >= 32 for k in ('api_key', 'ipn_secret', 'control_token')):
        parser.error('explicit generated fixture credentials required')
    if args.callback_target:
        target = urllib.parse.urlsplit(args.callback_target)
        if target.scheme != 'https' or target.hostname not in ('billing-service', 'localhost', '127.0.0.1') or target.username or target.password or target.query or target.fragment or target.path != '/api/v1/payments/nowpayments/webhook':
            parser.error('fixture callback target must be exact local billing webhook HTTPS')
    server = FixtureServer((args.bind, args.port), credentials, args.callback_ca, args.callback_origin, args.callback_target)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.cert, args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print('LOCAL_FIXTURE_READY: no real payment provider acceptance', flush=True)
    server.serve_forever()


if __name__ == '__main__':
    main()
