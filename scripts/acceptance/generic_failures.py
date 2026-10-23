#!/usr/bin/env python3
"""Real task-local SMTP/subscription/broker outage recovery; parent execution only.

No SQL, injected delivery jobs, foreign namespaces, host faults or provider claims.
Each invocation runs one explicit case under the shared fault_lifecycle lock.
Private state journals exact original replicas BEFORE the only allowed mutation.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta
from email import policy
from email.parser import BytesParser
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import uuid

from e2e import Client, NoRedirect, find_mail, save_state
from generic_commerce import command
from generic_notifications import history, private_json

INFRA = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(INFRA / 'scripts'))
import fault_lifecycle
import cluster_identity
from cli import wait_port_forward

NS = 'generic-subscriptions'
CONTEXT = 'k3d-sso-remediation'
ROOT = INFRA / '.generic-local'
TARGETS = {'smtp': ('deployment', 'mailpit'),
           'subscription': ('deployment', 'subscription-service'),
           'broker': ('statefulset', 'redpanda')}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def instant(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def wait(label, function, timeout):
    # Invariant failures must fail immediately, never be swallowed as polling.
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = function()
        if result:
            return result
        time.sleep(0.5)
    raise AssertionError('Deadline exceeded: ' + label)


def inside_private(path, directory, existing=True):
    require(path.absolute().is_relative_to(directory.absolute()), 'Input/output outside task-private directory')
    for candidate in (path, *path.parents):
        require(not candidate.is_symlink(), 'Symlink in task-private input/output path')
        if candidate == INFRA:
            break
    require(path.resolve().is_relative_to(directory.resolve()), 'Resolved path outside task-private directory')
    if existing:
        require(path.is_file(), 'Private regular input required')
        require(os.name != 'nt' and path.stat().st_mode & 0o077 == 0,
                'Run on Linux with owner-only private inputs')


class Acceptance:
    def __init__(self, args):
        self.args = args
        self.state = {'case': args.case, 'namespace': NS, 'context': CONTEXT,
                      'run_id': uuid.uuid4().hex, 'checks': [], 'accounts': [],
                      'faults': [], 'evidence': {}, 'status': 'RUNNING',
                      'limits': ['Mailpit proves local SMTP, not external email delivery',
                                 'HTTPS payment fixture is not NOWPayments sandbox acceptance',
                                 'No Telegram provider acceptance or whole-host crash claim']}
        self.environment = {key: value for key, value in os.environ.items()
                            if key in ('PATH', 'HOME', 'SYSTEMROOT', 'WINDIR', 'TMPDIR', 'TEMP', 'TMP')}
        self.base = ['kubectl', '--kubeconfig', str(args.kubeconfig), '--context', CONTEXT,
                     '--namespace', NS, '--request-timeout=20s']
        self.credentials = private_json(args.credentials)
        self.owner = None
        self.persist()

    def persist(self):
        save_state(self.args.state, self.state)

    def passed(self, label, **evidence):
        self.state['checks'].append(label)
        self.state['evidence'][label] = evidence
        self.persist()
        print('PASS ' + label, flush=True)

    def kube(self, *command, timeout=40):
        try:
            result = subprocess.run(self.base + list(command), capture_output=True,
                                    text=True, timeout=timeout, env=self.environment)
        except (OSError, subprocess.TimeoutExpired):
            raise RuntimeError('Task-local kubectl unavailable or timed out; output withheld') from None
        require(result.returncode == 0, 'Task-local kubectl failed; output withheld')
        return result.stdout

    def get(self, kind, name=None):
        return json.loads(self.kube('get', kind, *([name] if name else []), '-o', 'json'))

    def guard(self):
        config = json.loads(self.kube('config', 'view', '--raw', '--minify', '-o', 'json'))
        require(len(config.get('clusters', [])) == len(config.get('contexts', [])) == 1,
                'One explicit cluster/context required')
        cluster = config['clusters'][0]['cluster']
        server = urllib.parse.urlsplit(cluster.get('server', ''))
        require(server.scheme == 'https' and server.hostname in ('localhost', '127.0.0.1', '::1')
                and not server.username and not server.password and server.path in ('', '/')
                and not server.query and not server.fragment
                and not cluster.get('insecure-skip-tls-verify') and not cluster.get('proxy-url')
                and bool(cluster.get('certificate-authority-data') or cluster.get('certificate-authority')),
                'Explicit direct CA-verifying loopback cluster required')
        require(config['contexts'][0]['name'] == CONTEXT and config.get('current-context') == CONTEXT,
                'Unexpected task-local context')
        require(all(not any(key in entry.get('user', {}) for key in ('exec', 'auth-provider'))
                    for entry in config.get('users', [])), 'Cloud/external credential plugins forbidden')
        baseline_path = ROOT / 'namespace-identity.json'
        inside_private(baseline_path, ROOT)
        require(baseline_path.stat().st_mode & 0o377 == 0, 'Task ownership baseline must be read-only owner-only')
        baseline = private_json(baseline_path)
        import hmac
        require(hmac.compare_digest(baseline['sha256'], cluster_identity.digest(baseline['identity'])),
                'Task namespace baseline integrity mismatch')
        actual = cluster_identity.namespace_snapshot(CONTEXT, cluster['server'],
            self.get('namespace', 'kube-system')['metadata']['uid'], self.get('namespace', NS))
        cluster_identity.validate_namespace(baseline['identity'], actual)
        import base64
        actual_ca = base64.b64decode(self.get('secret', 'platform-ca')['data']['ca.crt'], validate=True)
        require(actual_ca == self.args.ca.read_bytes(), 'Gateway CA differs from task namespace trust root')
        self.ready(*TARGETS[self.args.case])
        if self.args.case in ('subscription', 'broker'):
            require(all(self.credentials.get(field) for field in
                        ('owner_email', 'owner_password', 'owner_totp_secret')),
                    'Existing OWNER MFA private credentials required; enrollment is forbidden')
            self.owner = Client(self.args.base, str(self.args.ca))
            self.owner.login(self.credentials['owner_email'], self.credentials['owner_password'],
                             self.credentials['owner_totp_secret'])
            user = self.owner.call('GET', '/api/v1/auth/me')[1]['user']
            require('owner' in user['roles'] and user['mfa_verified'] is True, 'Live OWNER MFA authority required')
        self.passed('explicit_private_loopback_generic_namespace_guard')

    def ready(self, kind, name):
        def probe():
            current = self.get(kind, name)
            replicas = current['spec'].get('replicas', 1)
            status = current.get('status', {})
            return current if (replicas > 0 and status.get('readyReplicas', 0) == replicas
                               and status.get('observedGeneration', 0) >= current['metadata']['generation']
                               and (kind != 'deployment' or status.get('updatedReplicas', 0) == replicas)) else None
        return wait('selected workload ready', probe, self.args.timeout)

    def controlled_pods(self, kind, name, uid):
        uids = {uid}
        if kind == 'deployment':
            uids = {row['metadata']['uid'] for row in self.get('replicasets')['items']
                    if any(ref.get('uid') == uid and ref.get('controller') for ref in row['metadata'].get('ownerReferences', []))}
        return [row for row in self.get('pods')['items'] if any(
            ref.get('uid') in uids and ref.get('controller') for ref in row['metadata'].get('ownerReferences', []))]

    def broker_storage(self):
        workload = self.get('statefulset', 'redpanda')
        spec = workload['spec']
        retention = spec.get('persistentVolumeClaimRetentionPolicy', {})
        require(retention.get('whenScaled', 'Retain') == retention.get('whenDeleted', 'Retain') == 'Retain',
                'Broker scale must retain every PVC')
        require(spec.get('volumeClaimTemplates') and all(
            volume.get('name') != 'data' or 'emptyDir' not in volume
            for volume in spec['template']['spec'].get('volumes', [])), 'Persistent broker data volume required')
        startup = json.dumps(spec['template']['spec']['containers'])
        require('--unsafe-bypass-fsync=false' in startup and '--unsafe-bypass-fsync=true' not in startup,
                'Fsync must already be enabled; acceptance never changes broker config')
        pvcs = {row['metadata']['name']: {'uid': row['metadata']['uid'], 'spec': row['spec']}
                for row in self.get('pvc')['items'] if row['metadata']['name'].startswith('data-redpanda-')}
        require(len(pvcs) >= spec.get('replicas', 1), 'Broker data PVC inventory incomplete')
        fingerprints = {}
        for kind, name in (('configmap', 'redpanda-config'), ('secret', 'redpanda-bootstrap'), ('secret', 'redpanda-tls')):
            data = self.get(kind, name)
            fingerprints[name] = hashlib.sha256(json.dumps(
                {'uid': data['metadata']['uid'], 'data': data.get('data', {}), 'binaryData': data.get('binaryData', {})},
                sort_keys=True).encode()).hexdigest()
        return {'pvcs': pvcs, 'config_sha256': fingerprints}

    def replicas(self, kind, name, snapshot, value):
        # A JSONPatch is atomic: a replaced workload or any intervening write
        # rejects all changes rather than scaling a new/unrelated controller.
        patch = [{'op': 'test', 'path': '/metadata/uid', 'value': snapshot['metadata']['uid']},
                 {'op': 'test', 'path': '/metadata/resourceVersion', 'value': snapshot['metadata']['resourceVersion']},
                 {'op': 'test', 'path': '/spec/replicas', 'value': snapshot['spec'].get('replicas', 1)},
                 {'op': 'replace', 'path': '/spec/replicas', 'value': value}]
        self.kube('patch', kind + '/' + name, '--type=json', '-p', json.dumps(patch))

    @contextmanager
    def outage(self):
        kind, name = TARGETS[self.args.case]
        before = self.ready(kind, name)
        original = before['spec'].get('replicas', 1)
        entry = {'kind': kind, 'name': name, 'uid': before['metadata']['uid'],
                 'original_replicas': original, 'original_spec': before['spec'], 'restored': False}
        if kind == 'statefulset':
            entry['storage_before'] = self.broker_storage()
        self.state['faults'].append(entry)
        self.persist()  # Must precede even the first scale request (including lost-response outcomes).
        try:
            self.replicas(kind, name, before, 0)
            wait('selected workload fully stopped', lambda: not self.controlled_pods(kind, name, entry['uid']), self.args.timeout)
            require(self.get(kind, name)['spec'].get('replicas') == 0, 'Selected workload was not stopped')
            self.passed(self.args.case + '_selected_workload_down', original_replicas=original)
            yield
        finally:
            # A second Ctrl-C/SIGTERM must not interrupt the bounded restore path.
            handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
            for sig in handlers:
                signal.signal(sig, signal.SIG_IGN)
            try:
                current = self.get(kind, name)
                require(current['metadata']['uid'] == entry['uid'], 'Selected workload replaced; manual recovery required')
                expected_down = {**entry['original_spec'], 'replicas': 0}
                require(current['spec'] in (expected_down, entry['original_spec']),
                        'Selected workload changed during outage; refusing concurrent operator overwrite')
                self.replicas(kind, name, current, original)
                restored = self.ready(kind, name)
                require(restored['spec'] == entry['original_spec'], 'Selected workload spec changed beyond replicas')
                if kind == 'statefulset':
                    require(self.broker_storage() == entry['storage_before'], 'Broker PVC/config identity changed')
                entry['restored'] = True
                self.persist()
                self.passed(self.args.case + '_exact_original_replicas_restored', replicas=original)
            finally:
                for sig, handler in handlers.items():
                    signal.signal(sig, handler)

    @contextmanager
    def mail_forward(self):
        # Mailpit scale-down kills existing pod-bound forwards. Own a fresh,
        # ephemeral loopback forward after recovery; never kill a parent forward.
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        process = subprocess.Popen(self.base + ['port-forward', '--address=127.0.0.1',
                                               'deployment/mailpit', str(port) + ':8025'],
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=self.environment)
        base = 'http://127.0.0.1:' + str(port)
        try:
            wait_port_forward(process, port, 8025, timeout=20)
            def available():
                require(process.poll() is None, 'Owned Mailpit forward exited; output withheld')
                try:
                    with urllib.request.urlopen(base + '/api/v1/messages?limit=1', timeout=2) as response:
                        return response.status == 200
                except OSError:
                    return False
            wait('owned recovered Mailpit loopback forward', available, 20)
            yield base
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            process.stdout.close()

    def account(self, label, referral_code=None, verify=True):
        record = {'email': 'generic-fault-' + label + '-' + uuid.uuid4().hex + '@example.invalid',
                  'password': secrets.token_urlsafe(24) + 'aA9!', 'locale': 'en'}
        self.state['accounts'].append(record)
        self.persist()
        client = Client(self.args.base, str(self.args.ca))
        client.bootstrap_csrf()
        body = dict(record)
        if referral_code:
            body['referral_code'] = referral_code
        _, registered, _ = client.call('POST', '/api/v1/auth/register', body, expected=(201,))
        record['user_id'] = registered['user_id']
        self.persist()
        if verify:
            self.verify(client, record, self.args.mailpit)
        return client, record

    def verify(self, client, record, mailpit):
        code = find_mail(mailpit, record['email'], 'verification', timeout=self.args.timeout)
        client.call('POST', '/api/v1/auth/verify-email', {'user_id': record['user_id'], 'code': code})
        client.login(record['email'], record['password'])
        def projected():
            status, body, _ = client.call('GET', '/api/v1/users/me', expected=(200, 404, 503))
            return body.get('profile') if status == 200 else None
        profile = wait('actual Kafka registration profile', projected, self.args.timeout)
        require(profile['email'] == record['email'], 'Wrong registered profile')
        return profile

    def settled_history(self, client):
        def settled():
            rows = history(client)
            # Registration verification and the subsequent real login each
            # create an email job. Do not race a not-yet-consumed login event.
            emails = [row for row in rows if row['channel'] == 'email']
            return rows if len(emails) >= 2 and all(row['status'] in ('sent', 'failed') for row in rows) else None
        return wait('initial registration/login jobs terminal', settled, self.args.timeout)

    def matching_mail(self, base, record, message_id=None):
        matches, offset = [], 0
        while True:
            url = base + '/api/v1/messages?' + urllib.parse.urlencode({'start': offset, 'limit': 100})
            with urllib.request.urlopen(url, timeout=10) as response:
                listing = json.load(response)
            entries = listing['messages']
            for entry in entries:
                if not any(to.get('Address', '').lower() == record['email'].lower() for to in entry.get('To', [])):
                    continue
                if message_id is None:
                    matches.append(entry['ID'])
                    continue
                with urllib.request.urlopen(base + '/api/v1/message/' + entry['ID'] + '/raw', timeout=10) as response:
                    parsed = BytesParser(policy=policy.default).parsebytes(response.read())
                if str(parsed.get('Message-ID', '')).strip() == message_id:
                    matches.append(entry['ID'])
            offset += len(entries)
            if offset >= listing['total']:
                return matches
            require(entries and offset < 10000, 'Mailpit evidence pagination exceeded bound')

    def smtp(self):
        client, record = self.account('smtp')
        client.call('PATCH', '/api/v1/users/me/notifications', {'email_login_alerts': True})
        require(client.call('GET', '/api/v1/users/me')[1]['notification_settings']['email_login_alerts'] is True,
                'Persisted login email preference missing')
        old_ids = {row['id'] for row in self.settled_history(client)}
        with self.outage():
            login = Client(self.args.base, str(self.args.ca))
            login.login(record['email'], record['password'])
            require(login.call('GET', '/api/v1/auth/me')[1]['user']['id'] == record['user_id'], 'Actual outage login missing')
            def deferred():
                rows = [row for row in history(client) if row['id'] not in old_ids and row['channel'] == 'email']
                require(len(rows) <= 1, 'One login created duplicate durable email jobs')
                if not rows:
                    return None
                row = rows[0]
                require(row['status'] not in ('sent', 'failed') and not row['delivered_at'], 'SMTP outage falsely terminal')
                return row if row['status'] == 'retry' and row['attempts'] >= 1 and row['last_error'] == 'smtp_unavailable' else None
            pending = wait('SMTP durable retry from real login', deferred, self.args.timeout)
            require(pending['message_id'] and not pending['ambiguous'], 'Pre-connect SMTP outage is not provider ambiguity')
            require(instant(pending['next_attempt_at']) > instant(pending['created_at']), 'Retry deadline was not persisted')
            self.passed('smtp_real_login_durable_deferred_email', delivery=pending)
        with self.mail_forward() as base:
            def delivered():
                rows = [row for row in history(client) if row['id'] not in old_ids and row['channel'] == 'email']
                require(len(rows) == 1 and rows[0]['id'] == pending['id'], 'Recovery allocated a duplicate logical job')
                row = rows[0]
                require(row['status'] != 'failed', 'Recovered SMTP delivery failed')
                if row['status'] != 'sent':
                    return None
                require(row['delivered_at'] and row['message_id'] == pending['message_id']
                        and row['attempts'] > pending['attempts'] and not row['ambiguous'], 'Recovered delivery metadata incorrect')
                matches = self.matching_mail(base, record, row['message_id'])
                require(len(matches) <= 1, 'Duplicate actual SMTP delivery')
                return {'delivery': row, 'mailpit_ids': matches} if matches else None
            evidence = wait('actual Mailpit SMTP delivery after recovery', delivered, self.args.timeout)
            self.observe(lambda: require(delivered() == evidence, 'SMTP logical/physical delivery changed after recovery'))
            self.passed('smtp_recovery_same_job_one_actual_mailpit_delivery', **evidence)

    def observe(self, invariant):
        deadline = time.monotonic() + self.args.observe_seconds
        while True:
            invariant()
            if time.monotonic() >= deadline:
                return
            time.sleep(1)

    def subscription(self):
        require(self.credentials.get('fixture_control_token'), 'Private fixture control token required')
        referrer, ref_record = self.account('referrer')
        def summary_ready():
            status, result, _ = referrer.call('GET', '/api/v1/referrals', expected=(200, 503))
            return result if status == 200 and result.get('code') else None
        before = wait('disposable referral account', summary_ready, self.args.timeout)
        require(before['earned'] == before['available'] == '0.000000', 'Fresh partner balance is not zero')
        # Public customer summary deliberately omits private rate-version data;
        # use the live MFA-authorized admin listing, never guess version1.
        cursor, seen_cursors, partner = None, set(), None
        for _ in range(100):
            query = {'limit': 100}
            if cursor:
                query['cursor'] = cursor
            page = self.owner.call('GET', '/api/v1/admin/referrals/partners?' + urllib.parse.urlencode(query))[1]
            partner = next((item for item in page['items'] if item['user_id'] == ref_record['user_id']), None)
            if partner:
                break
            cursor = page.get('next_cursor')
            if not cursor:
                break
            require(cursor not in seen_cursors, 'Admin partner pagination repeated cursor')
            seen_cursors.add(cursor)
        require(partner is not None, 'New referrer absent from bounded admin partner listing')
        self.owner.call('PUT', '/api/v1/admin/referrals/partners/' + ref_record['user_id'] + '/rate',
                        command(rate_bps=1000, expected_version=partner['rate_version'], reason='Disposable outage acceptance partner only'))
        require(referrer.call('GET', '/api/v1/referrals')[1]['rate_bps'] == 1000, 'Partner-only rate not persisted')
        customer, record = self.account('customer', before['code'])
        _, product, _ = self.owner.call('POST', '/api/v1/admin/catalog/products',
                                       command(key='fault-' + self.state['run_id'][:16]), expected=(201,))
        _, plan, _ = self.owner.call('POST', '/api/v1/admin/catalog/products/' + product['id'] + '/plans',
                                    command(key='standard', upgrade_rank=1), expected=(201,))
        _, draft, _ = self.owner.call('POST', '/api/v1/admin/catalog/plans/' + plan['id'] + '/drafts',
                                     command(expected_version=plan['version']), expected=(201,))
        _, draft, _ = self.owner.call('PUT', '/api/v1/admin/catalog/revisions/' + draft['id'],
                                     command(expected_version=draft['version'], name={'en': 'Fault acceptance', 'ru': 'Приёмка отказов'},
                                             description={'en': 'Disposable', 'ru': 'Временный'},
                                             features=[{'key': 'access', 'label': {'en': 'Access', 'ru': 'Доступ'}}],
                                             offers=[{'duration_days': 30, 'price': '10.000000', 'currency': 'USDT'}]))
        _, revision, _ = self.owner.call('POST', '/api/v1/admin/catalog/revisions/' + draft['id'] + '/publish',
                                        command(expected_version=draft['version']))
        offer_id = revision['offers'][0]['id']
        require(customer.call('GET', '/api/v1/subscriptions')[1]['items'] == [], 'Fresh customer already subscribed')
        body = command(offer_id=offer_id, kind='INITIAL', network='USDTTRC20')
        _, created, _ = customer.call('POST', '/api/v1/orders', body, expected=(200, 202))
        self.state['order_id'] = created['id']
        self.state['product_id'] = product['id']
        self.persist()
        def current_order():
            return customer.call('GET', '/api/v1/orders/' + created['id'])[1]
        order = wait('fixture order prepared before owner outage', lambda: (
            value if value['payment_attempt'].get('provider_payment_id') else None
        ) if (value := current_order()) else None, self.args.timeout)
        require(order['state'] == 'PAYMENT_PENDING' and not order['accepted_at'] and order['action_id']
                and order['commission_quote_id'] and order['amount'] == '10.000000', 'Order not genuinely prepared/unpaid')
        self.passed('subscription_new_order_prepared_before_fault', order=order)
        fixture = urllib.request.build_opener(urllib.request.HTTPSHandler(
            context=ssl.create_default_context(cafile=str(self.args.fixture_ca))),
            NoRedirect())
        def settle():
            request = urllib.request.Request(self.args.fixture + '/_fixture/payments/' + order['payment_attempt']['provider_payment_id'],
                data=json.dumps({'payment_status': 'finished', 'actually_paid': order['amount'], 'send_callback': True}).encode(),
                method='POST', headers={'Content-Type': 'application/json',
                                        'X-Fixture-Control': self.credentials['fixture_control_token']})
            with fixture.open(request, timeout=15) as response:
                result = json.load(response)
            require(result.get('fixture') is True and result['provider_acceptance'] is False
                    and result['callback_status'] == 202 and result['create_count_for_order'] == 1,
                    'Actual HTTPS fixture/callback evidence missing')
            return {'fixture': True, 'provider_acceptance': False, 'callback_status': result['callback_status'],
                    'create_count_for_order': result['create_count_for_order']}
        with self.outage():
            fixture_evidence = settle()
            def accepted_pending():
                value = current_order()
                require(value['state'] != 'FULFILLED', 'Unavailable subscription falsely fulfilled')
                return value if value['accepted_at'] and value['state'] == 'FULFILLMENT_PENDING' else None
            accepted = wait('money accepted without false fulfillment', accepted_pending, self.args.timeout)
            def pending_invariant():
                value = current_order()
                require(value['state'] == 'FULFILLMENT_PENDING' and value['accepted_at'] == accepted['accepted_at']
                        and value['payment_attempt']['state'] == 'ACCEPTED', 'Accepted monetary fact lost or falsely fulfilled')
                require(referrer.call('GET', '/api/v1/referrals')[1]['earned'] == '0.000000', 'Unfulfilled order earned commission')
                status, _, _ = customer.call('GET', '/api/v1/subscriptions', expected=(502, 503, 504))
                require(status in (502, 503, 504), 'Unavailable owner falsely returned successful subscriptions')
            self.observe(pending_invariant)
            self.passed('subscription_outage_money_accepted_fulfillment_pending_no_commission',
                        order=accepted, fixture=fixture_evidence)
        fulfilled = wait('actual Kafka fulfillment after owner restoration', lambda: (
            value if value['state'] == 'FULFILLED' else None
        ) if (value := current_order()) else None, self.args.timeout)
        require(fulfilled['accepted_at'] == accepted['accepted_at'] and fulfilled['action_id'] == accepted['action_id'],
                'Fulfillment rewrote monetary/action identity')
        sid = fulfilled['subscription_id']
        self.state['subscription_id'] = sid
        self.persist()
        def owner_routes_ready():
            # Kubernetes replica readiness and the Kafka fulfillment reply do
            # not prove the public HTTPS proxy route has recovered yet. Poll
            # dependency availability only; economic assertions below remain
            # strict and are never swallowed/retried as readiness failures.
            paths = ['/api/v1/subscriptions/' + sid, '/api/v1/subscriptions',
                     '/api/v1/subscriptions/' + sid + '/history',
                     '/api/v1/subscriptions/' + sid + '/entitlement']
            statuses = [customer.call('GET', path, expected=(200, 502, 503, 504))[0] for path in paths]
            self.state['evidence']['subscription_recovered_owner_route_http_statuses'] = statuses
            self.persist()
            return all(status == 200 for status in statuses)
        wait('restored subscription public HTTPS owner routes', owner_routes_ready, self.args.timeout)
        def recovered_invariant():
            value = current_order()
            require(value['state'] == 'FULFILLED' and value['accepted_at'] == accepted['accepted_at'], 'Fulfilled order regressed')
            sub = customer.call('GET', '/api/v1/subscriptions/' + sid)[1]
            subscriptions = customer.call('GET', '/api/v1/subscriptions')[1]
            rows = [row for row in subscriptions['items'] if row['product_id'] == product['id']]
            require(len(rows) == 1 and rows[0]['id'] == sid and not subscriptions.get('next_cursor'), 'Duplicate subscription aggregate')
            require(sub['state'] == 'ACTIVE' and sub['version'] == 1 and
                    instant(sub['current_period_end']) - instant(sub['current_period_start']) == timedelta(days=30),
                    'Recovery granted more or less than one exact period')
            hist = customer.call('GET', '/api/v1/subscriptions/' + sid + '/history')[1]
            require(len(hist['items']) == 1 and hist['items'][0]['version'] == 1 and not hist['next_cursor'], 'Duplicate period/history effect')
            require(customer.call('GET', '/api/v1/subscriptions/' + sid + '/entitlement')[1]['allowed'] is True, 'Recovered entitlement missing')
            balance = referrer.call('GET', '/api/v1/referrals')[1]
            require(balance['earned'] == balance['available'] == '1.000000' and balance['reserved'] == balance['paid'] == '0.000000',
                    'Commission not exactly one disposable purchase')
            return {'subscription': sub, 'history': hist, 'referral': balance}
        wait('one commission after actual fulfillment', lambda: (
            referrer.call('GET', '/api/v1/referrals')[1]['earned'] == '1.000000'), self.args.timeout)
        evidence = recovered_invariant()
        settle()  # A real duplicate signed callback, not a synthetic Kafka/SQL replay.
        replay = customer.call('POST', '/api/v1/orders', body, expected=(200, 202))[1]
        require(replay['id'] == order['id'], 'Duplicate checkout created another order')
        self.observe(recovered_invariant)
        self.passed('subscription_recovery_exact_one_period_commission_duplicate_callback_stable', **evidence)

    def broker(self):
        with self.outage():
            client, record = self.account('broker', verify=False)
            # Admin composition readiness depends on Kafka and is intentionally
            # unavailable during this fault. Direct identity login still queries
            # its owner DB and verifies the actual password before this precise
            # unverified-account denial; do not treat a generic403 as proof.
            client.call('POST', '/api/v1/auth/login',
                        {'email': record['email'], 'password': secrets.token_urlsafe(32)}, expected=(401,))
            _, denied, _ = client.call('POST', '/api/v1/auth/login',
                {'email': record['email'], 'password': record['password']}, expected=(403,))
            require(denied.get('code') == 'email_not_verified', 'Stored unverified identity proof missing')
            def stored_roles():
                roles = self.owner.call('GET', '/api/v1/admin/users/' + record['user_id'] + '/roles')[1]
                require(roles['user_id'] == record['user_id'] and isinstance(roles['role_version'], int)
                        and roles['role_version'] >= 1 and isinstance(roles['roles'], list),
                        'Direct identity-owned stored user read missing')
                return roles
            persisted_roles = stored_roles()
            def registration_pending():
                require(stored_roles() == persisted_roles, 'Stored identity roles changed during broker outage')
                require(not self.matching_mail(self.args.mailpit, record), 'Registration email bypassed unavailable broker')
            self.observe(registration_pending)
            self.passed('broker_outage_registration_identity_persisted_no_email', user_id=record['user_id'],
                        identity_roles=persisted_roles, correct_password_denial=denied['code'])
        def persisted_unverified():
            status, user, _ = self.owner.call('GET', '/api/v1/admin/users/' + record['user_id'], expected=(200, 502, 503, 504))
            if status != 200:
                return None
            require(user['id'] == record['user_id'] and user['email'] == record['email'] and not user['is_verified'],
                    'Recovered owner detail does not match persisted unverified identity')
            return user
        wait('restored admin composition confirms same unverified user', persisted_unverified, self.args.timeout)
        self.verify(client, record, self.args.mailpit)
        def complete():
            profile = client.call('GET', '/api/v1/users/me')[1]['profile']
            user = self.owner.call('GET', '/api/v1/admin/users/' + record['user_id'])[1]
            require(profile['email'] == record['email'] and user['is_verified'], 'Recovered profile/verification missing')
            return profile
        profile = complete()
        rows = self.settled_history(client)
        # Verification is the sole mandatory pre-login email; compare the actual
        # persisted message ID rather than confusing the later login alert.
        transactional = [row for row in rows if row['channel'] == 'email' and row['status'] == 'sent']
        require(transactional, 'No persisted actual email delivery after broker recovery')
        with self.mail_forward() as base:
            mail_evidence = []
            for row in transactional:
                ids = self.matching_mail(base, record, row['message_id'])
                require(len(ids) == 1, 'Broker recovery email missing or duplicated in Mailpit')
                mail_evidence.append({'delivery_id': row['id'], 'message_id': row['message_id'], 'mailpit_ids': ids})
            def stable():
                complete()
                require({row['id'] for row in history(client)} == {row['id'] for row in rows}, 'Broker recovery duplicated logical jobs')
                for item in mail_evidence:
                    require(self.matching_mail(base, record, item['message_id']) == item['mailpit_ids'], 'Broker recovery duplicated actual email')
            self.observe(stable)
        self.passed('broker_registration_outbox_recovery_actual_email_verified_profile', profile=profile, mail=mail_evidence)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', choices=tuple(TARGETS), required=True)
    parser.add_argument('--base', default='https://localhost:18448')
    parser.add_argument('--mailpit', default='http://localhost:38026')
    parser.add_argument('--fixture', default='https://localhost:19444')
    parser.add_argument('--ca', type=Path, required=True)
    parser.add_argument('--fixture-ca', type=Path)
    parser.add_argument('--kubeconfig', type=Path, required=True)
    parser.add_argument('--credentials', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True, help='NEW private .generic-local/acceptance evidence file')
    parser.add_argument('--timeout', type=int, default=180, help='Bound for each recovery/poll phase,10..600seconds')
    parser.add_argument('--observe-seconds', type=int, default=15, help='Post-recovery duplicate observation window,5..120seconds')
    args = parser.parse_args()
    require(args.base == 'https://localhost:18448' and args.mailpit == 'http://localhost:38026'
            and args.fixture == 'https://localhost:19444', 'Only isolated generic loopback endpoints allowed')
    require(10 <= args.timeout <= 600 and 5 <= args.observe_seconds <= 120, 'Timeout/observation bounds invalid')
    require(args.kubeconfig.absolute() == (ROOT / 'kubeconfig.json').absolute(), 'Explicit task-private kubeconfig required')
    inside_private(args.kubeconfig, ROOT)
    inside_private(args.credentials, ROOT / 'acceptance')
    inside_private(args.ca, ROOT, existing=False)
    require(args.ca.is_file(), 'Explicit task CA required')
    inside_private(args.state, ROOT / 'acceptance', existing=False)
    require(not args.state.exists(), 'Evidence path must be NEW; never overwrite existing private records')
    if args.case == 'subscription':
        require(args.fixture_ca is not None, 'Explicit HTTPS fixture CA required for subscription case')
        inside_private(args.fixture_ca, ROOT, existing=False)
        require(args.fixture_ca.is_file(), 'Fixture trust root missing')
    args.state.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    acceptance = Acceptance(args)
    try:
        with fault_lifecycle.exclusive(ROOT):
            acceptance.guard()
            getattr(acceptance, args.case)()
        acceptance.state['status'] = 'PASS'
        acceptance.persist()
        print('PASS generic_' + args.case + '_outage_recovery', flush=True)
        for limit in acceptance.state['limits']:
            print('LIMIT ' + limit, flush=True)
        return 0
    except BaseException as error:
        acceptance.state['status'] = 'INTERRUPTED' if isinstance(error, KeyboardInterrupt) else 'FAILED'
        acceptance.state['failure_type'] = type(error).__name__
        acceptance.state['failure_message'] = str(error)[:1500]  # Private only; never echoed to console.
        acceptance.persist()
        # Deliberately omit exception/provider bodies, tokens, addresses/passwords.
        print('FAIL generic_' + args.case + '_outage_recovery; type=' + type(error).__name__
              + '; inspect private evidence and fault restoration journal', file=sys.stderr, flush=True)
        return 130 if isinstance(error, KeyboardInterrupt) else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (AssertionError, OSError, ValueError) as error:
        print('FAIL generic fault prerequisite; type=' + type(error).__name__ + '; details withheld', file=sys.stderr)
        raise SystemExit(1) from None
