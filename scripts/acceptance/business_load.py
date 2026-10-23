"""Modest real login/profile/delivery latency and authoritative consumer lag acceptance."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import time
from types import SimpleNamespace
from common import BASE, CA, MAILPIT, STATE, primary
from e2e import Client, eventually, new_user, save_state
from events import kubectl, sql, notification_caught_up
from load import percentile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--base', default=BASE)
parser.add_argument('--ca', default=str(CA))
parser.add_argument('--mailpit', default=MAILPIT)
parser.add_argument('--users', type=int, default=10)
parser.add_argument('--workers', type=int, default=2)
args = parser.parse_args()
if not 1 <= args.users <= 10 or not 1 <= args.workers <= 2:
    parser.error('Bounded local acceptance requires1..10unique users and1..2workers; no rate-limit bypass')
cluster = SimpleNamespace(context='k3d-sso-remediation', namespace='sso-remediation', postgres_pod=primary(), postgres_user='postgres', broker_pod='redpanda-0', broker='redpanda-0.redpanda:29092')
accounts = []
for index in range(args.users):
    client, account = new_user(args, 'businessload')
    client.call('POST', '/api/v1/auth/logout', {})
    accounts.append(account)
# Registration/login setup events must finish before timing the single fresh login per user.
eventually('baseline notification group commits', lambda: notification_caught_up(cluster), 60)

def work(account):
    client = Client(args.base, args.ca)
    started = time.perf_counter()
    authenticated = client.login(account['email'], account['password'])
    login_ms = (time.perf_counter() - started) * 1000
    session_id = str(__import__('uuid').UUID(authenticated['session_id']))
    profile_started = time.perf_counter()
    _, response, _ = client.call('GET', '/api/v1/users/me')
    assert response['profile']['email'] == account['email']
    profile_ms = (time.perf_counter() - profile_started) * 1000
    user_id = str(__import__('uuid').UUID(account['user_id']))
    def delivered():
        outbox = sql(cluster, 'identity_db', f"SELECT id FROM outbox_events WHERE event_type='identity.user_logged_in' AND payload->'payload'->>'session_id'='{session_id}' LIMIT 1")
        if not outbox: return False
        event_id = str(__import__('uuid').UUID(outbox))
        return sql(cluster, 'notification_db', f"SELECT count(*) FROM delivery_jobs WHERE event_id='{event_id}' AND user_id='{user_id}' AND status='sent'") == '1'
    eventually('exact login notification delivered', delivered, 90)
    delivery_ms = (time.perf_counter() - started) * 1000
    client.call('POST', '/api/v1/auth/logout', {})
    return login_ms, profile_ms, delivery_ms

results = []
errors = 0
with ThreadPoolExecutor(max_workers=args.workers) as pool:
    futures = [pool.submit(work, account) for account in accounts]
    for future in futures:
        try: results.append(future.result())
        except (AssertionError, OSError, ValueError, KeyError): errors += 1

eventually('authoritative broker notification lag zero after business load', lambda: notification_caught_up(cluster), 90)
report = {'scenario': 'real-login-profile-email-delivery', 'users': args.users, 'workers': args.workers, 'successes': len(results), 'errors': errors, 'error_ratio': errors / args.users, 'broker_notification_lag_after': 0, 'local_target': 'login/profile p95<500ms; errors<1%; delivery p95<90000ms; lag0'}
for index, name in enumerate(('login', 'profile', 'delivery')):
    report[name + '_p95_ms'] = round(percentile([row[index] for row in results], .95), 3) if results else None
save_state(STATE / 'business-load-report.json', report)
print(json.dumps(report, indent=2))
assert report['error_ratio'] < .01 and len(results) == args.users, 'Business operations failed; no rate limit bypass permitted'
assert report['login_p95_ms'] < 500 and report['profile_p95_ms'] < 500, 'Explicit local HTTP latency target exceeded'
assert report['delivery_p95_ms'] < 90000, 'Durable email delivery latency target exceeded'
