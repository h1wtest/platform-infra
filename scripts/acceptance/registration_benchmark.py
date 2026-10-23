#!/usr/bin/env python3
"""Benchmark registration POSTs on the isolated HTTPS stand without bypassing limits."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http.client import HTTPException
import json
import math
from pathlib import Path
import secrets
import sys
import threading
import time
import uuid

from common import BASE, CA, ROOT, STATE
from e2e import Client, save_state


def latency_summary(values):
    if not values:
        return None
    ordered = sorted(values)
    return {name: round(ordered[max(0, math.ceil(len(ordered) * fraction) - 1)], 3)
            for name, fraction in (('p50', .5), ('p95', .95), ('p99', .99), ('max', 1))}


def summarize(samples, elapsed):
    created = [row for row in samples if row['outcome'] == 'created']
    limited = sum(row['outcome'] == 'rate_limited' for row in samples)
    errors = len(samples) - len(created) - limited
    outcome = ('failed' if errors else 'blocked' if not created else
               'completed_with_throttling' if limited else 'completed')
    return {'outcome': outcome, 'attempts': len(samples), 'successes': len(created),
            'rate_limited': limited, 'errors': errors,
            'http_status_counts': dict(sorted(Counter(str(row['status']) for row in samples
                                                     if row['status'] is not None).items())),
            'error_counts': dict(Counter(row['outcome'] for row in samples
                                        if row['outcome'] not in ('created', 'rate_limited'))),
            'elapsed_seconds': round(elapsed, 6),
            'registrations_per_second': round(len(created) / elapsed, 3),
            'attempts_per_second': round(len(samples) / elapsed, 3),
            'successful_latency_ms': latency_summary([row['latency_ms'] for row in created]),
            'all_attempt_latency_ms': latency_summary([row['latency_ms'] for row in samples])}


def run(args):
    run_id = uuid.uuid4().hex
    workers = min(args.workers, args.users)
    # Setup is deliberately excluded from registration timing; no timed warm-up user.
    accounts = [(f'benchmark-register-{run_id}-{index}@example.invalid',
                 secrets.token_urlsafe(24) + 'aA9!') for index in range(args.users)]
    clients = [Client(args.base, str(args.ca)) for _ in range(workers)]
    for client in clients:
        client.bootstrap_csrf()
    barrier = threading.Barrier(workers + 1)

    def work(worker_index):
        client = clients[worker_index]
        rows = []
        barrier.wait(timeout=30)
        for index in range(worker_index, args.users, workers):
            email, password = accounts[index]
            row = {'index': index, 'status': None}
            started = time.perf_counter()
            try:
                status, body, _ = client.call('POST', '/api/v1/auth/register',
                                             {'email': email, 'password': password},
                                             expected=range(100, 600))
                row['status'] = status
                row['outcome'] = ('rate_limited' if status == 429 else
                                  'created' if status == 201 else 'http_error')
                if status == 201:
                    try:
                        user_id = str(uuid.UUID(body['user_id']))
                        if body['email'] != email:
                            raise ValueError('Registration email mismatch')
                        row['user_id'] = user_id
                    except (KeyError, TypeError, ValueError, AttributeError):
                        row['outcome'] = 'invalid_response'
            except (OSError, ValueError, HTTPException) as error:
                # Never retain exception messages, response bodies or generated passwords.
                row.update(outcome='transport_error', error_type=type(error).__name__)
            row['latency_ms'] = round((time.perf_counter() - started) * 1000, 6)
            rows.append(row)
        return rows

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(work, index) for index in range(workers)]
        started_at = datetime.now(timezone.utc).isoformat()
        started = time.perf_counter()
        barrier.wait(timeout=30)
        samples = [row for future in futures for row in future.result()]
        elapsed = time.perf_counter() - started
    seen = set()
    for row in samples:
        if row['outcome'] == 'created':
            if row['user_id'] in seen:
                row['outcome'] = 'invalid_response'
            seen.add(row['user_id'])
    report = {'scenario': 'registration-post', 'run_id': run_id, 'started_at': started_at,
              'base': args.base, 'workers': workers, 'requested_workers': args.workers,
              'requested_users': args.users, **summarize(samples, elapsed),
              'measurement': 'Closed-loop POST latency including HTTPS, CSRF validation, '
                             'Argon2 and user/challenge/role/outbox transaction; '
                             'client/CSRF setup and asynchronous delivery excluded.',
              'limitations': 'Single local generator; gateway-observed IP buckets depend on '
                             'the local proxy/SNAT path. Live 20 attempts/10min per-bucket policy unchanged. '
                             '429 latency is excluded from successful percentiles. '
                             'Short local run is not maximum sustainable capacity. '
                             'Created unverified example.invalid accounts are retained.',
              'samples': sorted(samples, key=lambda row: row['index'])}
    path = STATE / f'registration-benchmark-{run_id}.json'
    save_state(path, report)
    print(json.dumps({key: value for key, value in report.items() if key != 'samples'}, indent=2))
    print('Report:', path)
    return 1 if report['errors'] else 2 if not report['successes'] else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', default=BASE)
    parser.add_argument('--ca', type=Path, default=CA)
    parser.add_argument('--users', type=int, default=40)
    parser.add_argument('--workers', type=int, default=4)
    args = parser.parse_args()
    if args.base != 'https://localhost:8448':
        parser.error('Only the isolated https://localhost:8448 stand is allowed')
    if not 1 <= args.users <= 200 or not 1 <= args.workers <= 32:
        parser.error('users 1..200 and workers 1..32 required; rate limits remain enabled')
    sys.path.insert(0, str(ROOT / 'scripts'))
    from fault_lifecycle import exclusive
    with exclusive(ROOT / '.local'):
        return run(args)


if __name__ == '__main__':
    raise SystemExit(main())
