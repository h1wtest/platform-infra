#!/usr/bin/env python3
"""Measure actual authenticated profile reads with bounded concurrency.

No claim of capacity from discovery. Caller supplies explicit latency threshold.
"""
from concurrent.futures import ThreadPoolExecutor
import argparse
import json
from pathlib import Path
import threading
import time

from e2e import Client


def percentile(values, fraction):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, int((len(ordered) - 1) * fraction)))]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base', default='https://localhost:8448')
    parser.add_argument('--state', required=True)
    parser.add_argument('--ca')
    parser.add_argument('--workers', type=int, default=8)
    parser.add_argument('--duration', type=float, default=15)
    parser.add_argument('--max-p95-ms', type=float, required=True)
    args = parser.parse_args()
    if not 1 <= args.workers <= 64 or not 1 <= args.duration <= 300 or args.max_p95_ms <= 0:
        parser.error('workers 1..64, duration 1..300s and positive max-p95-ms required')
    account = json.loads(Path(args.state).read_text())['probe']
    authenticated = Client(args.base, args.ca)
    authenticated.login(account['email'], account['password'])
    # Setup performs one real login; worker load measures authenticated profile reads,
    # not an artificial burst of repeated login attempts on the same account.
    shared_cookies = list(authenticated.jar)
    shared_csrf = authenticated.csrf
    barrier = threading.Barrier(args.workers)

    def worker():
        client = Client(args.base, args.ca)
        for cookie in shared_cookies:
            client.jar.set_cookie(cookie)
        client.csrf = shared_csrf
        barrier.wait(timeout=60)
        end = time.monotonic() + args.duration
        latencies, errors = [], 0
        while time.monotonic() < end:
            start = time.perf_counter()
            try:
                _, body, _ = client.call('GET', '/api/v1/users/me')
                if body['profile']['email'] != account['email']:
                    raise AssertionError('Wrong authenticated profile')
                latencies.append((time.perf_counter() - start) * 1000)
            except (AssertionError, OSError, KeyError):
                errors += 1
        return latencies, errors

    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = list(pool.map(lambda _: worker(), range(args.workers)))
    authenticated.call('POST', '/api/v1/auth/logout', {})
    latencies = [value for result, _ in results for value in result]
    errors = sum(error for _, error in results)
    assert latencies, 'No completed real authenticated requests'
    report = {'scenario': 'authenticated-profile-reads', 'workers': args.workers,
              'requested_duration_seconds': args.duration, 'elapsed_seconds': round(time.monotonic() - started, 3),
              'successes': len(latencies), 'errors': errors,
              'p50_ms': round(percentile(latencies, .5), 3),
              'p95_ms': round(percentile(latencies, .95), 3),
              'p99_ms': round(percentile(latencies, .99), 3),
              'max_p95_ms': args.max_p95_ms}
    print(json.dumps(report, indent=2))
    assert errors == 0, 'Business requests failed under load'
    assert report['p95_ms'] <= args.max_p95_ms, 'Explicit profile latency acceptance exceeded'


if __name__ == '__main__':
    main()
