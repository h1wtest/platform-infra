#!/usr/bin/env python3
"""Run real new-owner Go regressions with private per-owner PostgreSQL URLs.

Requires an explicitly owned disposable PostgreSQL fixture; never production.
No credential or raw subprocess output reaches stdout. Protected logs remain local.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import time
from urllib.parse import quote, urlsplit


OWNERS = ('catalog', 'billing', 'subscription', 'referral')
REPOSITORIES = ('user-notification-service', 'catalog-service', 'subscription-service', 'referral-service', 'billing-service')


def run(command, cwd, env, log, timeout=900):
    started = time.monotonic()
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, timeout=timeout, check=False)
    log.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(result.stdout)
        stream.write(result.stderr)
    print(('PASS' if result.returncode == 0 else 'FAIL') + ' ' + cwd.name + ' ' + ' '.join(command[1:])
          + ' (' + str(round(time.monotonic() - started, 2)) + 's; protected log ' + log.name + ')', flush=True)
    return result.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--credential-env', type=Path, required=True)
    parser.add_argument('--port', type=int, default=35432)
    parser.add_argument('--logs', type=Path, required=True)
    parser.add_argument('--repo', action='append', choices=REPOSITORIES)
    args = parser.parse_args()
    if args.credential_env.is_symlink() or args.credential_env.stat().st_mode & 0o077:
        parser.error('disposable credential input must be owner-only regular file')
    credentials = {}
    for line in args.credential_env.read_text().splitlines():
        if line.strip() and not line.startswith('#'):
            key, value = line.split('=', 1)
            credentials[key] = value
    user, password = credentials['POSTGRES_USER'], credentials['POSTGRES_PASSWORD']
    if user != 'generic_test' or args.port != 35432:
        parser.error('only explicitly named disposable generic_test fixture on localhost35432 allowed')
    env = dict(os.environ, GOTOOLCHAIN='go1.26.10', CGO_ENABLED='1')
    failures = []
    for repository in args.repo or REPOSITORIES:
        root = args.workspace / repository
        owner = repository.removesuffix('-service') if repository != 'user-notification-service' else 'profile'
        dsn = ('postgresql://' + quote(user, safe='') + ':' + quote(password, safe='')
               + '@127.0.0.1:' + str(args.port) + '/' + owner + '_test?sslmode=disable')
        # Test-only loopback PostgreSQL fixture. Actual runtime remains verify-full.
        selected = dict(env, TEST_DATABASE_URL=dsn)
        for name in ('PROFILE', 'NOTIFICATION', 'AUDIT', 'CATALOG', 'BILLING', 'SUBSCRIPTION', 'REFERRAL'):
            selected[name + '_TEST_DATABASE_URL'] = dsn.replace('/' + owner + '_test?', '/' + name.lower() + '_test?')
        selected['DATABASE_URL'] = dsn
        for label, command in [('test', ['go', 'test', '-race', './...']),
                               ('vet', ['go', 'vet', './...']),
                               ('build', ['go', 'build', './cmd/...'])]:
            if run(command, root, selected, args.logs / (repository + '-' + label + '.log')):
                failures.append(repository + ':' + label)
                break
    print(json.dumps({'checked': args.repo or list(REPOSITORIES), 'failures': failures,
                      'provider_acceptance': False}))
    raise SystemExit(bool(failures))


if __name__ == '__main__':
    main()
