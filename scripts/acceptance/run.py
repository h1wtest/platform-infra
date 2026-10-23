#!/usr/bin/env python3
"""Run proven real acceptance gates sequentially against the isolated platform only."""
import argparse
import os
from pathlib import Path
import sys
from common import BASE, CA, MAILPIT, ROOT, STATE, primary, run_module

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('gate', nargs='?', default='core', choices=['core', 'e2e', 'probe', 'negative', 'admin', 'race', 'events', 'smtp-fault', 'load', 'business-load', 'network', 'broker-acl', 'db-privileges', 'trace', 'failure', 'replay', 'tls', 'rolling'])
parser.add_argument('--base', default=BASE)
parser.add_argument('--mailpit', default=MAILPIT)
parser.add_argument('--state-directory', type=Path, default=STATE)
parser.add_argument('--ca', type=Path, default=CA)
args = parser.parse_args()
if args.base != 'https://localhost:8448':
    parser.error('Acceptance is restricted to the explicitly isolated localhost:8448 stand')
args.state_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
os.environ['ACCEPTANCE_DIRECTORY'] = str(args.state_directory.resolve())
os.environ['ACCEPTANCE_BASE'] = args.base
os.environ['ACCEPTANCE_MAILPIT'] = args.mailpit
os.environ['ACCEPTANCE_CA'] = str(args.ca.resolve())
state = args.state_directory / 'state.json'
shared = ['--base', args.base, '--state', state, '--ca', args.ca]

def gate(name):
    if name in ('e2e', 'probe'):
        run_module('e2e', '--mode', 'full' if name == 'e2e' else 'probe', *shared, '--mailpit', args.mailpit)
    elif name == 'negative': run_module('negative', *shared)
    elif name == 'admin': run_module('run_admin', '--ca', args.ca)
    elif name == 'race': run_module('oauth_race', *shared)
    elif name in ('events', 'smtp-fault'):
        from sys import path
        path.insert(0, str(ROOT / 'scripts'))
        from fault_lifecycle import exclusive
        with exclusive(ROOT / '.local'):
            run_module('events', '--state', state, '--postgres-pod', primary(), *(['--smtp-fault'] if name == 'smtp-fault' else []))
    elif name == 'load':
        load = args.state_directory / 'load.json'
        if not load.exists():
            run_module('prepare_load', '--base', args.base, '--mailpit', args.mailpit, '--ca', args.ca, '--state', load)
        run_module('load', '--base', args.base, '--ca', args.ca, '--state', load, '--workers', '8', '--duration', '15', '--max-p95-ms', '500')
    elif name == 'business-load':
        run_module('business_load', '--base', args.base, '--ca', args.ca, '--mailpit', args.mailpit)
    elif name == 'network':
        run_module('network_probe', '--context', 'k3d-sso-remediation', '--image', 'busybox:1.37.0@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e')
    elif name == 'broker-acl': run_module('broker_acl')
    elif name == 'db-privileges': run_module('db_privileges')
    elif name == 'trace':
        if not (args.state_directory / 'load.json').exists(): gate('load')
        run_module('trace', '--ca', args.ca)
    elif name in ('failure', 'replay'):
        sys.path.insert(0, str(ROOT / 'scripts'))
        from fault_lifecycle import exclusive
        with exclusive(ROOT / '.local'):
            if name == 'failure': run_module('failure_fixture', '--state', state)
            else: run_module('replay', '--ca', args.ca)
    elif name == 'tls': run_module('tls', '--base', args.base, '--ca', args.ca)
    elif name == 'rolling': run_module('rolling')

if args.gate == 'core':
    for name in ('tls', 'e2e', 'negative', 'race', 'events', 'broker-acl', 'db-privileges', 'network'):
        gate(name)
else:
    gate(args.gate)
