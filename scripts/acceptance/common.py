"""Shared ignored acceptance paths; no application or production access."""
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
STATE = Path(os.environ.get('ACCEPTANCE_DIRECTORY', ROOT / '.local/acceptance'))
CA = Path(os.environ.get('ACCEPTANCE_CA', ROOT / '.local/ca.crt'))
BASE = os.environ.get('ACCEPTANCE_BASE', 'https://localhost:8448')
MAILPIT = os.environ.get('ACCEPTANCE_MAILPIT', 'http://localhost:28026')


def primary():
    result = subprocess.run(['kubectl', '--context', 'k3d-sso-remediation', '-n', 'sso-remediation', 'get', 'cluster.postgresql.cnpg.io', 'postgres', '-o', 'jsonpath={.status.currentPrimary}'], capture_output=True, text=True, check=True, timeout=15)
    return result.stdout.strip()


def run_module(name, *arguments):
    subprocess.run([sys.executable, str(Path(__file__).with_name(name + '.py')), *map(str, arguments)], check=True, timeout=600)


def account_state(name='state.json'):
    return STATE / name
