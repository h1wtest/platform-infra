"""Build a real AES-GCM invalid-intent job for terminal failure/alert acceptance, never fake SMTP."""
import argparse
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid
from common import ROOT, STATE, run_module
sys.path.insert(0, str(ROOT / 'scripts'))
import env_secrets

parser = argparse.ArgumentParser()
parser.add_argument('--state', type=Path, required=True)
args = parser.parse_args()
values = env_secrets.load(ROOT / '.local')
account = json.loads(args.state.read_text())['probe']
job_id = str(uuid.uuid4())
# Node's maintained OpenSSL AES-GCM implementation creates exactly nonce+ciphertext+tag/AAD job UUID.
program = """
const fs=require('node:fs'),crypto=require('node:crypto');
const value=JSON.parse(fs.readFileSync(0,'utf8'));
const nonce=crypto.randomBytes(12),cipher=crypto.createCipheriv('aes-256-gcm',Buffer.from(value.key,'base64'),nonce);
cipher.setAAD(Buffer.from(value.id));
const body=Buffer.from(JSON.stringify({to:'invalid\\r\\nrecipient',subject:'Disposable terminal validation probe',body:'No valid SMTP recipient'}));
const encrypted=Buffer.concat([nonce,cipher.update(body),cipher.final(),cipher.getAuthTag()]);
process.stdout.write(encrypted.toString('base64'));
"""
result = subprocess.run(['node', '-e', program], input=json.dumps({'key': values['delivery_encryption_key'], 'id': job_id}), text=True, capture_output=True, check=True, timeout=15)
fixture = {'job_id': job_id, 'event_id': str(uuid.uuid4()), 'user_id': str(uuid.UUID(account['user_id'])), 'encrypted_body': result.stdout.strip()}
sys_path = str(ROOT / 'scripts')
import sys
sys.path.insert(0, sys_path)
from private_files import atomic_json
atomic_json(STATE / 'failure.json', fixture)
run_module('failure_alert')
