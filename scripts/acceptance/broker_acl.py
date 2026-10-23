#!/usr/bin/env python3
"""Verify actual SASL/TLS broker rejects forbidden service permissions."""
import json
from pathlib import Path
import subprocess

from common import ROOT, STATE
root=ROOT
values=json.loads((ROOT/'.local/secrets.json').read_text())
base=['kubectl','--context','k3d-sso-remediation','-n','sso-remediation','exec','redpanda-0','--','rpk','-X','brokers=localhost:29092']

def invoke(role,*arguments):
    # Credential never printed; subprocess result bodies contain no supplied password.
    return subprocess.run(base+['-X','user='+role,'-X','pass='+values['kafka_'+role+'_password'],*arguments],capture_output=True,text=True,timeout=20)

for role in ['profile','admin']:
    allowed=invoke(role,'topic','describe','identity.events.v1','--print-summary')
    assert allowed.returncode==0 and 'TOPIC_AUTHORIZATION_FAILED' not in allowed.stdout and 'PARTITIONS  6' in allowed.stdout, f'{role} public event metadata unavailable'
    rejected=invoke(role,'topic','describe','notification.commands.v1','--print-summary')
    diagnostic=(rejected.stdout+rejected.stderr).lower()
    assert 'topic_authorization_failed' in diagnostic, 'Failure was not broker authorization denial'
    print('PASS broker TLS/SASL '+role+' reads public metadata and is denied sensitive commands')
# A consumer is not an authoritative-event producer.
producer_base=['kubectl','--context','k3d-sso-remediation','-n','sso-remediation','exec','-i','redpanda-0','--','rpk','-X','brokers=localhost:29092']
producer=subprocess.run(producer_base+['-X','user=profile','-X','pass='+values['kafka_profile_password'],'topic','produce','identity.events.v1','--key','acceptance-forbidden'],input='{}\n',capture_output=True,text=True,timeout=20)
assert producer.returncode!=0 and 'authoriz' in (producer.stdout+producer.stderr).lower(), 'Profile can forge authoritative events or failure was not ACL denial'
print('PASS profile principal cannot publish authoritative identity events')
