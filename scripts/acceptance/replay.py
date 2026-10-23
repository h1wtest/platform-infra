#!/usr/bin/env python3
"""Exercise genuine owner-scoped poison correction and failed-job replay as MFA admin."""
import argparse
import json
from pathlib import Path
import subprocess
from e2e import Client, eventually
from events import create_event

from common import ROOT, STATE
root=ROOT
parser=argparse.ArgumentParser();parser.add_argument('--ca',required=True);args=parser.parse_args()
admin_state=json.loads((STATE/'admin-state.json').read_text())
user=json.loads((STATE/'state.json').read_text())['probe']
admin=Client('https://localhost:8448',args.ca)
from mfa_login import login_admin
login_admin(admin,admin_state['email'],admin_state['password'],STATE/'admin-state.json')
_,records,_=admin.call('GET','/api/v1/admin/quarantine?owner=notification')
from fixtures import owned_record
record=owned_record(records);path=f'/api/v1/admin/quarantine/{record["id"]}/replay?owner=notification'
admin.call('POST',path,{},expected=(409,))
event_id,encoded=create_event(user['user_id'])
admin.call('POST',path,{'corrected_event':json.loads(encoded)})
admin.call('POST',path,{'corrected_event':json.loads(encoded)},expected=(404,))
base=['kubectl','--context','k3d-sso-remediation','-n','sso-remediation']
def sql(query):
    primary=subprocess.run(base+['get','cluster.postgresql.cnpg.io','postgres','-o','jsonpath={.status.currentPrimary}'],capture_output=True,text=True,check=True,timeout=10).stdout.strip()
    result=subprocess.run(base+['exec',primary,'--','psql','-U','postgres','-d','notification_db','-Atc',query],capture_output=True,text=True,timeout=10)
    assert result.returncode==0,'Replay state SQL unavailable'
    return result.stdout.strip()
eventually('corrected actual poison creates sent delivery',lambda:sql(f"SELECT count(*) FROM delivery_jobs WHERE event_id='{event_id}' AND status='sent'")=='1',60)
assert sql(f"SELECT count(*) FROM quarantine_replays WHERE quarantine_id='{record['id']}'")=='1'
print('PASS malformed poison rejected, corrected canonical replay delivered once and immutable correction audit persisted')
fixture=json.loads((STATE/'failure.json').read_text());job=fixture['job_id']
assert sql(f"SELECT status FROM delivery_jobs WHERE id='{job}'")=='failed'
admin.call('POST',f'/api/v1/admin/deliveries/{job}/replay',{})
eventually('actual failed invalid-intent replay is revalidated',lambda:sql(f"SELECT count(*) FROM delivery_attempts WHERE job_id='{job}' AND status='failed'")=='2',45)
assert sql(f"SELECT status FROM delivery_jobs WHERE id='{job}'")=='failed'
admin.call('POST','/api/v1/auth/logout',{})
print('PASS authorized failed-job replay persisted second terminal attempt; no fabricated successful provider delivery')
