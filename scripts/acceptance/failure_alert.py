#!/usr/bin/env python3
"""Actual worker invalid-intent failure -> durable counter -> live Prometheus alert."""
import json
from pathlib import Path
import subprocess
import urllib.request
import uuid
from e2e import eventually

from common import ROOT, STATE
root=ROOT
fixture=json.loads((STATE/'failure.json').read_text())
for name in ('job_id','event_id','user_id'): uuid.UUID(fixture[name])
base=['kubectl','--context','k3d-sso-remediation','-n','sso-remediation']
primary=subprocess.run(base+['get','cluster.postgresql.cnpg.io','postgres','-o','jsonpath={.status.currentPrimary}'],capture_output=True,text=True,check=True,timeout=15).stdout.strip()
def sql(query):
    result=subprocess.run(base+['exec','-i',primary,'--','psql','-U','postgres','-d','notification_db','-v','ON_ERROR_STOP=1','-At'],input=query+'\n',capture_output=True,text=True,timeout=15)
    assert result.returncode==0,'Disposable terminal-job SQL failed'
    return result.stdout.strip()
job=fixture['job_id']
body=fixture['encrypted_body']
assert all(c.isalnum() or c in '+/=' for c in body)
sql(f"INSERT INTO delivery_jobs(id,event_id,user_id,channel,encrypted_body,message_id) VALUES('{job}','{fixture['event_id']}','{fixture['user_id']}','email','{body}','<{job}@sso.local>')")
eventually('actual worker terminal validation failure',lambda:sql(f"SELECT status||':'||attempts||':'||last_error FROM delivery_jobs WHERE id='{job}'")=='failed:1:invalid_recipient',30)
assert sql(f"SELECT count(*) FROM delivery_attempts WHERE job_id='{job}' AND status='failed'")=='1'
def firing():
    with urllib.request.urlopen('http://localhost:29090/api/v1/alerts',timeout=10) as response: data=json.load(response)
    return any(a['labels'].get('alertname')=='DeliveryFailed' and a['state']=='firing' for a in data['data']['alerts'])
eventually('live first-failure DeliveryFailed alert',firing,90)
print('PASS actual invalid-recipient job failed once; persisted failed attempt caused live DeliveryFailed firing (not SMTP provider failure)')
