#!/usr/bin/env python3
"""Exercise actual runtime database role limits through psql, no privilege mocks."""
import json
from pathlib import Path
import subprocess
import uuid

from common import ROOT, STATE
root=ROOT
base=['kubectl','--context','k3d-sso-remediation','-n','sso-remediation']
primary=subprocess.run(base+['get','cluster.postgresql.cnpg.io','postgres','-o','jsonpath={.status.currentPrimary}'],capture_output=True,text=True,check=True,timeout=15).stdout.strip()
for owner,table in [('identity','users'),('profile','profiles'),('notification','delivery_jobs'),('audit','audit_events')]:
    def psql(database,query):
        # SET ROLE exercises PostgreSQL's actual runtime grants; application TLS was checked separately.
        return subprocess.run(base+['exec','-i',primary,'--','psql','-U','postgres','-d',database,'-v','ON_ERROR_STOP=1','-At'],input=f'SET ROLE {owner}_runtime;\n'+query+'\n',capture_output=True,text=True,timeout=15)
    allowed=psql(owner+'_db','SELECT count(*) FROM '+table+';')
    assert allowed.returncode==0, f'{owner} runtime cannot read own data'
    forbidden=psql(owner+'_db','CREATE TABLE acceptance_forbidden_'+uuid.uuid4().hex+'(id integer);')
    assert forbidden.returncode!=0 and 'permission denied' in forbidden.stderr.lower(), f'{owner} runtime unexpectedly owns DDL'
    other='identity_db' if owner!='identity' else 'profile_db'
    # CONNECT privilege checked authoritatively by PostgreSQL independent of superuser session.
    query=f"SELECT has_database_privilege('{owner}_runtime','{other}','CONNECT');"
    check=subprocess.run(base+['exec',primary,'--','psql','-U','postgres','-d','postgres','-Atc',query],capture_output=True,text=True,check=True,timeout=15)
    assert check.stdout.strip()=='f', f'{owner} runtime has cross-owner CONNECT'
    print('PASS '+owner+' runtime own data allowed, DDL and cross-owner DB CONNECT denied')
