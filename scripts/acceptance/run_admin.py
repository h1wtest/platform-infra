#!/usr/bin/env python3
"""Read local admin credentials into child environment without printing values."""
import os
from pathlib import Path
import subprocess
import sys
from common import ROOT, STATE
sys.path.insert(0, str(ROOT / 'scripts'))
import env_secrets
root=ROOT
values=env_secrets.load(ROOT/'.local')
env=dict(os.environ,ADMIN_EMAIL=values['admin_email'],ADMIN_PASSWORD=values['admin_password'])
command=[sys.executable,str(Path(__file__).with_name('admin.py')),'--base','https://localhost:8448',
         '--state',str(STATE/'state.json'),'--admin-state',str(STATE/'admin-state.json'),
         '--ca',str(ROOT/'.local/ca.crt'),*sys.argv[1:]]
raise SystemExit(subprocess.run(command,env=env,check=False,timeout=180).returncode)
