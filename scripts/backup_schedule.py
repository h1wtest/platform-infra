"""Install explicit user-owned hourly encrypted backups; never writes root crontab."""
import os
from pathlib import Path
import shutil
import cli


def install():
    if not shutil.which('systemctl'):
        raise RuntimeError('systemd user manager required for scheduled backups; run backup manually until configured')
    cli.run(['systemctl', '--user', 'show-environment'], timeout=10)
    uv = shutil.which('uv') or str(Path.home() / '.local/bin/uv')
    if not Path(uv).is_file():
        raise RuntimeError('Pinned uv 0.13.5 required')
    directory = Path.home() / '.config/systemd/user'
    directory.mkdir(parents=True, exist_ok=True)
    path = str(cli.ROOT).replace('%', '%%')
    environment = (os.environ.get('PATH', '') + ':' + str(Path.home() / 'go/bin')).replace('%', '%%')
    service = f'[Unit]\nDescription=SSO remediation encrypted local logical backup\n[Service]\nType=oneshot\nWorkingDirectory={path}\nEnvironment="PATH={environment}"\nExecStart={uv} run --no-project python {path}/scripts/cli.py backup\nUMask=0077\nTimeoutStartSec=1800\n'
    timer = '[Unit]\nDescription=Hourly SSO remediation encrypted backup\n[Timer]\nOnCalendar=hourly\nPersistent=true\nRandomizedDelaySec=60\n[Install]\nWantedBy=timers.target\n'
    (directory / 'sso-remediation-backup.service').write_text(service)
    (directory / 'sso-remediation-backup.timer').write_text(timer)
    cli.run(['systemctl', '--user', 'daemon-reload'])
    cli.run(['systemctl', '--user', 'enable', '--now', 'sso-remediation-backup.timer'])
    cli.run(['systemctl', '--user', 'is-active', '--quiet', 'sso-remediation-backup.timer'])
    print('Hourly user backup timer active. Host/user manager availability is required. No PITR or remote durability claimed.')
