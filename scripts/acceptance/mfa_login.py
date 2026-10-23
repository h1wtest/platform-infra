"""Acceptance only: consume one fresh real TOTP counter, never retry rejected factors."""
import fcntl
import json
from pathlib import Path
import time
from e2e import save_state


def login_admin(client, email, password, state_path):
    state_path = Path(state_path)
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    secret = state.get('totp_secret')
    if not secret:
        return client.login(email, password)
    state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with state_path.with_suffix('.mfa.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        # Always cross a boundary: a browser or earlier acceptance may already have consumed current code.
        initial_counter = int(time.time()) // 30
        target = max(initial_counter + 1, int(state.get('last_login_counter', -1)) + 1)
        if target > initial_counter + 1:
            raise RuntimeError('Stored administrator counter is ahead of clock; correct clock/state explicitly')
        deadline = time.monotonic() + 32
        while int(time.time()) // 30 < target:
            if time.monotonic() >= deadline:
                raise RuntimeError('Fresh real TOTP counter deadline exceeded')
            time.sleep(.2)
        # Reserve before request so a crash or rejected request never causes this harness to reuse the counter.
        state['last_login_counter'] = target
        save_state(state_path, state)
        return client.login(email, password, secret)
