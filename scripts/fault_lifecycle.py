"""Serialize destructive local probes; cancellation becomes an exception so owned cleanup can run."""
from contextlib import contextmanager
import fcntl
import json
import signal
import time


@contextmanager
def exclusive(state, timeout=0):
    state.mkdir(exist_ok=True, mode=0o700)
    with (state / 'fault.lock').open('a') as lock:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError as error:
                if time.monotonic() >= deadline:
                    raise RuntimeError('Another fault workflow is active; exclusive operation deadline exceeded') from error
                time.sleep(min(0.1, max(0, deadline - time.monotonic())))
        previous = signal.getsignal(signal.SIGTERM)
        def cancel(signum, frame):
            raise KeyboardInterrupt('Fault workflow cancelled; waiting for safe owned cleanup')
        signal.signal(signal.SIGTERM, cancel)
        try:
            yield
        finally:
            signal.signal(signal.SIGTERM, previous)
            fcntl.flock(lock, fcntl.LOCK_UN)


def wait_writable(runtime, timeout=360):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        cluster = json.loads(runtime.kube('get', 'cluster.postgresql.cnpg.io', 'postgres', '-o', 'json').stdout)
        name = cluster.get('status', {}).get('currentPrimary')
        cluster_ready = any(item['type'] == 'Ready' and item['status'] == 'True' for item in cluster.get('status', {}).get('conditions', []))
        if name and name == cluster.get('status', {}).get('targetPrimary') and cluster_ready:
            observed = runtime.kube('get', 'pod', name, '-o', 'json', check=False)
            if observed.returncode:
                time.sleep(2)
                continue
            pod = json.loads(observed.stdout)
            ready = any(item['type'] == 'Ready' and item['status'] == 'True' for item in pod['status'].get('conditions', []))
            if not pod['metadata'].get('deletionTimestamp') and ready:
                result = runtime.kube('exec', name, '--', 'psql', '-U', 'postgres', '-Atqc', 'SELECT NOT pg_is_in_recovery()', check=False, timeout=10)
                if result.returncode == 0 and result.stdout.strip() == b't':
                    return name
        time.sleep(2)
    raise RuntimeError('No stable Ready writable PostgreSQL primary before fault recovery deadline')
