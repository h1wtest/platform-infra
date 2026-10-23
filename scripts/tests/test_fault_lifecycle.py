import pathlib
import signal
import sys
import tempfile
import unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from fault_lifecycle import exclusive


class FaultLifecycleBehavior(unittest.TestCase):
    def test_waiting_backup_acquires_after_other_process_releases(self):
        import subprocess
        import time
        with tempfile.TemporaryDirectory() as directory:
            state = pathlib.Path(directory)
            with subprocess.Popen([sys.executable, '-c', 'import fcntl,sys,time\nwith open(sys.argv[1],"a") as lock:\n fcntl.flock(lock,fcntl.LOCK_EX)\n print("locked",flush=True)\n time.sleep(0.3)', str(state / 'fault.lock')], stdout=subprocess.PIPE, text=True) as child:
                self.assertEqual(child.stdout.readline().strip(), 'locked')
                started = time.monotonic()
                with exclusive(state, timeout=2):
                    self.assertGreaterEqual(time.monotonic() - started, 0.2)
                child.wait(timeout=2)

    def test_waiting_backup_reports_real_lock_timeout(self):
        import subprocess
        import time
        with tempfile.TemporaryDirectory() as directory:
            state = pathlib.Path(directory)
            with subprocess.Popen([sys.executable, '-c', 'import fcntl,sys,time\nwith open(sys.argv[1],"a") as lock:\n fcntl.flock(lock,fcntl.LOCK_EX)\n print("locked",flush=True)\n time.sleep(2)', str(state / 'fault.lock')], stdout=subprocess.PIPE, text=True) as child:
                try:
                    self.assertEqual(child.stdout.readline().strip(), 'locked')
                    started = time.monotonic()
                    with self.assertRaises(RuntimeError):
                        with exclusive(state, timeout=0.2):
                            self.fail('Held lock cannot be acquired')
                    self.assertGreaterEqual(time.monotonic() - started, 0.15)
                finally:
                    child.terminate(); child.wait(timeout=2)

    def test_concurrent_injection_refused_and_lock_released_after_error(self):
        with tempfile.TemporaryDirectory() as directory:
            state = pathlib.Path(directory)
            with self.assertRaises(ValueError):
                with exclusive(state):
                    with self.assertRaises(RuntimeError):
                        with exclusive(state):
                            self.fail('Concurrent fault lock must never be acquired')
                    raise ValueError('injected original fault')
            with exclusive(state):
                pass

    def test_sigterm_triggers_cleanup_and_restores_handler(self):
        with tempfile.TemporaryDirectory() as directory:
            before = signal.getsignal(signal.SIGTERM)
            cleanup = []
            with self.assertRaises(KeyboardInterrupt):
                with exclusive(pathlib.Path(directory)):
                    try:
                        signal.raise_signal(signal.SIGTERM)
                    finally:
                        cleanup.append('owned cleanup executed')
            self.assertEqual(cleanup, ['owned cleanup executed'])
            self.assertEqual(signal.getsignal(signal.SIGTERM), before)


if __name__ == '__main__': unittest.main()
