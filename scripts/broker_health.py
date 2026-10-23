"""Authoritative broker cluster health, not TCP/pod readiness."""
import json
import time


def wait_healthy(runtime, timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = runtime.kube('exec', 'redpanda-0', '--', 'rpk', 'cluster', 'health', '--format', 'json', check=False, timeout=15)
        if result.returncode not in (0, 10):
            raise RuntimeError('Redpanda health query failed, not a healthy/unhealthy report')
        report = json.loads(result.stdout)
        healthy = report.get('is_healthy', report.get('healthy'))
        under = report.get('under_replicated_partitions')
        leaderless = report.get('leaderless_partitions')
        down = report.get('nodes_down')
        def empty(value):
            return value == 0 or value == []
        if healthy is True and empty(under) and empty(leaderless) and empty(down):
            return report
        time.sleep(2)
    raise RuntimeError('Broker recovery deadline exceeded: require healthy cluster, zero under-replicated/leaderless partitions and no nodes down')
