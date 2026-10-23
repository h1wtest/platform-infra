"""Throttling and failed requests must never masquerade as registration capacity."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'acceptance'))
from registration_benchmark import summarize


class RegistrationBenchmarkAccounting(unittest.TestCase):
    def test_fast_throttles_do_not_reduce_success_latency_or_inflate_throughput(self):
        samples = [
            {'status': 201, 'outcome': 'created', 'latency_ms': 100},
            {'status': 201, 'outcome': 'created', 'latency_ms': 300},
            *[{'status': 429, 'outcome': 'rate_limited', 'latency_ms': 1} for _ in range(20)],
            {'status': 503, 'outcome': 'http_error', 'latency_ms': 50},
            {'status': None, 'outcome': 'transport_error', 'latency_ms': 15000},
        ]
        report = summarize(samples, 4)
        self.assertEqual(report['successes'], 2)
        self.assertEqual(report['rate_limited'], 20)
        self.assertEqual(report['errors'], 2)
        self.assertEqual(report['registrations_per_second'], .5)
        self.assertEqual(report['attempts_per_second'], 6)
        self.assertEqual(report['successful_latency_ms']['p95'], 300)
        self.assertEqual(report['http_status_counts'], {'201': 2, '429': 20, '503': 1})
        self.assertEqual(report['outcome'], 'failed')

    def test_all_throttled_run_has_no_success_percentiles_and_is_blocked(self):
        report = summarize([{'status': 429, 'outcome': 'rate_limited', 'latency_ms': 2}], .1)
        self.assertEqual(report['outcome'], 'blocked')
        self.assertIsNone(report['successful_latency_ms'])
        self.assertEqual(report['registrations_per_second'], 0)
        self.assertEqual(report['errors'], 0)

    def test_invalid_created_response_is_not_a_success(self):
        report = summarize([{'status': 201, 'outcome': 'invalid_response', 'latency_ms': 10}], 1)
        self.assertEqual(report['successes'], 0)
        self.assertEqual(report['errors'], 1)
        self.assertEqual(report['outcome'], 'failed')


if __name__ == '__main__':
    unittest.main()
