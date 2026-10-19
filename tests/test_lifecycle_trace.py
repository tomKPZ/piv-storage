"""Reject incomplete or misordered lifecycle evidence, not just failed I/O."""
import unittest
from kernel.lifecycle_trace import check_trace


def trace(events):
    return '\n'.join(f'kworker/0:1-42 [000] ... 1.00: {e}: result=0' for e in events)


class LifecycleTraceTests(unittest.TestCase):
    def test_completion_after_flush(self):
        events = ['worker', 'write', 'flush', 'flush_done', 'write_done', 'endio', 'worker_done']
        self.assertEqual(check_trace(trace(events), 1)['writes'], 1)
        for missing in ('flush', 'flush_done', 'endio', 'worker_done'):
            with self.subTest(missing=missing), self.assertRaises(AssertionError):
                check_trace(trace([e for e in events if e != missing]), 1)

    def test_preflush_precedes_payload(self):
        write = ['worker', 'write', 'flush', 'flush_done', 'write_done', 'endio', 'worker_done']
        flush = ['worker', 'flush', 'flush_done', 'endio', 'worker_done']
        self.assertEqual(check_trace(trace(flush + write), 2)['workers'], 2)
        with self.assertRaises(AssertionError):
            check_trace(trace(write + flush), 2)

    def test_error_or_missing_worker_entry_is_not_evidence(self):
        events = ['worker', 'flush', 'flush_done', 'endio', 'worker_done']
        with self.assertRaises(AssertionError):
            check_trace(trace(events).replace('result=0', 'result=-5'), 3)
        with self.assertRaises(AssertionError):
            check_trace(trace(events[1:]), 3)
