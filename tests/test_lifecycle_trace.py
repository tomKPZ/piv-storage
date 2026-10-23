"""Reject incomplete or misordered lifecycle evidence, not just failed I/O."""
import unittest
from kernel.lifecycle_trace import check_trace


def trace(events, pid=42):
    return '\n'.join(f'kworker/0:1-{pid} [000] ... 1.00: {e}: result=0' for e in events)


def interleave(*traces):
    """Merge per-PID event lists, given as (pid, events, positions) in global order."""
    lines = []
    for pid, events, positions in traces:
        lines += [(at, f'kworker/u8:1-{pid} [000] ... 1.00: {e}: result=0') for at, e in zip(positions, events)]
    return '\n'.join(line for _, line in sorted(lines))


class LifecycleTraceTests(unittest.TestCase):
    def test_plain_write_has_no_flush(self):
        events = ['worker', 'write', 'write_done', 'endio', 'worker_done']
        self.assertEqual(check_trace(trace(events), 0)['writes'], 1)
        flushed = ['worker', 'write', 'write_done', 'flush', 'flush_done', 'endio', 'worker_done']
        with self.assertRaises(AssertionError):
            check_trace(trace(flushed), 0)

    def test_fua_completion_after_flush(self):
        events = ['worker', 'write', 'write_done', 'flush', 'flush_done', 'endio', 'worker_done']
        self.assertEqual(check_trace(trace(events), 1)['writes'], 1)
        for missing in ('flush', 'flush_done', 'endio', 'worker_done'):
            with self.subTest(missing=missing), self.assertRaises(AssertionError):
                check_trace(trace([e for e in events if e != missing]), 1)
        # The flush must follow the write and precede the completion.
        early = ['worker', 'flush', 'flush_done', 'write', 'write_done', 'endio', 'worker_done']
        late = ['worker', 'write', 'write_done', 'endio', 'flush', 'flush_done', 'worker_done']
        for order in (early, late):
            with self.subTest(order=order), self.assertRaises(AssertionError):
                check_trace(trace(order), 1)

    def test_preflush_precedes_payload(self):
        write = ['worker', 'write', 'write_done', 'flush', 'flush_done', 'endio', 'worker_done']
        flush = ['worker', 'flush', 'flush_done', 'endio', 'worker_done']
        self.assertEqual(check_trace(trace(flush) + '\n' + trace(write, pid=43), 2)['workers'], 2)
        with self.assertRaises(AssertionError):
            check_trace(trace(write, pid=43) + '\n' + trace(flush), 2)
        whole = ['worker', 'flush', 'flush_done', 'write', 'write_done', 'flush', 'flush_done', 'endio',
                 'worker_done']
        self.assertEqual(check_trace(trace(whole), 2)['flush_completions'], 2)

    def test_hidden_write_flushes_inside_pn_write(self):
        inside = ['worker', 'write', 'flush', 'flush_done', 'write_done', 'endio', 'worker_done']
        for mode in (0, 1):
            with self.subTest(mode=mode):
                self.assertEqual(check_trace(trace(inside), mode, hidden=True)['flush_completions'], 1)
        preflush = ['worker', 'flush', 'flush_done', 'write', 'flush', 'flush_done', 'write_done', 'endio',
                    'worker_done']
        self.assertEqual(check_trace(trace(preflush), 2, hidden=True)['flush_completions'], 2)
        # No flush inside pn_write, a second (FUA) flush after it, or a decoy
        # write flushing inside pn_write are all wrong.
        missing = ['worker', 'write', 'write_done', 'endio', 'worker_done']
        after = ['worker', 'write', 'flush', 'flush_done', 'write_done', 'flush', 'flush_done', 'endio',
                 'worker_done']
        for events, mode, hidden in ((missing, 0, True), (after, 1, True), (inside, 0, False)):
            with self.subTest(events=events, hidden=hidden), self.assertRaises(AssertionError):
                check_trace(trace(events), mode, hidden=hidden)

    def test_concurrent_workers_overlap(self):
        read = ['worker', 'endio', 'worker_done']
        write = ['worker', 'write', 'write_done', 'endio', 'worker_done']
        text = interleave((42, read, [0, 3, 6]), (43, write, [1, 2, 4, 5, 7]))
        self.assertEqual(check_trace(text, 0)['workers'], 2)
        # A second entry on one PID before its return is a lost event.
        with self.assertRaises(AssertionError):
            check_trace(interleave((42, read, [0, 3, 6]), (42, write, [1, 2, 4, 5, 7])), 0)

    def test_error_or_missing_worker_entry_is_not_evidence(self):
        events = ['worker', 'flush', 'flush_done', 'endio', 'worker_done']
        with self.assertRaises(AssertionError):
            check_trace(trace(events).replace('result=0', 'result=-5'), 3)
        with self.assertRaises(AssertionError):
            check_trace(trace(events[1:]), 3)
