"""Validate pinned guest kprobe evidence; no keys or block I/O."""
import re


def check_trace(text, mode):
    """Check the actual native worker call order in a globally ordered trace.

    Workers run concurrently on an unbound workqueue, so different kworkers may
    overlap; one kworker runs one work item at a time, so events are grouped per
    PID. Expected ordering (mode: 0 plain, 1 FUA, 2 PREFLUSH|FUA, 3 flush):
    a plain write completes without any flush; a FUA write completes only
    after a successful flush that follows its write; a PREFLUSH payload starts
    only after a successful flush (possibly in a separate DM-split flush bio);
    a standalone flush reaches a native worker.
    """
    workers, active = [], {}
    for position, line in enumerate(text.splitlines()):
        match = re.search(r'-(\d+)\s+\[\d+\].*?:\s+(worker_done|worker|write_done|write|flush_done|flush|endio):\s*(.*)', line)
        if not match: continue
        pid, event, detail = match.groups()
        if event == 'worker':
            assert pid not in active, 'A native worker entry lost its return event'
            active[pid] = []
        elif pid in active:
            active[pid].append((position, event))
            if event in ('write_done', 'flush_done'):
                assert re.search(r'result=0\b', detail), line
            if event == 'worker_done': workers.append(active.pop(pid))
    assert workers and not active, text
    names = [[event for _, event in w] for w in workers]
    for w in names:
        assert 'endio' in w and w[-1] == 'worker_done', w
        depth = 0
        for event in w:
            if event == 'flush': depth += 1
            if event == 'flush_done':
                depth -= 1
                assert depth == 0, w
        assert depth == 0 and w.count('write') == w.count('write_done') <= 1, w
        if 'write' in w:
            start, end = w.index('write'), w.index('write_done')
            assert end > start and w.index('endio', end) > end, w
            # View writes never flush inside pn_write (no A/B in this fixture).
            assert 'flush' not in w[start:end], w
    writes = [w for w in workers if 'write' in [e for _, e in w]]
    if mode == 3:
        assert not writes and any('flush_done' in w for w in names), names
    else:
        assert len(writes) == 1, names
        w = [event for _, event in writes[0]]
        after = w[w.index('write_done'):w.index('endio')]
        if mode == 0:
            assert 'flush' not in w, w
        else:
            assert 'flush_done' in after, w
        if mode == 2:
            # DM may split the preflush into a separate native bio; the trace is
            # globally ordered, so any completed flush must precede the write.
            write_at = next(position for position, event in writes[0] if event == 'write')
            assert any(event == 'flush_done' and position < write_at
                       for worker in workers for position, event in worker), names
    return dict(workers=len(workers), writes=len(writes),
                flush_completions=sum(w.count('flush_done') for w in names))
