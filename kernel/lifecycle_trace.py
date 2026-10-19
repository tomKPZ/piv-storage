"""Validate pinned guest kprobe evidence; no keys or block I/O."""
import re


def check_trace(text, mode):
    """Check actual synchronous native worker call order, not timestamps in userspace."""
    workers, active = [], {}
    for line in text.splitlines():
        match = re.search(r'-(\d+)\s+\[\d+\].*?:\s+(worker_done|worker|write_done|write|flush_done|flush|endio):\s*(.*)', line)
        if not match: continue
        pid, event, detail = match.groups()
        if event == 'worker':
            assert not active, 'Ordered native workers overlapped or entry was lost'
            active[pid] = []
        elif pid in active:
            active[pid].append(event)
            if event in ('write_done', 'flush_done'):
                assert re.search(r'result=0\b', detail), line
            if event == 'worker_done': workers.append(active.pop(pid))
    assert workers and not active, text
    writes = [w for w in workers if 'write' in w]
    for w in workers:
        assert 'endio' in w and w[-1] == 'worker_done', w
        depth = 0
        for event in w:
            if event == 'flush': depth += 1
            if event == 'flush_done':
                depth -= 1
                assert depth == 0, w
        assert depth == 0 and w.count('write') == w.count('write_done'), w
        if 'write' in w:
            start, end = w.index('write'), w.index('write_done')
            assert w.count('write') == 1 and end > start, w
            assert 'flush_done' in w[start:end], w
            assert w.index('endio', end) > end, w
    if mode == 3:
        assert not writes and any('flush_done' in w for w in workers), workers
    else:
        assert len(writes) == 1, workers
        if mode == 2:
            # DM may split preflush from the write into a separate native bio.
            before = []
            for w in workers:
                if 'write' in w:
                    before += w[:w.index('write')]
                    break
                before += w
            assert 'flush_done' in before, workers
    return dict(workers=len(workers), writes=len(writes),
                flush_completions=sum(w.count('flush_done') for w in workers))
