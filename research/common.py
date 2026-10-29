"""Bounded, typed research oracle and machine-readable experiment evidence."""

import ctypes as C
import hashlib
import json
from pathlib import Path
import platform
import random
import resource
import subprocess
import sys
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import reference as ref
from verify import Context, U8, array, load_library, require


class BudgetExceeded(RuntimeError):
    pass


def fingerprints():
    paths = [*ROOT.glob("src/*.[ch]"), *ROOT.glob("include/*.h"),
             *ROOT.glob("tests/*.[ch]"), *ROOT.glob("tests/*.py"),
             *ROOT.glob("research/*.py"), *ROOT.glob("research/*.[ch]"), *ROOT.glob("research/requirements*.txt"),
             ROOT / "docs/spec_ko.md", ROOT / "Makefile"]
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(set(paths))}


class Session:
    def __init__(self, seed, max_queries=1 << 24, seconds=120):
        if max_queries < 0 or seconds <= 0:
            raise ValueError("invalid experiment budget")
        self.seed, self.max_queries, self.seconds = seed, max_queries, seconds
        self.source_identity = fingerprints()
        self.binary_identity = hashlib.sha256((ROOT / "build/verify.so").read_bytes()).hexdigest()
        self.git_identity = subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip()
        self.started = time.perf_counter()
        self.queries = 0
        self.ledger = {}

    def reserve(self, count, rounds, inverse):
        if type(count) is not int or count < 0 or type(rounds) is not int or not 0 <= rounds <= 28 or type(inverse) is not bool:
            raise ValueError("invalid query ledger entry")
        if self.queries + count > self.max_queries:
            raise BudgetExceeded("block-query budget exhausted")
        if time.perf_counter() - self.started > self.seconds:
            raise BudgetExceeded("cooperative wall-time budget exhausted")
        self.queries += count
        label = f"{'inverse' if inverse else 'forward'}/{rounds}"
        self.ledger[label] = self.ledger.get(label, 0) + count

    def save(self, name, result, path=None):
        sources = fingerprints()
        require(sources == self.source_identity,"sources changed during experiment")
        binary = hashlib.sha256((ROOT / "build/verify.so").read_bytes()).hexdigest()
        require(binary == self.binary_identity,"binary changed during experiment")
        head = subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip()
        require(head == self.git_identity,"git head changed during experiment")
        if time.perf_counter()-self.started > self.seconds:
            raise BudgetExceeded("cooperative wall-time budget exhausted before report publication")
        document = {"experiment": name, "seed": hex(self.seed), "platform": platform.platform(),
                    "python": platform.python_version(), "source_sha256": sources,
                    "binary_sha256": binary,
                    "git_head": head,
                    "git_worktree_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
                    "wall_seconds": time.perf_counter() - self.started,
                    "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                    "query_budget": self.max_queries, "oracle_queries": self.queries,
                    "query_ledger": self.ledger, "cooperative_seconds_budget": self.seconds,
                    "status": "completed", "result": result}
        if platform.system() == "Darwin":
            document["peak_rss_kib"] /= 1024
        path = Path(path) if path is not None else ROOT / "build" / f"{name}.json"
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(json.dumps(document, indent=2) + "\n")
        label = path.relative_to(ROOT) if path.is_relative_to(ROOT) else path
        print(f"{name}: queries={self.queries}, wall={document['wall_seconds']:.3f}s, "
              f"peak={document['peak_rss_kib']}KiB -> {label}")
        return document


class Oracle:
    def __init__(self, session, key, lib=None):
        if len(key) != 32:
            raise ValueError("key must be exactly 32 bytes")
        self.session, self.lib = session, lib or load_library()
        self.ctx, self.closed = Context(), False
        require(self.lib.interlock_init(C.byref(self.ctx), array(key), 32) == 0, "oracle init")

    def blocks(self, data, rounds, inverse=False):
        if self.closed or type(rounds) is not int or not 0 <= rounds <= 28 or len(data) % 16 or type(inverse) is not bool:
            raise ValueError("closed oracle, invalid rounds or block length")
        count = len(data) // 16
        if count > 1 << 17:
            raise ValueError("one batch may contain at most 131072 blocks")
        self.session.reserve(count, rounds, bool(inverse))
        output = (U8 * len(data))()
        require(self.lib.il_test_batch(C.byref(self.ctx), output, array(data), count, rounds, bool(inverse)) == 0,
                "research batch rejected")
        return bytes(output)

    def close(self):
        if not self.closed:
            self.lib.interlock_clear(C.byref(self.ctx))
            self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def difference_counts(pairs, block_bytes=16, lib=None):
    if not 1 <= block_bytes <= 16 or len(pairs) % (2*block_bytes):
        raise ValueError("complete pairs of 1..16-byte outputs required")
    lib = lib or load_library()
    counts = (C.c_uint64 * (8*block_bytes))()
    require(lib.il_test_diff_counts(counts,array(pairs),len(pairs)//(2*block_bytes),block_bytes) == 0,
            "difference counter")
    return list(counts)


def check():
    session = Session(0x4f5241434c45, max_queries=512)
    rng = random.Random(session.seed)
    key, blocks = rng.randbytes(32), rng.randbytes(64)
    traces = [ref.trace(key, blocks[i:i+16])[1] for i in range(0, 64, 16)]
    with Oracle(session, key) as oracle:
        for rounds in range(29):
            output = oracle.blocks(blocks, rounds)
            expected = b"".join(b"".join(w.to_bytes(4, "little") for w in t[rounds]) for t in traces)
            require(output == expected, f"batch independent prefix {rounds}")
            require(oracle.blocks(output, rounds, True) == blocks, f"inverse prefix {rounds}")
        for data, rounds in ((b"x", 1), (bytes(16), -1), (bytes(16), 29)):
            try:
                oracle.blocks(data, rounds)
            except ValueError:
                pass
            else:
                raise AssertionError("oracle must reject invalid input")
    require(bytes(oracle.ctx) == bytes(C.sizeof(Context)), "oracle context erased")
    limited = Session(1, max_queries=1)
    with Oracle(limited, bytes(32)) as oracle:
        try:
            oracle.blocks(bytes(32), 1)
        except BudgetExceeded:
            pass
        else:
            raise AssertionError("query limit must stop before a batch")
    require(limited.queries == 0, "rejected batch must consume no queries")
    for count,rounds,inverse in ((-1,0,False),(1,-1,False),(1,29,False),(1,1.5,False),(1,1,2)):
        try:
            limited.reserve(count,rounds,inverse)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid ledger entries must be rejected")
    require(limited.queries == 0, "invalid ledger entries must change no counts")
    changed = dict(session.source_identity)
    changed["research/benchmark.c"] = "0"*64
    with patch(__name__+".fingerprints",return_value=changed):
        try:
            session.save("rejected_changed_source",{})
        except AssertionError:
            pass
        else:
            raise AssertionError("mid-experiment source drift must prevent publication")
    expired = Session(1,seconds=1)
    expired.started -= 2
    try:
        expired.save("rejected_expired",{})
    except BudgetExceeded:
        pass
    else:
        raise AssertionError("zero-query expired experiments must not publish")
    session.save("oracle", {"prefixes_checked": 29, "blocks_per_prefix": 4,
                            "inverse_model": "inverse of the first r rounds, not the last r rounds",
                            "production_api": "unchanged, fixed 28 rounds"})


if __name__ == "__main__":
    check()
