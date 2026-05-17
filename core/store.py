"""
Persistent snapshot store using append-only JSONL files.
Crash-safe: each snapshot is written immediately to disk.
"""

import json
import fcntl
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional


DATA_DIR = Path(__file__).parent.parent / "data"
SNAPSHOT_LOG = DATA_DIR / "snapshots.jsonl"
SCAN_LOG = DATA_DIR / "scan-log.jsonl"


def _get_snapshot_path() -> Path:
    """Return the path to the current snapshot log (weekday vs weekend)."""
    # 5: Saturday, 6: Sunday
    is_weekend = datetime.now(timezone.utc).weekday() >= 5
    suffix = "-weekend" if is_weekend else "-weekday"
    return DATA_DIR / f"snapshots{suffix}.jsonl"


def _ensure_data_dir():
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def append_snapshot(snapshot: dict[str, Any]):
    """Append a single snapshot to the current JSONL file (atomic, crash-safe)."""
    _ensure_data_dir()
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        **snapshot,
    }
    path = _get_snapshot_path()
    with open(path, "a") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            f.write(json.dumps(record, default=str) + "\n")
            f.flush()
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


def iter_snapshots(limit: Optional[int] = None, path: Optional[Path] = None) -> Iterator[dict[str, Any]]:
    """Read snapshots from oldest to newest from current or specified path."""
    log_path = path or _get_snapshot_path()
    if not log_path.exists():
        return

    with open(log_path) as f:
        fcntl.flock(f, fcntl.LOCK_SH)
        try:
            lines = f.readlines()
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)

    count = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        yield json.loads(line)
        count += 1
        if limit and count >= limit:
            break


def snapshot_count() -> int:
    """Return total number of stored snapshots for current period."""
    path = _get_snapshot_path()
    if not path.exists():
        return 0
    with open(path) as f:
        return sum(1 for line in f if line.strip())


def clear_snapshots():
    """Remove all stored snapshots for current period."""
    path = _get_snapshot_path()
    if path.exists():
        path.unlink()


def append_scan_result(result: dict[str, Any]):
    """Append a scan result to the scan log."""
    _ensure_data_dir()
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        **result,
    }
    with open(SCAN_LOG, "a") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            f.write(json.dumps(record, default=str) + "\n")
            f.flush()
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


def iter_scan_results(
    limit: Optional[int] = None,
    min_risk: Optional[float] = None,
) -> Iterator[dict[str, Any]]:
    """Read scan results, optionally filtered."""
    if not SCAN_LOG.exists():
        return

    with open(SCAN_LOG) as f:
        fcntl.flock(f, fcntl.LOCK_SH)
        try:
            lines = f.readlines()
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)

    count = 0
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        record = json.loads(line)
        if min_risk is not None and record.get("risk_score", 0) < min_risk:
            continue
        yield record
        count += 1
        if limit and count >= limit:
            break


def latest_scan() -> Optional[dict[str, Any]]:
    """Return the most recent scan result."""
    results = list(iter_scan_results(limit=1))
    return results[0] if results else None


def critical_count() -> int:
    """Return number of CRITICAL scan results."""
    return sum(
        1 for r in iter_scan_results() if r.get("risk_level") == "CRITICAL"
    )


def store_stats() -> dict[str, Any]:
    """Return store statistics."""
    return {
        "snapshot_count": snapshot_count(),
        "snapshot_log": str(SNAPSHOT_LOG),
        "scan_log": str(SCAN_LOG),
        "critical_events": critical_count(),
        "latest_scan": latest_scan(),
    }
