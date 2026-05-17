"""
Statistical baseline generator.
Processes learning snapshots and creates normal system state profiles.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd


BASELINE_PATH = Path(__file__).parent.parent / "data" / "baseline.json"


def _get_baseline_path() -> Path:
    """Return the path to the current baseline (weekday vs weekend)."""
    # 5: Saturday, 6: Sunday
    is_weekend = datetime.now(timezone.utc).weekday() >= 5
    suffix = "-weekend" if is_weekend else "-weekday"
    return Path(__file__).parent.parent / "data" / f"baseline{suffix}.json"


def _extract_system_features(snapshots: list[dict[str, Any]]) -> pd.DataFrame:
    """Extract numerical system metrics from snapshots into DataFrame."""
    rows = []
    for snap in snapshots:
        system = snap.get("system", {})
        rows.append(
            {
                "cpu_percent": system.get("cpu_percent", 0),
                "memory_percent": system.get("memory_percent", 0),
                "memory_available_mb": system.get("memory_available_mb", 0),
                "swap_percent": system.get("swap_percent", 0),
                "disk_usage_percent": system.get("disk_usage_percent", 0),
                "process_count": snap.get("process_count", 0),
                "load_avg_1": system.get("load_avg", [0, 0, 0])[0],
                "load_avg_5": system.get("load_avg", [0, 0, 0])[1],
                "load_avg_15": system.get("load_avg", [0, 0, 0])[2],
                "listening_ports_count": len(snap.get("listening_ports", [])),
                "outbound_connections_count": len(
                    snap.get("outbound_connections", [])
                ),
            }
        )
    return pd.DataFrame(rows)


def _extract_process_profile(snapshots: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Build process frequency profile.
    Tracks which processes are normally running and their typical resource usage.
    """
    process_freq: dict[str, dict[str, Any]] = {}

    for snap in snapshots:
        processes = snap.get("processes", [])
        current_names = set()

        for proc in processes:
            name = proc.get("name", "unknown")
            current_names.add(name)

            if name not in process_freq:
                process_freq[name] = {
                    "occurrences": 0,
                    "total_memory": 0,
                    "total_cpu": 0,
                    "usernames": set(),
                }

            process_freq[name]["occurrences"] += 1
            process_freq[name]["total_memory"] += proc.get("memory_info", 0)
            process_freq[name]["total_cpu"] += proc.get("cpu_percent", 0)
            proc_username = proc.get("username", "unknown")
            if isinstance(process_freq[name]["usernames"], set):
                process_freq[name]["usernames"].add(proc_username)

        for known_proc in process_freq:
            if known_proc not in current_names:
                pass

    result = {}
    snapshot_count = max(len(snapshots), 1)
    for name, stats in process_freq.items():
        occurrences = stats["occurrences"]
        result[name] = {
            "frequency": occurrences / snapshot_count,
            "avg_memory_mb": (stats["total_memory"] / max(occurrences, 1))
            / (1024 * 1024),
            "avg_cpu": stats["total_cpu"] / max(occurrences, 1),
        }

    return result


def _extract_port_profile(snapshots: list[dict[str, Any]]) -> dict[str, Any]:
    """Build normal listening port profile."""
    port_freq: dict[int, int] = {}

    for snap in snapshots:
        ports = snap.get("listening_ports", [])
        for port_info in ports:
            port = port_info.get("local_port", 0)
            port_freq[port] = port_freq.get(port, 0) + 1

    snapshot_count = max(len(snapshots), 1)
    return {
        str(port): count / snapshot_count
        for port, count in port_freq.items()
    }


def create_baseline(
    snapshots: list[dict[str, Any]],
    save_path: Path | None = None,
) -> dict[str, Any]:
    """
    Create a statistical baseline from learning snapshots.
    Returns baseline dict with system stats, process profile, and port profile.
    """
    if not snapshots:
        raise ValueError("No snapshots provided for baseline creation")

    system_df = _extract_system_features(snapshots)

    baseline = {
        "system_stats": {
            "mean": system_df.mean().to_dict(),
            "std": system_df.std().to_dict(),
            "min": system_df.min().to_dict(),
            "max": system_df.max().to_dict(),
        },
        "process_profile": _extract_process_profile(snapshots),
        "port_profile": _extract_port_profile(snapshots),
        "snapshot_count": len(snapshots),
        "created_at": pd.Timestamp.now(tz="UTC").isoformat(),
    }

    target_path = save_path or _get_baseline_path()
    target_path.parent.mkdir(parents=True, exist_ok=True)

    with open(target_path, "w") as f:
        json.dump(baseline, f, indent=2, default=str)

    return baseline


def load_baseline(path: Path | None = None) -> dict[str, Any] | None:
    """Load existing baseline from disk."""
    target_path = path or _get_baseline_path()
    if not target_path.exists():
        # Fallback to generic baseline if time-specific one doesn't exist
        if BASELINE_PATH.exists():
            target_path = BASELINE_PATH
        else:
            return None

    with open(target_path) as f:
        return json.load(f)


def baseline_exists(path: Path | None = None) -> bool:
    """Check if a baseline file exists."""
    target_path = path or _get_baseline_path()
    return target_path.exists() or BASELINE_PATH.exists()


def create_baseline_from_store(
    store_module=None,
    save_path: Path | None = None,
) -> dict[str, Any] | None:
    """
    Build baseline from persistent JSONL store.
    Returns None if no snapshots available.
    """
    if store_module is None:
        from core import store as store_module

    # Get current period snapshots
    snapshots = list(store_module.iter_snapshots())
    if not snapshots:
        return None

    return create_baseline(snapshots, save_path=save_path)
