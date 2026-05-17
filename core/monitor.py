"""
Low-overhead system state collector using psutil.
Collects process trees, network connections, and system metrics.
"""

import os
import time
from datetime import datetime, timezone
from typing import Any

import psutil


def _safe_process_info(proc: psutil.Process) -> dict[str, Any] | None:
    """Safely extract process info with permission error handling."""
    try:
        with proc.oneshot():
            return {
                "pid": proc.pid,
                "ppid": proc.ppid(),
                "name": proc.name(),
                "username": proc.username(),
                "status": proc.status(),
                "nice": proc.nice(),
                "create_time": proc.create_time(),
                "memory_info": proc.memory_info().rss,
                "cpu_percent": proc.cpu_percent(interval=0.0),
                "cmdline": " ".join(proc.cmdline()),
            }
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
        return None


def collect_process_tree() -> list[dict[str, Any]]:
    """Collect all running processes with parent-child relationships."""
    processes = []
    for proc in psutil.process_iter():
        info = _safe_process_info(proc)
        if info:
            processes.append(info)
    return processes


def collect_open_ports() -> list[dict[str, Any]]:
    """Collect listening ports and associated process info (LSOF style)."""
    connections = []
    net_connections = psutil.net_connections(kind="inet")

    for conn in net_connections:
        if conn.status == psutil.CONN_LISTEN and conn.laddr:
            conn_info = {
                "local_ip": conn.laddr.ip,
                "local_port": conn.laddr.port,
                "pid": conn.pid,
            }

            if conn.pid:
                try:
                    proc = psutil.Process(conn.pid)
                    conn_info["process_name"] = proc.name()
                    conn_info["username"] = proc.username()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    conn_info["process_name"] = "unknown"
                    conn_info["username"] = "unknown"

            connections.append(conn_info)

    return connections


def collect_outbound_connections() -> list[dict[str, Any]]:
    """Collect established outbound connections with remote IPs."""
    connections = []
    net_connections = psutil.net_connections(kind="inet")

    for conn in net_connections:
        if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
            conn_info = {
                "local_ip": conn.laddr.ip if conn.laddr else None,
                "local_port": conn.laddr.port if conn.laddr else None,
                "remote_ip": conn.raddr.ip,
                "remote_port": conn.raddr.port,
                "pid": conn.pid,
            }

            if conn.pid:
                try:
                    proc = psutil.Process(conn.pid)
                    conn_info["process_name"] = proc.name()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    conn_info["process_name"] = "unknown"

            connections.append(conn_info)

    return connections


def collect_system_metrics() -> dict[str, Any]:
    """Collect overall system resource metrics."""
    return {
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "cpu_count": psutil.cpu_count(logical=True),
        "memory_percent": psutil.virtual_memory().percent,
        "memory_available_mb": psutil.virtual_memory().available / (1024 * 1024),
        "swap_percent": psutil.swap_memory().percent,
        "disk_usage_percent": psutil.disk_usage("/").percent,
        "boot_time": psutil.boot_time(),
        "load_avg": list(os.getloadavg()),
    }


def collect_snapshot() -> dict[str, Any]:
    """
    Collect a complete system snapshot.
    Sets process priority to 19 (lowest) to minimize system impact.
    """
    os.nice(19)

    try:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "system": collect_system_metrics(),
            "processes": collect_process_tree(),
            "listening_ports": collect_open_ports(),
            "outbound_connections": collect_outbound_connections(),
            "process_count": len(psutil.pids()),
        }
    finally:
        os.nice(0)


def run_learning_cycle(
    duration_hours: float,
    interval_minutes: int = 10,
    progress_callback=None,
) -> list[dict[str, Any]]:
    """
    Run continuous learning for specified duration.
    Collects snapshots at regular intervals.
    """
    snapshots = []
    total_seconds = duration_hours * 3600
    interval_seconds = interval_minutes * 60
    iterations = int(total_seconds / interval_seconds)

    if progress_callback:
        progress_callback(0, iterations)

    for i in range(iterations):
        snapshot = collect_snapshot()
        snapshots.append(snapshot)

        if progress_callback:
            progress_callback(i + 1, iterations)

        if i < iterations - 1:
            time.sleep(interval_seconds)

    return snapshots
