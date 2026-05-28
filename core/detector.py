"""
Anomaly detection using Isolation Forest (scikit-learn).
Compares current system state against learned baseline.
"""

import re
import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from core.monitor import collect_snapshot
from core.profiler import load_baseline


FEATURE_COLUMNS = [
    "cpu_percent",
    "memory_percent",
    "memory_available_mb",
    "swap_percent",
    "disk_usage_percent",
    "process_count",
    "load_avg_1",
    "load_avg_5",
    "load_avg_15",
    "listening_ports_count",
    "outbound_connections_count",
]

# ─── Kernel Thread Patterns (always ignored) ─────────────────────────
# Linux kernel threads create transient, dynamically-named processes
# that cause massive false positives if not filtered.
_KERNEL_THREAD_PATTERNS: list[re.Pattern] = [
    re.compile(r"^kworker/"),          # kworker/4:1-mm_percpu_wq, kworker/1:2-events, etc.
    re.compile(r"^kcompactd"),         # kcompactd0
    re.compile(r"^kblockd"),           # kblockd
    re.compile(r"^kdevtmpfs"),         # kdevtmpfs
    re.compile(r"^kintegrityd"),       # kintegrityd
    re.compile(r"^kstrp"),             # kstrp
    re.compile(r"^kswapd"),            # kswapd0
    re.compile(r"^kthreadd"),          # kthreadd
    re.compile(r"^rcu_"),              # rcu_gp, rcu_par_gp, etc.
    re.compile(r"^slub"),              # slub_flushwq
    re.compile(r"^writeback"),         # writeback
    re.compile(r"^nvidia-drm/"),       # nvidia-drm/timeline-*, nvidia-drm/flip-*, etc.
    re.compile(r"^nvidia-modeset/"),   # nvidia-modeset/
    re.compile(r"^jbd2/"),             # jbd2/nvme0n1p2-8
    re.compile(r"^ext4"),              # ext4lazyinit
    re.compile(r"^btrfs-"),            # btrfs-endio, btrfs-delalloc, etc.
    re.compile(r"^xfs"),               # xfs-cil, xfs-reclaim, etc.
    re.compile(r"^irq/"),              # irq/<num>-<device>
    re.compile(r"^scsi"),              # scsi_eh_N, scsi_tmf_N
    re.compile(r"^ata_"),              # ata_sff, ata_piix
    re.compile(r"^krfcommd"),          # krfcommd
    re.compile(r"^ksmd"),              # ksmd, khugepaged
    re.compile(r"^oom_"),              # oom_reaper
    re.compile(r"^khubd"),             # khubd
    re.compile(r"^logwriter"),         # xfs logwriter
    re.compile(r"^cfg80211"),          # cfg80211
    re.compile(r"^mt76"),              # mt76 wifi driver threads
    re.compile(r"^kdmflush"),          # dm- flush threads
    re.compile(r"^cryptd"),            # cryptd
    re.compile(r"^ipv6_addrconf"),     # ipv6_addrconf
    re.compile(r"^kprobe-optimizer"),  # CachyOS booster
    re.compile(r"^dmemcg-booster"),    # CachyOS booster
    re.compile(r"^scx_"),              # CachyOS sched-ext (scx_bpfland, etc.)
    re.compile(r"^foreground_booster"),# CachyOS booster
    re.compile(r"^systemd-"),          # Transient systemd services
    re.compile(r"^\(udev-worker\)"),   # udev workers
    re.compile(r"^nm-dispatcher"),     # NetworkManager dispatcher
]

# Processes where memory spikes are normal behaviour — raise tolerance.
# Maps process name → multiplier (default is 3x baseline).
_HIGH_MEMORY_TOLERANCE: dict[str, float] = {
    "electron": 6.0,
    "QtWebEngineProcess": 8.0,
    "browseros": 8.0,        # Browser app — very variable
    "node-MainThread": 5.0,  # Node.js apps
    "python3": 6.0,
    "python": 6.0,           # Common name on some systems
    "bash": 6.0,
    "gdbus": 6.0,
    "dbus-broker": 5.0,
    "dbus-broker-launch": 5.0,
    "systemd-userwork:": 6.0,
    "kioworker": 5.0,        # KDE IO worker
    "plasmashell": 4.0,
    "kwin_wayland": 4.0,
    "kwin_x11": 4.0,
    "Xorg": 4.0,
    "Xwayland": 4.0,
    "mutter": 4.0,
}

_USER_IGNORE_LIST: set[str] = set()
_USER_IGNORE_PORTS: set[int] = set()

def load_user_ignore_list():
    """Load process names and ports to ignore from data/ignore.json"""
    global _USER_IGNORE_LIST, _USER_IGNORE_PORTS
    ignore_file = Path(__file__).parent.parent / "data" / "ignore.json"
    if ignore_file.exists():
        try:
            with open(ignore_file, "r") as f:
                data = json.load(f)
                _USER_IGNORE_LIST = set(data.get("ignore_processes", []))
                _USER_IGNORE_PORTS = set(data.get("ignore_ports", []))
        except Exception:
            _USER_IGNORE_LIST = set()
            _USER_IGNORE_PORTS = set()

def _is_ignored(name: str) -> bool:
    """Check if a process should be ignored (kernel or user-defined)."""
    if name in _USER_IGNORE_LIST:
        return True
    return any(p.match(name) for p in _KERNEL_THREAD_PATTERNS)

def _is_port_ignored(port: int) -> bool:
    """Check if a port should be ignored."""
    return port in _USER_IGNORE_PORTS


def _is_kernel_thread(name: str) -> bool:
    """Check if a process name matches known kernel thread patterns."""
    return any(p.match(name) for p in _KERNEL_THREAD_PATTERNS)


def _extract_current_features() -> dict[str, float]:
    """Extract numerical features from current system snapshot."""
    snapshot = collect_snapshot()
    system = snapshot.get("system", {})
    load_avg = system.get("load_avg", [0, 0, 0])

    return {
        "cpu_percent": system.get("cpu_percent", 0),
        "memory_percent": system.get("memory_percent", 0),
        "memory_available_mb": system.get("memory_available_mb", 0),
        "swap_percent": system.get("swap_percent", 0),
        "disk_usage_percent": system.get("disk_usage_percent", 0),
        "process_count": snapshot.get("process_count", 0),
        "load_avg_1": load_avg[0] if len(load_avg) > 0 else 0,
        "load_avg_5": load_avg[1] if len(load_avg) > 1 else 0,
        "load_avg_15": load_avg[2] if len(load_avg) > 2 else 0,
        "listening_ports_count": len(snapshot.get("listening_ports", [])),
        "outbound_connections_count": len(snapshot.get("outbound_connections", [])),
    }


# ─── Security Threat Patterns (Hacker Eye) ──────────────────────────
# Patterns derived from OpenCode security-master hack-skills.
# These trigger high-risk scores and mandatory AI analysis.
_SUSPICIOUS_CMDLINE_PATTERNS: list[re.Pattern] = [
    # --- Reverse Shells & Bind Shells ---
    re.compile(r"bash\s+-i\s+>&\s+/dev/tcp/"),           # Classic Reverse Shell
    re.compile(r"nc\s+-[ecl]\s+"),                        # Netcat listeners/backdoors
    re.compile(r"python.*\s+-c\s+.*socket.*connect"),     # Python reverse shell
    re.compile(r"python.*\s+-c\s+.*pty\.spawn"),           # PTY spawning (shell upgrade)
    re.compile(r"socat\s+TCP:.*EXEC:"),                   # Socat reverse shell
    re.compile(r"perl.*\s+-e\s+.*Socket.*connect"),      # Perl reverse shell
    re.compile(r"ruby\s+-rsocket\s+-e"),                  # Ruby reverse shell
    
    # --- Privilege Escalation (GTFOBins & SUID) ---
    re.compile(r"bash\s+-p"),                             # SUID bash (effective UID)
    re.compile(r"sh\s+-p"),                               # SUID sh (effective UID)
    re.compile(r"find\s+.*\s+-exec\s+/bin/sh\s+-p"),      # find SUID abuse
    re.compile(r"python.*\s+-c\s+.*os\.setuid\(0\)"),     # Explicit setuid(0) call
    re.compile(r"LD_PRELOAD="),                           # Library injection / Rootkit
    re.compile(r"LD_LIBRARY_PATH="),                      # Library hijacking
    
    # --- Credential Harvesting & Exfiltration ---
    re.compile(r"cat\s+/etc/shadow"),                     # Reading shadow file
    re.compile(r"grep\s+-r\s+SSH_AUTH_SOCK\s+/proc/"),    # SSH agent hijacking prep
    re.compile(r"find\s+.*\s+-name\s+id_rsa"),            # SSH key hunting
    re.compile(r"base64\s+-d\s+\|\s+bash"),               # Encoded execution
    re.compile(r"curl.*\|\s+bash"),                       # Pipe to bash (risky)
    re.compile(r"wget.*\|\s+bash"),                       # Pipe to bash (risky)
    
    # --- Persistence & Destructive ---
    re.compile(r"echo\s+.*\s+>>\s+/etc/passwd"),          # Unauthorized user creation
    re.compile(r"echo\s+.*\s+>>\s+/etc/shadow"),          # Unauthorized hash injection
    re.compile(r"rm\s+-rf\s+/\s+--no-preserve-root"),     # System wiping
    re.compile(r"find\s+/tmp\s+.*\s+-name\s+agent\."),     # Hunting SSH sockets
    re.compile(r"pkaction\s+--verbose"),                  # PolicyKit enumeration
    
    # --- Suspicious Paths ---
    re.compile(r"/tmp/.*\.sh"),                           # Suspicious execution from /tmp
    re.compile(r"/dev/shm/"),                             # In-memory execution
    re.compile(r"nohup\s+.*&"),                           # Backgrounding unauthorized tasks
]

def _load_cmdline_ignore_patterns() -> set[str]:
    """Load cmdline ignore patterns from ignore.json"""
    ignore_file = Path(__file__).parent.parent / "data" / "ignore.json"
    if ignore_file.exists():
        try:
            with open(ignore_file, "r") as f:
                data = json.load(f)
                return set(data.get("ignore_cmdline_patterns", []))
        except Exception:
            return set()
    return set()

_CMDLINE_IGNORE_PATTERNS: set[str] = set()

def _is_ignored_cmdline(cmdline: str) -> bool:
    """Check if cmdline should be ignored (context-mode, etc.)"""
    global _CMDLINE_IGNORE_PATTERNS
    if not _CMDLINE_IGNORE_PATTERNS:
        _CMDLINE_IGNORE_PATTERNS = _load_cmdline_ignore_patterns()
    for pattern in _CMDLINE_IGNORE_PATTERNS:
        if pattern in cmdline:
            return True
    return False

def _check_security_threats(processes: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Scan command lines for known hacker patterns and malicious intent."""
    threats = []
    for proc in processes:
        cmdline = proc.get("cmdline", "")
        if not cmdline:
            continue
        # Skip ignored cmdline patterns (context-mode, etc.)
        if _is_ignored_cmdline(cmdline):
            continue
            
        for pattern in _SUSPICIOUS_CMDLINE_PATTERNS:
            if pattern.search(cmdline):
                threats.append({
                    "type": "security_threat",
                    "process": proc.get("name", "unknown"),
                    "pid": proc.get("pid"),
                    "details": f"High-risk command pattern detected: {cmdline[:100]}...",
                    "severity": "HIGH"
                })
                break
    return threats


def _check_process_anomalies(
    current_processes: list[dict[str, Any]],
    process_profile: dict[str, Any],
) -> list[dict[str, str]]:
    """Detect unusual processes not in baseline or with abnormal resource usage."""
    anomalies = []
    known_processes = set(process_profile.keys())

    current_process_map: dict[str, dict[str, float]] = {}
    for proc in current_processes:
        name = proc.get("name", "unknown")
        # Skip ignored processes (kernel or user-defined whitelist)
        if _is_ignored(name):
            continue
        if name not in current_process_map:
            current_process_map[name] = {
                "memory": 0,
                "cpu": 0,
                "count": 0,
            }
        current_process_map[name]["memory"] += proc.get("memory_info", 0) / (
            1024 * 1024
        )
        current_process_map[name]["cpu"] += proc.get("cpu_percent", 0)
        current_process_map[name]["count"] += 1

    for proc_name, stats in current_process_map.items():
        if proc_name not in known_processes:
            anomalies.append(
                {
                    "type": "unknown_process",
                    "process": proc_name,
                    "details": f"New process detected: {proc_name}",
                }
            )
        else:
            profile = process_profile[proc_name]
            avg_memory = profile.get("avg_memory_mb", 0)
            multiplier = _HIGH_MEMORY_TOLERANCE.get(proc_name, 3.0)
            if avg_memory > 0 and stats["memory"] > avg_memory * multiplier:
                anomalies.append(
                    {
                        "type": "memory_spike",
                        "process": proc_name,
                        "details": (
                            f"Memory usage {stats['memory']:.1f}MB "
                            f"vs baseline {avg_memory:.1f}MB "
                            f"(threshold: {multiplier}x)"
                        ),
                    }
                )

    return anomalies


def _check_port_anomalies(
    current_ports: list[dict[str, Any]],
    port_profile: dict[str, float],
) -> list[dict[str, str]]:
    """Detect unusual listening ports."""
    anomalies = []
    known_ports = {int(p) for p in port_profile.keys()}

    for port_info in current_ports:
        port = port_info.get("local_port", 0)
        if _is_port_ignored(port):
            continue
        if port not in known_ports:
            anomalies.append(
                {
                    "type": "new_listening_port",
                    "port": port,
                    "details": f"New listening port: {port}",
                }
            )

    return anomalies


def train_and_detect(
    baseline: dict[str, Any] | None = None,
    contamination: float = 0.1,
) -> dict[str, Any]:
    """
    Train Isolation Forest on baseline data and detect anomalies in current state.
    Returns risk score and detailed analysis.
    """
    current_features = _extract_current_features()
    current_df = pd.DataFrame([current_features])

    snapshot = collect_snapshot()
    process_anomalies = []
    port_anomalies = []
    security_threats = _check_security_threats(snapshot.get("processes", []))

    if baseline:
        process_profile = baseline.get("process_profile", {})
        port_profile = baseline.get("port_profile", {})

        process_anomalies = _check_process_anomalies(
            snapshot.get("processes", []), process_profile
        )
        port_anomalies = _check_port_anomalies(
            snapshot.get("listening_ports", []), port_profile
        )

        system_stats = baseline.get("system_stats", {})
        mean_values = system_stats.get("mean", {})
        std_values = system_stats.get("std", {})

        synthetic_data = []
        for col in FEATURE_COLUMNS:
            mean = mean_values.get(col, current_features[col])
            std = std_values.get(col, 1.0)
            if pd.isna(std) or std == 0:
                std = 1.0
            synthetic_data.append(
                np.random.normal(mean, std, 100)
            )

        synthetic_df = pd.DataFrame(
            np.column_stack(synthetic_data), columns=FEATURE_COLUMNS
        )

        X_train = synthetic_df[FEATURE_COLUMNS].values
        X_current = current_df[FEATURE_COLUMNS].values

        model = IsolationForest(
            n_estimators=100,
            contamination=0.02,
            random_state=42,
            n_jobs=-1,
        )
        model.fit(X_train)

        score = model.decision_function(X_current)[0]
        risk_score = float(1 - (score + 1) / 2)
    else:
        process_anomalies = _check_process_anomalies(
            snapshot.get("processes", []), {}
        )
        port_anomalies = _check_port_anomalies(
            snapshot.get("listening_ports", []), {}
        )

        risk_score = 0.5
        if process_anomalies:
            risk_score += min(0.3, len(process_anomalies) * 0.05)
        if port_anomalies:
            risk_score += min(0.2, len(port_anomalies) * 0.05)
        risk_score = min(1.0, risk_score)

    # Force CRITICAL for security threats
    if security_threats:
        risk_score = max(risk_score, 0.95)

    risk_score = max(0.0, min(1.0, risk_score))

    if risk_score < 0.7:
        level = "NORMAL"
    elif risk_score < 0.9:
        level = "WARNING"
    else:
        level = "CRITICAL"

    return {
        "risk_score": round(risk_score, 3),
        "risk_level": level,
        "timestamp": snapshot.get("timestamp"),
        "system_metrics": current_features,
        "anomalies": {
            "process": process_anomalies,
            "ports": port_anomalies,
            "security_threats": security_threats,
            "total_count": len(process_anomalies) + len(port_anomalies) + len(security_threats),
        },
        "requires_ai_analysis": risk_score >= 0.9,
    }


def scan() -> dict[str, Any]:
    """
    Quick scan: load baseline and run detection.
    Main entry point for anomaly detection.
    """
    load_user_ignore_list()
    baseline = load_baseline()
    return train_and_detect(baseline)
