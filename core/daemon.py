"""
Daemon loop: continuous learning → baseline → monitoring cycle.
Handles signals, per-snapshot persistence, rich notifications, and autonomous reactions.
"""

import asyncio
import json
import os
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from core.monitor import collect_snapshot
from core.profiler import (
    create_baseline,
    create_baseline_from_store,
    baseline_exists,
    load_baseline,
)
from core.detector import scan
from core.ai_analyzer import analyze_with_ai, AIAnalysisResult
from core.reactions import execute_auto_action
from core.store import (
    append_snapshot,
    snapshot_count,
    clear_snapshots,
    append_scan_result,
)


PID_FILE = Path(__file__).parent.parent / "data" / "daemon.pid"
STATUS_FILE = Path(__file__).parent.parent / "data" / "daemon-status.json"


class DaemonState:
    """Track daemon state and handle graceful shutdown."""

    def __init__(self):
        self.running = True
        self.mode: str = "idle"  # idle | learning | monitoring
        self.started_at: Optional[str] = None
        self.last_event: Optional[str] = None

    def mark(self, event: str):
        self.last_event = event
        self._persist()

    def _persist(self):
        status = {
            "pid": os.getpid(),
            "mode": self.mode,
            "started_at": self.started_at,
            "last_event": self.last_event,
            "last_event_at": datetime.now(timezone.utc).isoformat(),
        }
        STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(STATUS_FILE, "w") as f:
            json.dump(status, f, indent=2, default=str)


# Global state for signal handling
_state = DaemonState()


def _signal_handler(signum, frame):
    """Handle SIGTERM/SIGINT for graceful shutdown."""
    sig_name = signal.Signals(signum).name
    _state.running = False
    _state.mode = "stopped"
    _state.mark(f"Received {sig_name}, shutting down")


def _setup_signals():
    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGHUP, lambda s, f: _state.mark("SIGHUP received"))


def _write_pid():
    """Write PID file. Exit if already running."""
    PID_FILE.parent.mkdir(parents=True, exist_ok=True)

    if PID_FILE.exists():
        try:
            with open(PID_FILE) as f:
                old_pid = int(f.read().strip())
            os.kill(old_pid, 0)
            print(f"[daemon] Already running (PID {old_pid})")
            sys.exit(1)
        except PermissionError:
            try:
                cmdline = (Path(f"/proc/{old_pid}") / "cmdline").read_text()
                if "smart-agent" in cmdline or "daemon-start" in cmdline:
                    print(f"[daemon] Already running (PID {old_pid}, verified via /proc)")
                    sys.exit(1)
                PID_FILE.unlink(missing_ok=True)
            except (FileNotFoundError, PermissionError, OSError):
                PID_FILE.unlink(missing_ok=True)
        except (ProcessLookupError, ValueError):
            PID_FILE.unlink(missing_ok=True)

    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))


def _remove_pid():
    PID_FILE.unlink(missing_ok=True)


def _send_notification(title: str, message: str, action_command: Optional[str] = None):
    """Send desktop notification via notify-send with optional command suggestion."""
    try:
        body = message
        if action_command:
            body += f"\n\n👉 ACTION: {action_command}"
        
        # Escape quotes for shell
        safe_body = body.replace('"', "'")
        os.system(
            f'notify-send "🔍 Smart-Agent" "{title}\n{safe_body}" '
            f'-u critical -t 10000 2>/dev/null'
        )
    except Exception:
        pass


def _interruptible_sleep(seconds: int):
    """Wait for 'seconds', checking 'running' flag every second."""
    for _ in range(seconds):
        if not _state.running:
            break
        time.sleep(1)


def _run_learning_phase(
    target_hours: float = 72,
    interval_minutes: int = 10,
):
    """Phase 1: Collect snapshots until we have enough for a baseline."""
    _state.mode = "learning"
    _state.mark(f"Learning started, target={target_hours}h, interval={interval_minutes}m")
    print(f"[daemon] Learning phase: {target_hours}h target, {interval_minutes}m interval")

    total_snapshots = int((target_hours * 3600) / (interval_minutes * 60))
    interval_seconds = interval_minutes * 60

    while _state.running and snapshot_count() < total_snapshots:
        current = snapshot_count()
        snapshot = collect_snapshot()
        append_snapshot(snapshot)
        _state.mark(f"Snapshot #{current + 1}/{total_snapshots}")

        if (current + 1) % 10 == 0:
            print(f"[daemon] Learning: {current + 1}/{total_snapshots} snapshots")

        if snapshot_count() < total_snapshots and _state.running:
            _interruptible_sleep(interval_seconds)


def _run_monitoring_phase(
    scan_interval_seconds: int = 300,
    silent: bool = False,
):
    """Phase 2: Continuous anomaly detection with autonomous reactions."""
    _state.mode = "monitoring"
    _state.mark(f"Monitoring started, interval={scan_interval_seconds}s, silent={silent}")
    print(f"[daemon] Monitoring phase: scan every {scan_interval_seconds}s{' (silent)' if silent else ''}")

    while _state.running:
        try:
            result = scan()
            result["mode"] = "daemon"
            append_scan_result(result)

            risk_level = result.get("risk_level", "UNKNOWN")
            risk_score = result.get("risk_score", 0)
            _state.mark(f"Scan: {risk_level} ({risk_score})")

            if risk_level == "CRITICAL":
                anomalies = result.get("anomalies", {})
                total = anomalies.get("total_count", 0)
                security_threats = anomalies.get("security_threats", [])
                
                # 1. Run AI analysis first to get expert context
                ai_result: Optional[AIAnalysisResult] = None
                if result.get("requires_ai_analysis"):
                    if not silent:
                        print("[daemon] Running AI analysis...")
                    ai_result = asyncio.run(analyze_with_ai(result))

                # 2. Execute autonomous reaction if it's a security threat
                action_info = ""
                if security_threats:
                    for threat in security_threats:
                        action_summary = execute_auto_action("security_threat", threat)
                        action_info += f"\n[!] {action_summary}"
                        print(f"[daemon] 🛡️ AUTO-ACTION: {action_summary}")

                # 3. Send rich notification
                if not silent:
                    msg = f"{total} anomalies detected.{action_info}"
                    if ai_result:
                        msg = f"{ai_result.EXPLANATION}{action_info}"
                    
                    _send_notification(
                        f"🚨 CRITICAL — Risk {risk_score:.3f}",
                        msg,
                        action_command=ai_result.LOG_COMMAND if ai_result else None
                    )
                
                print(f"[daemon] 🚨 CRITICAL: score={risk_score:.3f}, anomalies={total}")
                if ai_result and not silent:
                    print(f"[daemon] AI: {ai_result.RISK_LEVEL} — {ai_result.EXPLANATION[:100]}")

            elif risk_level == "WARNING":
                if not silent:
                    print(f"[daemon] ⚠ WARNING: score={risk_score:.3f}")

        except Exception as e:
            error_msg = f"Scan error: {e}"
            _state.mark(error_msg)
            print(f"[daemon] ERROR: {error_msg}")

        if _state.running:
            _interruptible_sleep(scan_interval_seconds)


def run_daemon(
    learn_hours: float = 72,
    learn_interval_minutes: int = 10,
    scan_interval_seconds: int = 300,
    silent: bool = False,
):
    """Main daemon entry point."""
    _setup_signals()
    _write_pid()

    _state.started_at = datetime.now(timezone.utc).isoformat()
    _state.running = True

    try:
        if not baseline_exists():
            _run_learning_phase(target_hours=learn_hours, interval_minutes=learn_interval_minutes)
            if _state.running and snapshot_count() > 0:
                create_baseline_from_store()
                clear_snapshots()
        else:
            _state.mark("Skipping learning — baseline already exists")
            print("[daemon] Baseline exists, skipping learning phase")

        if _state.running:
            _run_monitoring_phase(scan_interval_seconds=scan_interval_seconds, silent=silent)

    finally:
        _shutdown()


def _shutdown():
    """Clean shutdown."""
    _state.mode = "stopped"
    _state.mark("Daemon stopped")
    _remove_pid()
    print("[daemon] Stopped")


def stop_daemon():
    """Send SIGTERM to running daemon."""
    if not PID_FILE.exists():
        return False
    try:
        with open(PID_FILE) as f:
            pid = int(f.read().strip())
        os.kill(pid, signal.SIGTERM)
        for _ in range(10):
            try:
                os.kill(pid, 0)
                time.sleep(0.5)
            except ProcessLookupError:
                PID_FILE.unlink(missing_ok=True)
                return True
        return False
    except (ProcessLookupError, ValueError):
        PID_FILE.unlink(missing_ok=True)
        return False


def get_status() -> Optional[dict[str, Any]]:
    """Return daemon status."""
    if not STATUS_FILE.exists(): return None
    try:
        with open(STATUS_FILE) as f: return json.load(f)
    except (json.JSONDecodeError, OSError): return None


def is_running() -> bool:
    """Check if daemon is actually running."""
    if not PID_FILE.exists(): return False
    try:
        with open(PID_FILE) as f:
            pid = int(f.read().strip())
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, ValueError, OSError): return False
