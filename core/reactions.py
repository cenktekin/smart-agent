"""
Autonomous reaction module for Smart-Agent.
Handles defensive actions like process pausing, network blocking, etc.
"""

import os
import signal
import subprocess
from typing import Optional


def pause_process(pid: int) -> bool:
    """Send SIGSTOP to a process to freeze it without killing."""
    try:
        os.kill(pid, signal.SIGSTOP)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def resume_process(pid: int) -> bool:
    """Send SIGCONT to a frozen process to resume it."""
    try:
        os.kill(pid, signal.SIGCONT)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def block_ip(ip: str) -> bool:
    """Block an IP address using iptables (requires sudo/root)."""
    try:
        # Check if ufw is available first (cleaner)
        if subprocess.run(["which", "ufw"], capture_output=True).returncode == 0:
            subprocess.run(["sudo", "ufw", "deny", "from", ip], check=True)
        else:
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        return True
    except Exception:
        return False


def execute_auto_action(threat_type: str, details: dict) -> str:
    """
    Decide and execute an action based on threat type.
    Returns a summary of the action taken.
    """
    action_summary = "No autonomous action taken."
    
    # 1. Security Threats (Reverse Shells, etc.) -> Freeze immediately
    if threat_type == "security_threat":
        pid = details.get("pid")
        if pid and pid != os.getpid():
            if pause_process(pid):
                action_summary = f"SUSPICIOUS PROCESS FROZEN (PID {pid})."
    
    # 2. Port backdoors -> Block IP (if remote IP exists)
    elif threat_type == "new_listening_port":
        # In a real scenario, we might track which IP is trying to connect
        pass

    return action_summary
