# Smart-Agent v2.0 "Autonomous Guardian"

System Anomaly Detector and Autonomous Security Agent for CachyOS (Arch-based). 
Integrates **Isolation Forest** anomaly detection with **Hacker Eye** (OpenCode security-master) pattern matching and **Autonomous Response** capabilities.

## Features

- **Autonomous Guardian**: Automatically freezes (SIGSTOP) suspicious processes on critical security threats.
- **Hacker Eye**: 20+ expert-derived attack patterns (Reverse shells, SUID abuse, Persistence, Exfiltration) derived from OpenCode `security-master`.
- **Advanced Noise Reduction (v2.1.2)**: 
  - **Port Filtering**: Ability to ignore specific dynamic ports (MCP, Opencode, etc.).
  - **Smart Whitelist**: Deeply integrated process ignore list (`ignore.json`).
  - **Adaptive Memory Tolerance**: Per-process resource thresholds to prevent false positives from browsers and compilers.
- **AI-powered Analysis**: Senior Security Architect context for critical events (OpenRouter/Groq).
- **Rich Notifications**: Desktop alerts with AI explanation, autonomous action summary, and investigation commands.
- **Adaptive Scan (Burst Mode)**: Risk > 0.7 triggers high-frequency 15s scanning.
- **Learning Phase**: Statistical baseline construction of normal system behavior with time-based profiling (Weekend/Weekday).
- **CachyOS Optimized**: Pre-filtered kernel boosters and low-overhead psutil collection (nice 19).
- **Safety First**: Non-destructive response — freezes processes instead of killing them.

## Risk Scoring & Autonomous Response

| Score Range | Level | Daemon Action |
|-------------|-------|---------------|
| 0.0 – 0.7 | NORMAL | Silent (log only) |
| 0.7 – 0.9 | WARNING | Log with warning flag |
| 0.9 – 1.0 | CRITICAL | Log + Rich Notification + AI Analysis |
| **Security Threat** | **CRITICAL** | **Forced 0.95+ & Autonomous SIGSTOP (Freeze)** |

## Architecture

1. **`monitor.py`**: Collects system snapshots (processes, ports, metrics).
2. **`detector.py`**: Runs Isolation Forest + Hacker Eye pattern scan.
3. **`ai_analyzer.py`**: Triggers LLM for expert context on critical events.
4. **`reactions.py`**: Executes autonomous defense (SIGSTOP/IP-Block).
5. **`daemon.py`**: Orchestrates the entire lifecycle and sends notifications.

## Installation


```fish
cd smart-agent
python -m venv .venv
source .venv/bin/activate.fish
pip install -r requirements.txt
```

## Quick Start (Daemon)

```fish
# Install systemd service
smart-agent export-service

# Reload and start
systemctl --user daemon-reload
systemctl --user enable --now smart-agent.service

# Check status anytime
smart-agent daemon-status

# View logs
smart-agent daemon-logs
smart-agent daemon-logs -l critical -n 10
```

## Commands

### Manual Mode

```fish
# 1. Learn normal behavior
smart-agent learn --duration 72h
smart-agent learn -d 24h -i 5

# 2. Scan for anomalies
smart-agent scan

# 3. View baseline
smart-agent baseline-info

# 4. Test AI
smart-agent ai-test
smart-agent ai-test --provider groq
```

### Daemon Mode

```fish
# Foreground (for testing)
smart-agent daemon-start
smart-agent daemon-start --silent -l 24 -s 300

# Stop
smart-agent daemon-stop

# Status
smart-agent daemon-status

# Logs
smart-agent daemon-logs               # all entries
smart-agent daemon-logs -l critical   # CRITICAL only
smart-agent daemon-logs -l warning    # WARNING + CRITICAL
smart-agent daemon-logs -n 50         # last 50 entries

# Install systemd service
smart-agent export-service
```

## Architecture

```
smart-agent/
├── core/
│   ├── monitor.py      # psutil-based low-overhead collector
│   ├── profiler.py     # Statistical baseline generator
│   ├── detector.py     # Isolation Forest implementation
│   ├── ai_analyzer.py  # LLM Integration (OpenRouter/Groq)
│   ├── store.py        # Append-only JSONL persistent storage
│   └── daemon.py       # Continuous loop with signal handling
├── data/
│   ├── baseline.json       # Normal system state (generated)
│   ├── snapshots.jsonl     # Raw learning snapshots (generated)
│   ├── scan-log.jsonl      # Scan results history (generated)
│   ├── daemon.pid          # PID file (generated)
│   └── daemon-status.json  # Daemon state (generated)
├── cli.py              # Typer entry point
└── requirements.txt    # Dependencies
```

## Daemon Flow

```
Start → [Learning Phase] → Build Baseline → [Monitoring Phase] → SIGTERM
            ↓                    ↓                    ↓
        Snapshots →         baseline.json        scan-log.jsonl
        (JSONL)              (process/port        (append-only,
         ↓                    profiles)             crash-safe)
    clear_snapshots()            ↓                    ↓
    (free disk)            Isolation Forest     risk scoring
                           training             + AI (if CRITICAL)
```

## Risk Scoring

| Score Range | Level | Daemon Action |
|-------------|-------|---------------|
| 0.0 – 0.7 | NORMAL | Silent (log only) |
| 0.7 – 0.9 | WARNING | Log with warning flag |
| 0.9 – 1.0 | CRITICAL | Log + notify-send + AI analysis |
| **Pattern Match** | **CRITICAL** | **Forced 0.95+ for Security Threats** |

## AI Integration

Create a `.env` file (copy from `.env.example`):

```fish
cp .env.example .env
```

Then add your API key:

```
OPENROUTER_API_KEY="your-key"
# or
GROQ_API_KEY="your-key"

# Optional: override default model
LLM_MODEL="anthropic/claude-sonnet-4-20250514"
```

`.env` is gitignored — never committed to version control.

All data sent to LLMs is anonymized (usernames, internal IPs, home paths removed).

## systemd Service

```fish
# Install
smart-agent export-service

# Start
systemctl --user daemon-reload
systemctl --user enable --now smart-agent.service

# Check
systemctl --user status smart-agent
journalctl --user -u smart-agent -f

# Stop
systemctl --user stop smart-agent
systemctl --user disable smart-agent
```

Security features in unit file:
- `NoNewPrivileges=true`
- `ProtectSystem=strict`
- `ProtectHome=read-only`
- `ReadWritePaths=.../data` (scoped access)

## Dependencies

| Package | Purpose |
|---------|---------|
| typer | CLI framework |
| psutil | System/process monitoring |
| scikit-learn | Isolation Forest anomaly detection |
| pandas | Statistical processing |
| rich | Terminal UI |
| pydantic | Data validation |
| httpx | Async HTTP (AI integration) |
| python-dotenv | .env file loading |
