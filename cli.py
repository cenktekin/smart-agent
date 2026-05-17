"""
Smart-Agent CLI - System Anomaly Detector for CachyOS.
Lightweight, local-first analysis with AI-as-a-judge for high-risk events.
"""

import asyncio
import json
import subprocess
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table

from core.monitor import run_learning_cycle
from core.profiler import create_baseline, load_baseline, baseline_exists
from core.detector import scan
from core.ai_analyzer import analyze_with_ai
from core import store as scan_store


app = typer.Typer(
    name="smart-agent",
    help="System Anomaly Detector for CachyOS",
    add_completion=False,
)
console = Console()


def _format_risk_score(score: float) -> str:
    """Format risk score with color coding."""
    if score < 0.7:
        return f"[green]{score:.3f}[/green]"
    elif score < 0.9:
        return f"[yellow]{score:.3f}[/yellow]"
    else:
        return f"[red]{score:.3f}[/red]"


def _display_scan_result(result: dict):
    """Display scan results with rich formatting."""
    risk_level = result.get("risk_level", "UNKNOWN")
    risk_score = result.get("risk_score", 0)

    if risk_level == "NORMAL":
        color = "green"
        icon = "✓"
    elif risk_level == "WARNING":
        color = "yellow"
        icon = "⚠"
    else:
        color = "red"
        icon = "🚨"

    console.print()
    console.print(
        Panel(
            f"[bold {color}]{icon} {risk_level}[/bold {color}]\n"
            f"Risk Score: {_format_risk_score(risk_score)}",
            title="Smart-Agent Analysis Result",
            border_style=color,
        )
    )

    anomalies = result.get("anomalies", {})
    process_anomalies = anomalies.get("process", [])
    port_anomalies = anomalies.get("ports", [])
    security_threats = anomalies.get("security_threats", [])

    if process_anomalies or port_anomalies or security_threats:
        table = Table(title="Detected Anomalies", show_header=True)
        table.add_column("Type", style="cyan")
        table.add_column("Details", style="white")

        for threat in security_threats:
            table.add_row("[bold red]Security Threat[/bold red]", f"[red]{threat.get('details', 'N/A')}[/red]")

        for anomaly in process_anomalies:
            table.add_row("Process", anomaly.get("details", "N/A"))

        for anomaly in port_anomalies:
            table.add_row("Port", anomaly.get("details", "N/A"))

        console.print()
        console.print(table)

    if result.get("requires_ai_analysis"):
        console.print()
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]AI Analysis in progress...[/bold blue]"),
            BarColumn(),
            console=console,
        ) as progress:
            progress.add_task("", total=100)

        ai_result = asyncio.run(analyze_with_ai(result))

        if ai_result:
            console.print()
            console.print(
                Panel(
                    f"[bold]Risk Level:[/bold] {ai_result.RISK_LEVEL}\n\n"
                    f"[bold]Explanation:[/bold]\n{ai_result.EXPLANATION}\n\n"
                    f"[bold]Investigation Command:[/bold]\n"
                    f"[cyan]{ai_result.LOG_COMMAND}[/cyan]",
                    title="🤖 AI Analysis",
                    border_style="blue",
                )
            )

    console.print()


@app.command()
def learn(
    duration: str = typer.Option(
        "72h",
        "--duration",
        "-d",
        help="Learning duration (e.g., 72h, 24h, 2h)",
    ),
    interval: int = typer.Option(
        10,
        "--interval",
        "-i",
        help="Snapshot interval in minutes",
    ),
):
    """
    Learn normal system behavior to build a baseline.

    Examples (Fish Shell):
        smart-agent learn --duration 72h
        smart-agent learn -d 24h -i 5
    """
    hours_str = duration.rstrip("hH")
    try:
        hours = float(hours_str)
    except ValueError:
        console.print("[red]Error:[/red] Invalid duration format. Use e.g. '72h', '24h'")
        raise typer.Exit(1)

    if hours < 0.5:
        console.print("[red]Error:[/red] Minimum duration is 0.5h (30 minutes)")
        raise typer.Exit(1)

    console.print(
        f"[bold blue]Starting learning phase[/bold blue]\n"
        f"Duration: {hours} hours | Interval: {interval} minutes"
    )

    snapshots = []

    def progress_callback(current, total):
        pct = current / max(total, 1) * 100
        console.print(
            f"\rProgress: {current}/{total} snapshots ({pct:.1f}%)",
            end="",
        )

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]Collecting system snapshots...[/bold blue]"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task("", total=100)

            def update_progress(current, total):
                pct = current / max(total, 1) * 100
                progress.update(task, completed=pct)

            snapshots = run_learning_cycle(
                duration_hours=hours,
                interval_minutes=interval,
                progress_callback=update_progress,
            )

        if snapshots:
            baseline = create_baseline(snapshots)
            console.print()
            console.print(
                Panel(
                    f"[green]✓[/green] Baseline created successfully\n"
                    f"Snapshots collected: {baseline['snapshot_count']}\n"
                    f"Created at: {baseline['created_at']}",
                    title="Learning Complete",
                    border_style="green",
                )
            )
        else:
            console.print("[red]Error:[/red] No snapshots collected")
            raise typer.Exit(1)

    except KeyboardInterrupt:
        if snapshots:
            console.print("\n[yellow]Learning interrupted. Saving partial baseline...[/yellow]")
            baseline = create_baseline(snapshots)
            console.print(
                f"[green]✓[/green] Partial baseline saved ({len(snapshots)} snapshots)"
            )
        else:
            console.print("\n[red]Learning cancelled. No data to save.[/red]")
        raise typer.Exit(1)


@app.command(name="scan")
def scan_cmd():
    """
    Scan current system state for anomalies.

    Examples (Fish Shell):
        smart-agent scan
    """
    if not baseline_exists():
        console.print(
            "[yellow]No baseline found.[/yellow] "
            "Run [bold]smart-agent learn[/bold] first to establish normal behavior."
        )
        raise typer.Exit(1)

    baseline = load_baseline()
    if baseline:
        snapshot_count = baseline.get("snapshot_count", 0)
        created_at = baseline.get("created_at", "unknown")
        console.print(
            f"[dim]Baseline: {snapshot_count} snapshots, created {created_at}[/dim]"
        )

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]Analyzing system state...[/bold blue]"),
        console=console,
    ):
        result = scan()

    _display_scan_result(result)


@app.command()
def baseline_info():
    """
    Show information about the current baseline.

    Examples (Fish Shell):
        smart-agent baseline-info
    """
    if not baseline_exists():
        console.print("[yellow]No baseline found.[/yellow]")
        console.print("Run [bold]smart-agent learn[/bold] to create one.")
        raise typer.Exit(0)

    baseline = load_baseline()
    if not baseline:
        console.print("[red]Error:[/red] Could not load baseline")
        raise typer.Exit(1)

    table = Table(title="Baseline Information")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Created", baseline.get("created_at", "N/A"))
    table.add_row("Snapshots", str(baseline.get("snapshot_count", 0)))
    table.add_row("Known Processes", str(len(baseline.get("process_profile", {}))))
    table.add_row("Known Ports", str(len(baseline.get("port_profile", {}))))

    console.print(table)

    stats = baseline.get("system_stats", {})
    mean_values = stats.get("mean", {})

    if mean_values:
        console.print()
        console.print(
            Panel(
                "\n".join(
                    f"{k}: {v:.2f}"
                    for k, v in mean_values.items()
                ),
                title="Average System Metrics",
                border_style="blue",
            )
        )


@app.command()
def version():
    """Show version information."""
    console.print("Smart-Agent v1.0.0")
    console.print("System Anomaly Detector for CachyOS")
    console.print("[dim]Local-first analysis with AI-as-a-judge[/dim]")


@app.command()
def ai_test(
    provider: Optional[str] = typer.Option(
        None,
        "--provider",
        "-p",
        help="LLM provider (openrouter, groq)",
    ),
):
    """
    Test AI analysis with current system state.
    Useful for verifying LLM integration is configured correctly.

    Examples (Fish Shell):
        smart-agent ai-test
        smart-agent ai-test --provider groq
    """
    console.print("[bold blue]Running AI analysis test...[/bold blue]")

    result = scan()
    result["requires_ai_analysis"] = True

    ai_result = asyncio.run(analyze_with_ai(result, provider=provider))

    if ai_result:
        console.print(
            Panel(
                f"[bold]Risk Level:[/bold] {ai_result.RISK_LEVEL}\n\n"
                f"[bold]Explanation:[/bold]\n{ai_result.EXPLANATION}\n\n"
                f"[bold]Investigation Command:[/bold]\n"
                f"[cyan]{ai_result.LOG_COMMAND}[/cyan]",
                title="🤖 AI Analysis Test",
                border_style="green",
            )
        )
    else:
        console.print(
            "[yellow]AI analysis not available.[/yellow]\n"
            "Set OPENROUTER_API_KEY or GROQ_API_KEY environment variable."
        )


# ─── Daemon Commands ─────────────────────────────────────────────


@app.command(name="daemon-start")
def daemon_start(
    learn_hours: float = typer.Option(72, "--learn-hours", "-l", help="Learning duration in hours"),
    learn_interval: int = typer.Option(10, "--learn-interval", "-i", help="Snapshot interval in minutes"),
    scan_interval: int = typer.Option(300, "--scan-interval", "-s", help="Scan interval in seconds"),
    silent: bool = typer.Option(
        False,
        "--silent",
        help="Silent mode: no notifications, no AI analysis, log only",
    ),
):
    """
    Start the daemon in the foreground.
    Learns system behavior, builds baseline, then monitors continuously.

    Use with systemd: systemctl --user start smart-agent

    Examples (Fish Shell):
        smart-agent daemon-start --silent
        smart-agent daemon-start -l 24 -s 60
    """
    from core.daemon import run_daemon, is_running

    if is_running():
        console.print("[yellow]Daemon is already running.[/yellow]")
        console.print("Run [bold]smart-agent daemon-stop[/bold] first.")
        raise typer.Exit(1)

    mode_str = "silent" if silent else "interactive"
    console.print(
        f"[bold green]Starting Smart-Agent Daemon[/bold green] ({mode_str})\n"
        f"Learning: {learn_hours}h (every {learn_interval}m) → "
        f"Monitoring: every {scan_interval}s"
    )
    if silent:
        console.print("[dim]Silent: logging only, no notifications[/dim]")
    console.print("[dim]Press Ctrl+C to stop[/dim]\n")

    run_daemon(
        learn_hours=learn_hours,
        learn_interval_minutes=learn_interval,
        scan_interval_seconds=scan_interval,
        silent=silent,
    )


@app.command(name="daemon-stop")
def daemon_stop():
    """
    Stop the running daemon gracefully.

    Examples (Fish Shell):
        smart-agent daemon-stop
    """
    from core.daemon import stop_daemon, is_running

    if not is_running():
        console.print("[yellow]Daemon is not running.[/yellow]")
        raise typer.Exit(0)

    if stop_daemon():
        console.print("[green]✓ Daemon stopped successfully[/green]")
    else:
        console.print("[red]✗ Failed to stop daemon[/red]")
        raise typer.Exit(1)


@app.command(name="daemon-status")
def daemon_status():
    """
    Show current daemon status.

    Examples (Fish Shell):
        smart-agent daemon-status
    """
    from core.daemon import is_running, get_status

    running = is_running()
    status = get_status()

    table = Table(title="Daemon Status")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Running", "[green]Yes[/green]" if running else "[red]No[/red]")

    if status:
        table.add_row("Mode", status.get("mode", "unknown"))
        table.add_row("Last Event", status.get("last_event", "N/A"))
        table.add_row("Last Event At", status.get("last_event_at", "N/A"))
        table.add_row("Started At", status.get("started_at", "N/A"))

    table.add_row("Snapshots", str(scan_store.snapshot_count()))
    table.add_row("Critical Events", str(scan_store.critical_count()))

    latest = scan_store.latest_scan()
    if latest:
        table.add_row("Last Scan", latest.get("risk_level", "N/A"))
        table.add_row("Last Score", str(latest.get("risk_score", "N/A")))

    console.print(table)

    if running:
        console.print()
        console.print("[dim]systemctl --user status smart-agent[/dim]")


@app.command(name="daemon-logs")
def daemon_logs(
    level: str = typer.Option(
        "all",
        "--level",
        "-l",
        help="Filter by risk level: all, warning, critical",
    ),
    limit: int = typer.Option(
        20,
        "--limit",
        "-n",
        help="Number of entries to show",
    ),
):
    """
    Show daemon scan logs.

    Examples (Fish Shell):
        smart-agent daemon-logs
        smart-agent daemon-logs -l critical -n 5
        smart-agent daemon-logs -l warning
    """
    min_risk = None
    if level == "warning":
        min_risk = 0.7
    elif level == "critical":
        min_risk = 0.9

    results = list(scan_store.iter_scan_results(limit=limit, min_risk=min_risk))

    if not results:
        console.print("[yellow]No scan results found.[/yellow]")
        return

    console.print(f"[bold]Last {len(results)} scan results[/bold]\n")

    for r in reversed(results):
        risk_level = r.get("risk_level", "UNKNOWN")
        risk_score = r.get("risk_score", 0)
        ts = r.get("ts", "unknown")
        anomalies = r.get("anomalies", {})
        total = anomalies.get("total_count", 0)

        if risk_level == "NORMAL":
            color, icon = "green", "✓"
        elif risk_level == "WARNING":
            color, icon = "yellow", "⚠"
        else:
            color, icon = "red", "🚨"

        console.print(
            f"[{color}]{icon} [{ts}] [bold]{risk_level}[/bold] "
            f"(score: {risk_score:.3f}, anomalies: {total})[/{color}]"
        )

        if total > 0 and risk_level != "NORMAL":
            for threat in anomalies.get("security_threats", [])[:3]:
                console.print(f"    [bold red]!!! {threat.get('details', '')}[/bold red]")
            for anomaly in anomalies.get("process", [])[:3]:
                console.print(f"    [dim]→ {anomaly.get('details', '')}[/dim]")
            for anomaly in anomalies.get("ports", [])[:3]:
                console.print(f"    [dim]→ {anomaly.get('details', '')}[/dim]")

    console.print()


@app.command(name="export-service")
def export_service():
    """
    Generate and install systemd user service file.

    Examples (Fish Shell):
        smart-agent export-service
    """
    unit_content = _get_systemd_unit()

    service_dir = Path.home() / ".config" / "systemd" / "user"
    service_dir.mkdir(parents=True, exist_ok=True)
    service_file = service_dir / "smart-agent.service"

    with open(service_file, "w") as f:
        f.write(unit_content)

    console.print(f"[green]✓[/green] Service file written to: [cyan]{service_file}[/cyan]")
    console.print()
    console.print("Enable and start with:")
    console.print("  [cyan]systemctl --user daemon-reload[/cyan]")
    console.print("  [cyan]systemctl --user enable --now smart-agent.service[/cyan]")
    console.print()
    console.print("View logs:")
    console.print("  [cyan]journalctl --user -u smart-agent -f[/cyan]")
    console.print()
    console.print("Unit file content:")
    console.print(Panel(unit_content, border_style="dim"))


def _get_systemd_unit() -> str:
    """Generate the systemd unit file content."""
    project_dir = Path(__file__).parent.resolve()
    venv_python = project_dir / ".venv" / "bin" / "python"

    return f"""\
[Unit]
Description=Smart-Agent System Anomaly Detector
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory={project_dir}
ExecStart={venv_python} cli.py daemon-start
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal

# Environment
Environment=PYTHONUNBUFFERED=1

# Security
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths={project_dir}/data
ProtectHome=read-only

[Install]
WantedBy=default.target
"""


def main():
    app()


if __name__ == "__main__":
    main()
