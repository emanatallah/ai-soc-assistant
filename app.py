#!/usr/bin/env python3
"""
AI SOC Assistant
Team: DR \ Hacker

Linux Terminal Edition
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Any
from ai.report_builder import build_report

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn,
)
from rich.prompt import Prompt
from rich import box

from ai.analyzer import analyze_scan
from ai.mitre_mapper import map_findings_to_mitre
from ai.risk_engine import calculate_risk

from database.sqlite import (
    save_scan,
    list_scans,
    #compare_latest_scans,
    compare_two_targets,
)

from reports.pdf import generate_pdf_report
from scanner import run_unified_scan

console = Console()


# ============================================================
# Splash Screen
# ============================================================

def splash() -> None:

    os.system("cls")

    console.print("""

 █████╗ ██╗     ███████╗ ██████╗  ██████╗
██╔══██╗██║     ██╔════╝██╔═══██╗██╔════╝
███████║██║     ███████╗██║   ██║██║
██╔══██║██║     ╚════██║██║   ██║██║
██║  ██║██║     ███████║╚██████╔╝╚██████╗
╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝  ╚═════╝

""", style="bold cyan")

    console.print(
        Panel.fit(
            "[bold green]AI SOC Assistant[/bold green]\n"
            "Team : [yellow]DR \\ Hacker[/yellow]\n\n"
            "Attack Surface Intelligence Platform",
            border_style="green",
        )
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]Initializing modules..."),
        BarColumn(),
        transient=True,
    ) as progress:

        task = progress.add_task("", total=100)

        for i in range(100):
            time.sleep(0.01)
            progress.update(task, advance=1)

    console.print("[green]Initialization Complete.[/green]\n")


# ============================================================
# Main Menu
# ============================================================

def menu() -> str:

    table = Table(
        title="AI SOC Assistant",
        box=box.ROUNDED,
        border_style="cyan",
    )

    table.add_column("Option", style="yellow")
    table.add_column("Description", style="green")

    table.add_row("1", "Scan Target")
    table.add_row("2", "Scan History")
    table.add_row("3", "Compare Scans")
    table.add_row("4", "Generate Report")
    table.add_row("5", "Settings")
    table.add_row("6", "About")
    table.add_row("0", "Exit")

    console.print(table)

    return Prompt.ask(
        "[bold cyan]Select Option[/bold cyan]",
        default="1",
    )


# ============================================================
# Helpers
# ============================================================

def wait():

    console.print()
    input("Press ENTER to continue...")


def clear():

    pass


# ============================================================
# Run Full Assessment
# ============================================================

def run_full_assessment(target: str):

    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(),
    ) as progress:

        task = progress.add_task(
            "[cyan]Scanning target...",
            total=100,
        )

        progress.update(task, advance=10)

        scan = run_unified_scan(target)

        progress.update(task, advance=25)

        risk = calculate_risk(scan)
        progress.update(task, advance=15)

        mitre = map_findings_to_mitre(
            risk.get("findings", [])
        )

        progress.update(task, advance=20)

        summary = {
    "target": scan.get("target"),
    "ip": scan.get("ip"),

    "services": scan.get("services", []),

    "risk_score": risk.get("risk_score"),
    "severity": risk.get("severity"),
    "risk_summary": risk.get("risk_summary"),
    "findings": risk.get("findings", []),

    "mitre": mitre,

    "headers": scan.get("headers", {}),
    "ssl": scan.get("ssl", {}),
    "technologies": scan.get("technologies", []),
}
    
        report = build_report(summary)
        ai_report = analyze_scan(report)
        progress.update(task, advance=15)

        scan_id = save_scan(
            scan["target"],
            scan,
            risk,
            ai_report,
            mitre,
        )

        pdf_path = generate_pdf_report(
            scan["target"],
            scan,
            risk,
            mitre,
            ai_report,
        )

        progress.update(task, completed=100)

    return {
        "scan_id": scan_id,
        "scan": scan,
        "risk": risk,
        "mitre": mitre,
        "ai_report": ai_report,
        "pdf_path": pdf_path,
    }


# ============================================================
# Display Scan Result
# ============================================================

def show_scan_result(result: dict[str, Any]) -> None:

    clear()

    scan = result["scan"]
    risk = result["risk"]

    console.print(
        Panel.fit(
            "[bold green]Scan Completed Successfully[/bold green]",
            border_style="green",
        )
    )

    info = Table(
        title="Target Information",
        box=box.ROUNDED,
        border_style="cyan",
    )

    info.add_column("Field", style="yellow")
    info.add_column("Value", style="green")

    info.add_row("Target", str(scan.get("target")))
    info.add_row("IP", str(scan.get("ip")))
    info.add_row("Risk Score", str(risk.get("risk_score")))
    info.add_row("Severity", str(risk.get("severity")))

    console.print(info)

    ports = Table(
        title="Open Ports",
        box=box.SIMPLE_HEAVY,
        border_style="red",
    )

    ports.add_column("Port")
    ports.add_column("Service")
    ports.add_column("Product")
    ports.add_column("Version")

    for item in scan.get("services", []):

        ports.add_row(
            str(item.get("port", "")),
            str(item.get("service", "")),
            str(item.get("product", "")),
            str(item.get("version", "")),
        )

    console.print(ports)

    mitre = Table(
        title="MITRE ATT&CK",
        box=box.ROUNDED,
        border_style="magenta",
    )

    mitre.add_column("Technique")
    mitre.add_column("Name")

    for item in result["mitre"]:

        mitre.add_row(
        str(item.get("technique_id", "-")),
        str(item.get("technique_name", "-")),
    )

    console.print(mitre)

    console.print(
        Panel(
            result["ai_report"],
            title="AI Analysis",
            border_style="blue",
        )
    )

    console.print(
        f"\n[green]PDF Report:[/green] {result['pdf_path']}"
    )

    wait()


# ============================================================
# Scan Target
# ============================================================

def scan_target():

    clear()

    console.print(
        Panel.fit(
            "[bold cyan]Target Scanner[/bold cyan]"
        )
    )

    target = Prompt.ask(
        "Enter Target (Domain/IP)"
    ).strip()

    if not target:

        console.print("[red]Invalid Target[/red]")

        wait()

        return

    result = run_full_assessment(target)

    show_scan_result(result)

    # ============================================================
# History
# ============================================================

def show_history():

    clear()

    rows = list_scans()

    if not rows:

        console.print("[yellow]No scans found.[/yellow]")

        wait()

        return

    table = Table(
        title="Scan History",
        box=box.ROUNDED,
        border_style="cyan",
    )

    table.add_column("ID")
    table.add_column("Target")
    table.add_column("Risk")
    table.add_column("Timestamp")

    for row in rows:

        table.add_row(
            str(row.get("id")),
            str(row.get("target")),
            str(row.get("risk_score")),
            str(row.get("timestamp")),
        )

    console.print(table)

    wait()


# ============================================================
# Compare
# ============================================================

def compare_scans():

    clear()

    target1 = Prompt.ask(
        "First Target"
    ).strip()

    target2 = Prompt.ask(
        "Second Target"
    ).strip()

    result = compare_two_targets(
        target1,
        target2,
    )

    if not result.get("available"):

        console.print(
            f"[red]{result.get('message')}[/red]"
        )

        wait()
        return

    table = Table(
        title=f"Comparison - {target1} vs {target2}",
        box=box.ROUNDED,
        border_style="green",
    )

    table.add_column("Field")
    table.add_column(target1)
    table.add_column(target2)

    table.add_row(
        "Risk Score",
        str(result["target1"]["risk_score"]),
        str(result["target2"]["risk_score"]),
    )

    table.add_row(
        "Timestamp",
        str(result["target1"]["timestamp"]),
        str(result["target2"]["timestamp"]),
    )

    table.add_row(
        "Severity",
        str(result["target1"]["severity"]),
        str(result["target2"]["severity"]),
    )

    table.add_row(
        "Difference",
        "-",
        str(result["delta"]),
    )

    console.print(table)

    wait()
# ============================================================
# About
# ============================================================

def about():

    clear()

    console.print(

        Panel.fit(

            """
[bold cyan]AI SOC Assistant[/bold cyan]

Version : 1.0

Team : DR \\ Hacker

Attack Surface Intelligence Platform

Backend
--------

• Scanner Engine
• Risk Engine
• MITRE ATT&CK
• Ollama AI
• SQLite
• PDF Reports
• Network Graph

""",

            border_style="green",

        )

    )

    wait()


# ============================================================
# Settings
# ============================================================

def settings():

    clear()

    console.print(

        Panel.fit(

            """
Settings are loaded from:

config.py

.env

To modify scan timeout,
database path,
or AI model,
edit config.py
""",

            border_style="yellow",

        )

    )

    wait()

    # ============================================================
# History
# ============================================================

def show_history():

    clear()

    rows = list_scans()

    if not rows:

        console.print("[yellow]No scans found.[/yellow]")

        wait()

        return

    table = Table(
        title="Scan History",
        box=box.ROUNDED,
        border_style="cyan",
    )

    table.add_column("ID")
    table.add_column("Target")
    table.add_column("Risk")
    table.add_column("Timestamp")

    for row in rows:

        table.add_row(
            str(row.get("id")),
            str(row.get("target")),
            str(row.get("risk_score")),
            str(row.get("timestamp")),
        )

    console.print(table)

    wait()


# ============================================================
# Compare
# ============================================================

def compare_scans():

    clear()

    console.print(
        "[cyan]Enter two targets separated by a comma[/cyan]\n"
        "Example: 8.8.8.8, 9.9.9.9\n"
    )

    targets = Prompt.ask("Targets").strip()

    if "," not in targets:
        console.print("[red]Please enter two targets separated by a comma.[/red]")
        wait()
        return

    target1, target2 = [t.strip() for t in targets.split(",", 1)]

    result = compare_two_targets(target1, target2)

    if not result.get("available"):
        console.print(f"[red]{result.get('message')}[/red]")
        wait()
        return

    table = Table(
        title="Target Comparison",
        box=box.ROUNDED,
        border_style="green",
    )

    table.add_column("Field")
    table.add_column(target1)
    table.add_column(target2)

    table.add_row(
        "Risk Score",
        str(result["target1"]["risk_score"]),
        str(result["target2"]["risk_score"]),
    )

    table.add_row(
        "Severity",
        str(result["target1"]["severity"]),
        str(result["target2"]["severity"]),
    )

    table.add_row(
        "Scan Time",
        str(result["target1"]["timestamp"]),
        str(result["target2"]["timestamp"]),
    )

    console.print(table)

    wait()

# ============================================================
# About
# ============================================================

def about():

    clear()

    console.print(

        Panel.fit(

            """
[bold cyan]AI SOC Assistant[/bold cyan]

Version : 1.0

Team : DR \\ Hacker

Attack Surface Intelligence Platform

Backend
--------

• Scanner Engine
• Risk Engine
• MITRE ATT&CK
• Ollama AI
• SQLite
• PDF Reports
• Network Graph

Linux Terminal Edition
""",

            border_style="green",

        )

    )

    wait()


# ============================================================
# Settings
# ============================================================

def settings():

    clear()

    console.print(

        Panel.fit(

            """
Settings are loaded from:

config.py

.env

To modify scan timeout,
database path,
or AI model,
edit config.py
""",

            border_style="yellow",

        )

    )

    wait()

    # ============================================================
# Generate Report
# ============================================================

def generate_report():

    clear()

    rows = list_scans()

    if not rows:

        console.print("[red]No reports available.[/red]")

        wait()

        return

    latest = rows[0]

    console.print(
        Panel.fit(
            f"""
Latest Scan

Target : {latest['target']}

Risk Score : {latest['risk_score']}

The PDF report is stored inside

history/
""",
            border_style="green",
        )
    )

    wait()


# ============================================================
# Main Loop
# ============================================================

def main():

    splash()

    while True:

        clear()

        choice = menu()

        if choice == "1":

            scan_target()

        elif choice == "2":

            show_history()

        elif choice == "3":

            compare_scans()

        elif choice == "4":

            generate_report()

        elif choice == "5":

            settings()

        elif choice == "6":

            about()

        elif choice == "0":

            console.print(
                "\n[bold green]Goodbye.[/bold green]\n"
            )

            sys.exit(0)

        else:

            console.print(
                "[red]Invalid Option[/red]"
            )

            time.sleep(1)


# ============================================================
# Entry
# ============================================================

if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        console.print(
            "\n[yellow]Interrupted by user.[/yellow]"
        )

    except Exception as e:

        console.print(
            f"\n[bold red]Fatal Error:[/bold red] {e}"
        )

        