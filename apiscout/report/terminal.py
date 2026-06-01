from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.columns import Columns
from rich import box
from ..console import console
from ..models import ScanResult, Severity, SEVERITY_COLORS, SEVERITY_ICONS


def _severity_badge(sev: Severity) -> Text:
    icon = SEVERITY_ICONS[sev]
    color = SEVERITY_COLORS[sev]
    return Text(f" {icon} {sev.value:<8}", style=color)


def render_findings_table(result: ScanResult) -> None:
    if not result.findings:
        console.print(
            Panel("[pass]  No findings — looking clean![/pass]", border_style="green", padding=(0, 2))
        )
        return

    table = Table(
        box=box.ROUNDED,
        border_style="dim white",
        header_style="bold white",
        show_lines=False,
        padding=(0, 1),
        expand=True,
    )

    table.add_column("ID", style="dim", width=10, no_wrap=True)
    table.add_column("Severity", width=12, no_wrap=True)
    table.add_column("Module", style="module", width=10, no_wrap=True)
    table.add_column("Endpoint", width=30, no_wrap=True)
    table.add_column("Finding")

    for f in result.sorted_findings():
        color = SEVERITY_COLORS[f.severity]
        table.add_row(
            f"[dim]{f.id}[/dim]",
            _severity_badge(f.severity),
            f"[module]{f.module}[/module]",
            f"[dim]{f.endpoint[:40]}[/dim]",
            Text(f.title, style=color),
        )

    console.print()
    console.print(table)


def render_finding_details(result: ScanResult) -> None:
    for f in result.sorted_findings():
        color = SEVERITY_COLORS[f.severity]
        icon = SEVERITY_ICONS[f.severity]
        header = Text(f" {icon} [{f.id}] {f.title}", style=color)

        body = Text()
        body.append("\nEndpoint:  ", style="dim")
        body.append(f.endpoint + "\n", style="white")
        body.append("Detail:    ", style="dim")
        body.append(f.detail + "\n", style="white")
        if f.evidence:
            body.append("Evidence:  ", style="dim")
            body.append(f.evidence + "\n", style="yellow")
        if f.remediation:
            body.append("Fix:       ", style="dim")
            body.append(f.remediation + "\n", style="cyan")

        console.print(
            Panel(body, title=header, border_style=color.replace("bold ", ""), padding=(0, 2))
        )


def render_summary(result: ScanResult) -> None:
    counts = result.count_by_severity()
    score = result.risk_score()
    grade = result.grade()

    grade_color = {
        "A+": "bold green", "A": "green", "B": "cyan",
        "C": "yellow", "D": "red", "F": "bold red",
    }.get(grade, "white")

    sev_line = Text()
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        n = counts[sev]
        color = SEVERITY_COLORS[sev]
        icon = SEVERITY_ICONS[sev]
        sev_line.append(f"  {icon} {n} {sev.value:<8}", style=color if n > 0 else "dim")

    stats = Text()
    stats.append("\n")
    stats.append(sev_line)
    stats.append(f"\n\n  Risk Score  ", style="dim")
    stats.append(f"{score}/100", style="bold white")
    stats.append("   Grade  ", style="dim")
    stats.append(f" {grade} ", style=grade_color)
    stats.append(f"   Endpoints  ", style="dim")
    stats.append(str(result.endpoints_probed), style="bold white")
    stats.append(f"   Duration  ", style="dim")
    stats.append(f"{result.duration_s:.1f}s\n", style="bold white")

    console.print(
        Panel(stats, title="[section] Summary [/section]", border_style="dim white", padding=(0, 1))
    )
