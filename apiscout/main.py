import time
import asyncio
from typing import Optional
import typer
import httpx
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.text import Text

from .console import console, print_banner
from .models import ScanResult
from .scanner import headers as hdr_scanner
from .scanner import fuzzer as fuzz_scanner
from .scanner import spec as spec_scanner
from .scanner import live as live_scanner
from .report.terminal import render_findings_table, render_finding_details, render_summary
from .report.export import export_json, export_html

app = typer.Typer(
    name="apiscout",
    help="An aesthetic, all-in-one API security scanner.",
    add_completion=False,
    rich_markup_mode="rich",
)


def _info_panel(target: str, spec: Optional[str], modules: list[str]) -> None:
    body = Text()
    body.append("  Target  ", style="dim")
    body.append(target + "\n", style="bold white")
    if spec:
        body.append("  Spec    ", style="dim")
        body.append(spec + "\n", style="bold white")
    body.append("  Modules ", style="dim")
    body.append(", ".join(modules) + "\n", style="cyan")

    console.print(Panel(body, border_style="dim", padding=(0, 0)))
    console.print()


async def _run_scan(
    target: str,
    spec: Optional[str],
    no_fuzz: bool,
    no_live: bool,
    verbose: bool,
) -> ScanResult:
    result = ScanResult(target=target, spec_source=spec)
    finding_counter = [0]

    modules = ["headers"]
    if spec:
        modules.append("spec")
    if not no_live:
        modules.append("live")
    if not no_fuzz:
        modules.append("fuzzer")

    _info_panel(target, spec, modules)

    start = time.monotonic()

    limits = httpx.Limits(max_connections=20, max_keepalive_connections=10)
    timeout = httpx.Timeout(10.0, connect=5.0)

    async with httpx.AsyncClient(
        limits=limits,
        timeout=timeout,
        headers={"User-Agent": "apiscout/0.1.0 (security-scanner)"},
        verify=False,
    ) as client:
        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[cyan]{task.description:<30}"),
            BarColumn(bar_width=24, style="cyan", complete_style="bold cyan"),
            TextColumn("[dim]{task.fields[status]}"),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as progress:

            # ── Header checks ─────────────────────────────────────────────
            t_hdr = progress.add_task("Checking response headers…", total=1, status="")
            hdr_findings = await hdr_scanner.check_headers(client, target, finding_counter)
            result.findings.extend(hdr_findings)
            progress.update(t_hdr, advance=1, status=f"{len(hdr_findings)} finding(s)")

            # ── Spec analysis ─────────────────────────────────────────────
            spec_endpoints: list[str] = []
            if spec:
                t_spec = progress.add_task("Analyzing OpenAPI spec…", total=1, status="")
                spec_findings, spec_endpoints = await spec_scanner.analyze_spec(client, spec, finding_counter)
                result.findings.extend(spec_findings)
                progress.update(
                    t_spec, advance=1,
                    status=f"{len(spec_endpoints)} endpoints, {len(spec_findings)} finding(s)"
                )

            # ── Live endpoint probing ──────────────────────────────────────
            if not no_live and spec_endpoints:
                t_live = progress.add_task(
                    "Probing live endpoints…",
                    total=len(spec_endpoints),
                    status="",
                )

                def live_progress(done: int, total: int) -> None:
                    progress.update(t_live, completed=done, status=f"{done}/{total}")

                live_findings = await live_scanner.probe_endpoints(
                    client, target, spec_endpoints, finding_counter, live_progress
                )
                result.findings.extend(live_findings)
                result.endpoints_probed = len(spec_endpoints)
                progress.update(t_live, status=f"{len(live_findings)} finding(s)")

            # ── Path fuzzing ───────────────────────────────────────────────
            if not no_fuzz:
                t_fuzz = progress.add_task(
                    "Fuzzing paths…",
                    total=len(fuzz_scanner.WORDLIST),
                    status="",
                )

                def fuzz_progress(done: int, total: int) -> None:
                    progress.update(t_fuzz, completed=done, status=f"{done}/{total}")

                fuzz_findings, discovered = await fuzz_scanner.fuzz_paths(
                    client, target, finding_counter, fuzz_progress
                )
                result.findings.extend(fuzz_findings)
                result.endpoints_discovered.extend(discovered)
                progress.update(t_fuzz, status=f"{len(discovered)} discovered, {len(fuzz_findings)} finding(s)")

    result.duration_s = time.monotonic() - start
    return result


@app.command()
def scan(
    target: str = typer.Argument(..., help="Base URL to scan (e.g. https://api.example.com)"),
    spec: Optional[str] = typer.Option(None, "--spec", "-s", help="OpenAPI spec URL or file path"),
    output_json: Optional[str] = typer.Option(None, "--json", "-j", help="Export findings to a JSON file"),
    output_html: Optional[str] = typer.Option(None, "--html", help="Export findings to an HTML report"),
    no_fuzz: bool = typer.Option(False, "--no-fuzz", help="Skip path fuzzing"),
    no_live: bool = typer.Option(False, "--no-live", help="Skip live endpoint probing"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show full finding details"),
    no_banner: bool = typer.Option(False, "--no-banner", help="Suppress the ASCII banner"),
) -> None:
    """Scan an API for security issues."""
    if not no_banner:
        print_banner()

    # Normalise target
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "https://" + target

    result = asyncio.run(_run_scan(target, spec, no_fuzz, no_live, verbose))

    console.print()
    render_findings_table(result)
    console.print()

    if verbose and result.findings:
        render_finding_details(result)
        console.print()

    render_summary(result)

    if output_json:
        export_json(result, output_json)
        console.print(f"  [dim]JSON report saved to [white]{output_json}[/white][/dim]")

    if output_html:
        export_html(result, output_html)
        console.print(f"  [dim]HTML report saved to [white]{output_html}[/white][/dim]")

    console.print()
    raise typer.Exit(0 if result.risk_score() == 0 else 1)


@app.command()
def version() -> None:
    """Show apiscout version."""
    from .console import VERSION
    console.print(f"apiscout {VERSION}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
