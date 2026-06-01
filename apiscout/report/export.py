import json
from pathlib import Path
from ..models import ScanResult


def export_json(result: ScanResult, path: str) -> None:
    data = {
        "target": result.target,
        "spec_source": result.spec_source,
        "risk_score": result.risk_score(),
        "grade": result.grade(),
        "duration_s": result.duration_s,
        "endpoints_probed": result.endpoints_probed,
        "findings": [
            {
                "id": f.id,
                "severity": f.severity.value,
                "module": f.module,
                "endpoint": f.endpoint,
                "title": f.title,
                "detail": f.detail,
                "remediation": f.remediation,
                "evidence": f.evidence,
            }
            for f in result.sorted_findings()
        ],
    }
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>APIScount Report — {target}</title>
<style>
  body {{ font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #e6edf3; margin: 0; padding: 2rem; }}
  h1 {{ color: #58a6ff; }} h2 {{ color: #8b949e; font-weight: 400; }}
  .summary {{ display: flex; gap: 1rem; margin: 1.5rem 0; flex-wrap: wrap; }}
  .badge {{ padding: .4rem 1rem; border-radius: 4px; font-weight: 600; font-size: .9rem; }}
  .CRITICAL {{ background: #3d1a1a; color: #f85149; border: 1px solid #f85149; }}
  .HIGH {{ background: #2d1a1a; color: #ff7b72; border: 1px solid #ff7b72; }}
  .MEDIUM {{ background: #2d2200; color: #e3b341; border: 1px solid #e3b341; }}
  .LOW {{ background: #0d2d3d; color: #58a6ff; border: 1px solid #58a6ff; }}
  .INFO {{ background: #1c1c1c; color: #8b949e; border: 1px solid #8b949e; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
  th {{ text-align: left; padding: .6rem 1rem; background: #161b22; color: #8b949e; font-weight: 500; }}
  td {{ padding: .6rem 1rem; border-bottom: 1px solid #21262d; vertical-align: top; }}
  tr:hover td {{ background: #161b22; }}
  .score {{ font-size: 2rem; font-weight: 700; }} .grade {{ font-size: 1.5rem; margin-left: 1rem; }}
  .meta {{ color: #8b949e; font-size: .85rem; margin-bottom: 1.5rem; }}
</style>
</head>
<body>
<h1>APIScount Security Report</h1>
<p class="meta">Target: <strong>{target}</strong> &nbsp;|&nbsp; Score: <span class="score">{score}/100</span><span class="grade">Grade {grade}</span> &nbsp;|&nbsp; {duration}s</p>
<div class="summary">{badges}</div>
<h2>Findings</h2>
<table>
  <tr><th>ID</th><th>Severity</th><th>Module</th><th>Endpoint</th><th>Finding</th><th>Remediation</th></tr>
  {rows}
</table>
</body></html>"""


def export_html(result: ScanResult, path: str) -> None:
    from ..models import Severity, SEVERITY_ICONS
    counts = result.count_by_severity()

    badges = "".join(
        f'<span class="badge {sev.value}">{SEVERITY_ICONS[sev]} {counts[sev]} {sev.value}</span>'
        for sev in Severity if counts[sev] > 0
    )

    rows = "".join(
        f"<tr><td>{f.id}</td><td><span class='badge {f.severity.value}'>{f.severity.value}</span></td>"
        f"<td>{f.module}</td><td><code>{f.endpoint}</code></td>"
        f"<td>{f.title}<br><small style='color:#8b949e'>{f.detail}</small></td>"
        f"<td><small>{f.remediation}</small></td></tr>"
        for f in result.sorted_findings()
    )

    html = _HTML_TEMPLATE.format(
        target=result.target,
        score=result.risk_score(),
        grade=result.grade(),
        duration=f"{result.duration_s:.1f}",
        badges=badges,
        rows=rows,
    )
    Path(path).write_text(html, encoding="utf-8")
