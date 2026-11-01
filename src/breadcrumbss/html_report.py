"""Offline, self-contained HTML view of a Breadcrumbss report."""

from datetime import datetime, timezone
from html import escape


def _text(value) -> str:
    if value is None or value == "":
        return "—"
    return escape(str(value), quote=True)


def _joined(values) -> str:
    return ", ".join(_text(value) for value in values) if values else "—"


def _time(value) -> str:
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return escape(moment.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
    except (AttributeError, TypeError, ValueError):
        return _text(value)


def _count(value) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError, OverflowError):
        return 0


def _stats(row: dict) -> dict:
    result = row.get("providers", {}).get("virustotal") or {}
    data = result.get("data") or {}
    stats = data.get("last_analysis_stats") or {}
    return stats if isinstance(stats, dict) else {}


def _vt_details(row: dict) -> tuple[str, str, str]:
    result = row.get("providers", {}).get("virustotal")
    if not result:
        return "Not enabled", "—", ""
    status = result.get("status", "unknown")
    state = _text(status.replace("_", " "))
    if result.get("cache_hit"):
        state += ' <span class="muted">· cached</span>'
    data = result.get("data") or {}
    stats = _stats(row)
    malicious = _count(stats.get("malicious"))
    suspicious = _count(stats.get("suspicious"))
    if status == "found" and stats:
        detections = f"{malicious} malicious · {suspicious} suspicious"
    else:
        detections = "—"
    context_parts = []
    for key in ("as_owner", "country", "asn"):
        if data.get(key):
            context_parts.append(_text(data[key]))
    context = " · ".join(context_parts)
    return state, detections, context


def _row(row: dict) -> str:
    status, detections, context = _vt_details(row)
    stats = _stats(row)
    flagged = _count(stats.get("malicious")) + _count(stats.get("suspicious")) > 0
    signal_class = ' class="signal"' if flagged else ""
    other = []
    for name, result in sorted(row.get("providers", {}).items()):
        if name != "virustotal":
            other.append(f"{_text(name)}: {_text(result.get('status', 'unknown'))}")
    if other:
        status += "<br><span class=\"muted\">" + " · ".join(other) + "</span>"
    first = _time(row.get("first_seen"))
    last = _time(row.get("last_seen"))
    return (
        "<tr>"
        f"<td><code>{_text(row.get('ip'))}</code><small>{_text(row.get('classification'))}</small></td>"
        f"<td class=\"numeric\">{_count(row.get('packet_count')):,}</td>"
        f"<td><span>{first}</span><small>to {last}</small></td>"
        f"<td>{_joined(row.get('protocols'))}<small>Ports: {_joined(row.get('ports'))}</small></td>"
        f"<td{signal_class}>{_text(detections)}<small>{context or '—'}</small></td>"
        f"<td>{status}<small>{_joined(row.get('directions'))}</small></td>"
        "</tr>"
    )


def _table(rows: list[dict], empty: str) -> str:
    if not rows:
        return f'<p class="empty">{escape(empty)}</p>'
    return (
        '<div class="table-wrap"><table><thead><tr>'
        '<th scope="col">IP address</th><th scope="col">Packets</th>'
        '<th scope="col">Observed</th><th scope="col">Traffic</th>'
        '<th scope="col">VirusTotal</th><th scope="col">Lookup status</th>'
        '</tr></thead><tbody>'
        + "".join(_row(row) for row in rows)
        + "</tbody></table></div>"
    )


def render_html(report: dict) -> str:
    """Return a readable report without scripts, network assets, or unescaped values."""
    rows = report.get("addresses", [])
    public = [row for row in rows if row.get("classification") == "public"]
    local = [row for row in rows if row.get("classification") != "public"]
    public.sort(key=lambda row: (
        -_count(_stats(row).get("malicious")),
        -_count(_stats(row).get("suspicious")),
        -_count(row.get("packet_count")), row.get("ip", "")))
    local.sort(key=lambda row: (-_count(row.get("packet_count")), row.get("ip", "")))
    found = sum((row.get("providers", {}).get("virustotal") or {}).get("status") == "found"
                for row in public)
    flagged = sum(_count(_stats(row).get("malicious"))
                  + _count(_stats(row).get("suspicious")) > 0 for row in public)
    filename = _text(report.get("capture", {}).get("filename"))
    totals = report.get("totals", {})
    providers = _joined(report.get("settings", {}).get("providers", []))
    capture_hash = _text(report.get("capture", {}).get("sha256"))
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Breadcrumbss · {filename}</title>
<style>
:root {{ color-scheme: light dark; font-family: system-ui, -apple-system, Segoe UI, sans-serif; }}
* {{ box-sizing: border-box; }}
body {{ margin: 0; background: #f5f7fb; color: #172033; line-height: 1.45; }}
main {{ max-width: 1380px; margin: auto; padding: 40px 28px 80px; }}
header {{ border-bottom: 1px solid #d8dee9; padding-bottom: 26px; }}
.eyebrow {{ color: #445aa5; font-size: .76rem; font-weight: 750; letter-spacing: .12em; text-transform: uppercase; }}
h1 {{ font-size: clamp(1.7rem, 3vw, 2.5rem); margin: 7px 0 10px; overflow-wrap: anywhere; }}
h2 {{ margin: 38px 0 12px; font-size: 1.25rem; }}
p {{ margin: 0 0 14px; }}
.muted, small {{ color: #5c687b; }}
.summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(175px, 1fr)); gap: 12px; margin: 26px 0; }}
.metric {{ background: white; border: 1px solid #dce2ec; border-radius: 12px; padding: 16px 18px; }}
.metric strong {{ display: block; font-size: 1.75rem; line-height: 1.1; }}
.metric span {{ display: block; margin-top: 7px; color: #5c687b; font-size: .84rem; }}
.notice {{ background: #e9f0ff; border-left: 4px solid #526ac9; border-radius: 5px; padding: 14px 16px; }}
.table-wrap {{ overflow-x: auto; background: white; border: 1px solid #dce2ec; border-radius: 12px; }}
table {{ border-collapse: collapse; width: 100%; min-width: 980px; }}
th, td {{ padding: 13px 14px; text-align: left; vertical-align: top; border-bottom: 1px solid #e8ecf2; }}
th {{ color: #4c5870; font-size: .76rem; font-weight: 750; letter-spacing: .05em; text-transform: uppercase; background: #f9fafc; }}
tr:last-child td {{ border-bottom: 0; }}
td {{ font-size: .9rem; }}
td small {{ display: block; margin-top: 4px; font-size: .76rem; }}
code {{ font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: .87rem; overflow-wrap: anywhere; }}
.numeric {{ font-variant-numeric: tabular-nums; }}
.signal {{ color: #a43223; font-weight: 700; }}
.empty {{ padding: 18px; background: white; border: 1px solid #dce2ec; border-radius: 12px; }}
details {{ margin-top: 28px; color: #4c5870; font-size: .83rem; }}
summary {{ cursor: pointer; font-weight: 650; }}
@media (prefers-color-scheme: dark) {{
  body {{ background: #111826; color: #e7edf8; }}
  header {{ border-color: #303b50; }}
  .metric, .table-wrap, .empty {{ background: #1b2536; border-color: #374459; }}
  .muted, small, .metric span {{ color: #acb8ca; }}
  .eyebrow {{ color: #a6b6ff; }}
  .notice {{ background: #202e4a; border-color: #9caeff; }}
  th {{ background: #243047; color: #b9c7dc; }}
  th, td {{ border-color: #374459; }}
  .signal {{ color: #ff9c88; }}
}}
</style>
</head>
<body><main>
<header><div class="eyebrow">Breadcrumbss capture report</div><h1>{filename}</h1>
<p class="muted">Completed {_time(report.get('completed_at'))} · Providers: {providers}</p></header>
<section class="summary" aria-label="Capture summary">
<div class="metric"><strong>{_count(totals.get('packets')):,}</strong><span>Packets</span></div>
<div class="metric"><strong>{_count(totals.get('unique_ips')):,}</strong><span>Unique IPs</span></div>
<div class="metric"><strong>{len(public):,}</strong><span>Public IPs</span></div>
<div class="metric"><strong>{found:,}</strong><span>VirusTotal results</span></div>
<div class="metric"><strong>{flagged:,}</strong><span>IPs with detection signals</span></div>
</section>
<p class="notice">VirusTotal detections are signals to investigate, not proof that a connection or device is malicious. An IP address may be shared by many users or services.</p>
<section aria-labelledby="public-heading"><h2 id="public-heading">Public IPs</h2>
{_table(public, 'No public IP addresses were found.')}</section>
<section aria-labelledby="local-heading"><h2 id="local-heading">Local and special-use IPs</h2>
{_table(local, 'No local or special-use IP addresses were found.')}</section>
<details><summary>Capture details</summary><p>SHA-256: <code>{capture_hash}</code></p>
<p>Report generated {_time(report.get('completed_at'))}. Times shown in UTC.</p></details>
</main></body></html>
"""
