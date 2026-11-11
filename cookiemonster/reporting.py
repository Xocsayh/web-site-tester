from __future__ import annotations

import json
from html import escape
from pathlib import Path
from typing import Any


def to_json(data: dict) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False, default=str)


def save_json(data: dict, path: str) -> None:
    if path == "-":
        print(to_json(data))
        return
    Path(path).write_text(to_json(data) + "\n", encoding="utf-8")


def _e(value: Any) -> str:
    """Everything that came from the scanned site is untrusted -> escape it."""
    return escape("" if value is None else str(value), quote=True)


_CSS = """
:root{--bg:#0b1020;--card:#121a2f;--line:#22304f;--text:#e6ecff;--muted:#93a1c4;
--blue:#3b82f6;--high:#f87171;--medium:#fb923c;--low:#facc15;--info:#60a5fa;--ok:#4ade80}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;padding:24px 16px}
.wrap{max-width:1100px;margin:0 auto}.card{background:var(--card);border:1px solid var(--line);
border-radius:14px;padding:20px;margin-bottom:16px}h1{margin:0 0 4px;font-size:24px}
h2{margin:0 0 12px;font-size:18px}.muted{color:var(--muted)}.hero{display:flex;gap:24px;
align-items:center;flex-wrap:wrap}.score{font-size:52px;font-weight:800;line-height:1}
.pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:700;
text-transform:uppercase;border:1px solid currentColor}.sev-high{color:var(--high)}
.sev-medium{color:var(--medium)}.sev-low{color:var(--low)}.sev-info{color:var(--info)}
.ok{color:var(--ok)}table{width:100%;border-collapse:collapse}th,td{padding:10px 8px;
border-bottom:1px solid var(--line);text-align:left;vertical-align:top}th{color:var(--muted);
font-weight:600;font-size:13px}td.fix{color:var(--muted)}code{background:#0a1226;padding:1px 6px;
border-radius:6px;word-break:break-all}.grid{display:grid;grid-template-columns:repeat(auto-fit,
minmax(220px,1fr));gap:8px 24px}.kv b{color:var(--muted);font-weight:500}
.counts span{margin-right:14px}.wrapx{overflow-x:auto}
footer{color:var(--muted);font-size:12px;text-align:center;margin-top:8px}
@media (max-width:700px){thead{display:none}table,tbody,tr,td{display:block;width:100%}
tr{border-bottom:1px solid var(--line);padding:10px 0}td{border:0;padding:3px 0}
td.pen:empty{display:none}.score{font-size:44px}}
"""


def render_html(data: dict) -> str:
    sev_counts = data.get("summary") or {}
    score = data.get("score")
    score_cls = "ok" if score is not None and score >= 85 else (
        "sev-low" if score is not None and score >= 70 else (
            "sev-medium" if score is not None and score >= 50 else "sev-high"))

    rows = []
    for f in data.get("findings", []):
        sev = f.get("severity", "info")
        sev_cls = sev if sev in ("high", "medium", "low", "info") else "info"
        rows.append(
            "<tr>"
            f"<td><span class='pill sev-{sev_cls}'>{_e(sev)}</span></td>"
            f"<td><strong>{_e(f.get('title'))}</strong><br><span class='muted'>{_e(f.get('category'))}</span></td>"
            f"<td>{_e(f.get('detail'))}</td>"
            f"<td class='fix'>{_e(f.get('fix'))}</td>"
            f"<td class='pen'>{'-' + _e(f.get('penalty')) if f.get('penalty') else ''}</td>"
            "</tr>"
        )
    findings_html = "\n".join(rows) or "<tr><td colspan='5' class='ok'>No findings. The monster went home hungry.</td></tr>"

    tech = "".join(f"<code>{_e(t)}</code> " for t in data.get("technology_hints", [])) or "<span class='muted'>None detected</span>"

    info = data.get("info") or {}
    kv = []
    tls = info.get("tls") or {}
    for label, key in (("TLS protocol", "protocol"), ("Cipher", "cipher"), ("Issuer", "issuer"),
                       ("Expires", "expires"), ("Days left", "days_left")):
        if tls.get(key) is not None:
            kv.append((label, tls[key]))
    perf = info.get("performance") or {}
    for label, key in (("Response", "response_ms"), ("Redirects", "redirects"), ("HTML size (KB)", "html_kb"),
                       ("Compression", "compression"), ("Scripts", "scripts"), ("Stylesheets", "stylesheets"),
                       ("Images", "images")):
        if key in perf:
            val = perf[key]
            kv.append((label, f"{val} ms" if key == "response_ms" else ("none" if val is None else val)))
    links = info.get("links")
    if links:
        kv.append(("Internal links checked", f"{links['checked']} / {links['found']} ({links['broken']} broken)"))
    if info.get("cookies") is not None:
        kv.append(("Cookies set", ", ".join(info["cookies"]) or "none"))
    details = "".join(f"<div class='kv'><b>{_e(k)}:</b> {_e(v)}</div>" for k, v in kv)

    counts = "".join(
        f"<span class='sev-{s}'>{_e(s)}: {_e(sev_counts.get(s, 0))}</span>"
        for s in ("high", "medium", "low", "info"))
    note = f"<p class='sev-low'>{_e(data['note'])}</p>" if data.get("note") else ""
    message = f"<p><strong>{_e(data['message'])}</strong></p>" if data.get("message") else ""

    redirected = ""
    if data.get("target") and data.get("target") != data.get("final_url"):
        redirected = f" <span class='muted'>(from <code>{_e(data.get('target'))}</code>)</span>"

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>CookieMonster report - {_e(data.get('final_url'))}</title><style>{_CSS}</style></head>
<body><div class="wrap">
<div class="card"><div class="hero">
<div class="score {score_cls}">{_e(score if score is not None else '--')}<span class="muted" style="font-size:20px">/100</span></div>
<div><h1>CookieMonster report</h1>
<div class="muted">Target: <code>{_e(data.get('final_url'))}</code>{redirected}</div>
<div class="muted">Scanned {_e(data.get('scanned_at'))} &middot; level <strong>{_e(data.get('level'))}</strong></div>
<div>{_e(data.get('mood', ''))}</div></div></div>
{message}{note}<p class="counts">{counts}</p></div>
<div class="card"><h2>Technology</h2>{tech}</div>
<div class="card"><h2>Findings</h2><div class="wrapx"><table>
<thead><tr><th>Severity</th><th>Finding</th><th>Detail</th><th>How to fix</th><th>Score</th></tr></thead>
<tbody>{findings_html}</tbody></table></div></div>
<div class="card"><h2>Details</h2><div class="grid">{details or "<span class='muted'>-</span>"}</div></div>
<footer>CookieMonster {_e(data.get('version'))} &middot; passive audit &middot; only scan sites you are allowed to test</footer>
</div></body></html>
"""


def save_html(data: dict, path: str) -> None:
    Path(path).write_text(render_html(data), encoding="utf-8")
