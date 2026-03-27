from __future__ import annotations

import json
from pathlib import Path

from web_site_tester.templates import HTML_TEMPLATE


def save_json(data: dict, path: str) -> None:
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def save_html(data: dict, path: str) -> None:
    finding_rows = []
    for item in data.get("findings", []):
        finding_rows.append(
            "<tr>"
            f"<td>{item['title']}</td>"
            f"<td class='sev-{item['severity']}'>{item['severity']}</td>"
            f"<td>{item['penalty']}</td>"
            f"<td>{item['detail']}</td>"
            "</tr>"
        )

    tech_items = []
    for tech in data.get("technology_hints", []):
        tech_items.append(f"<li><code>{tech}</code></li>")

    html = HTML_TEMPLATE
    html = html.replace("{{target}}", str(data.get("target", "-")))
    html = html.replace("{{score}}", str(data.get("score", 0)))
    html = html.replace("{{level}}", str(data.get("level", "unknown")))
    html = html.replace("{{message}}", str(data.get("message", "No custom message.")))
    html = html.replace("{{finding_rows}}", "\n".join(finding_rows) or "<tr><td colspan='4' class='ok'>No findings.</td></tr>")
    html = html.replace("{{tech_items}}", "\n".join(tech_items) or "<li>None detected</li>")

    Path(path).write_text(html, encoding="utf-8")