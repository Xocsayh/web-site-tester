"""Broken internal links on the scanned page (same host only)."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urldefrag, urlparse


def _internal_links(scan) -> list[str]:
    host = urlparse(scan.final_url).netloc
    out: list[str] = []
    seen = {urldefrag(scan.final_url)[0]}
    for a in scan.soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
            continue
        url = urldefrag(scan.absolute(href))[0]
        p = urlparse(url)
        if p.scheme not in ("http", "https") or p.netloc != host or url in seen:
            continue
        seen.add(url)
        out.append(url)
    return out


def check_links(scan) -> None:
    if not scan.options.check_links or not scan.soup:
        return
    links = _internal_links(scan)
    checked = links[: scan.options.max_links]

    def status(url: str) -> tuple[str, int | None]:
        p = scan.probe(url, method="HEAD", allow_redirects=True)
        if p is None or p.status in (405, 501) or p.status >= 400:
            # Some servers reject HEAD; confirm with a tiny GET.
            p = scan.probe(url, max_bytes=1, allow_redirects=True)
        return url, (p.status if p else None)

    with ThreadPoolExecutor(max_workers=scan.options.workers) as ex:
        results = list(ex.map(status, checked))

    broken = [(u, s) for u, s in results if s is None or s >= 400]
    scan.info["links"] = {"found": len(links), "checked": len(checked), "broken": len(broken)}
    if broken:
        sample = ", ".join(f"{u} ({s or 'no response'})" for u, s in broken[:5])
        more = f" and {len(broken) - 5} more" if len(broken) > 5 else ""
        scan.add("broken_links", f"{len(broken)} broken internal link(s)", "info", 0,
                 sample + more, "Fix or remove the dead links.", "links")
