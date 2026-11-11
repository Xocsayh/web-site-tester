"""Basic speed/size metrics. Reported as info - they never change the security score."""
from __future__ import annotations


def check_performance(scan) -> None:
    resp = scan.response
    size = len(resp.content)
    encoding = resp.headers.get("Content-Encoding", "").lower() or None
    total_ms = int(sum(r.elapsed.total_seconds() for r in resp.history) * 1000
                   + resp.elapsed.total_seconds() * 1000)
    perf = {
        "response_ms": int(resp.elapsed.total_seconds() * 1000),
        "total_ms_with_redirects": total_ms,
        "redirects": len(resp.history),
        "html_kb": round(size / 1024, 1),
        "compression": encoding,
        "cache_control": resp.headers.get("Cache-Control"),
    }
    if scan.soup:
        perf["scripts"] = len(scan.soup.find_all("script", src=True))
        perf["stylesheets"] = len([l for l in scan.soup.find_all("link")
                                   if "stylesheet" in [r.lower() for r in (l.get("rel") or [])]])
        perf["images"] = len(scan.soup.find_all("img"))
    scan.info["performance"] = perf

    cat = "performance"
    if perf["response_ms"] > 1500:
        scan.add("perf_slow", "Slow server response", "info", 0,
                 f"Main page took {perf['response_ms']} ms (aim for < 800 ms).",
                 "Add caching / a CDN, check slow database queries.", cat)
    if perf["redirects"] >= 3:
        scan.add("perf_redirects", "Long redirect chain", "info", 0,
                 f"{perf['redirects']} redirects before the page loads.",
                 "Link directly to the final URL.", cat)
    if size > 10 * 1024 and encoding not in ("gzip", "br", "zstd", "deflate"):
        scan.add("perf_no_compression", "HTML is not compressed", "info", 0,
                 f"{perf['html_kb']} KB sent without gzip/brotli.",
                 "Enable gzip or brotli compression.", cat)
    if size > 1024 * 1024:
        scan.add("perf_big_html", "Very large HTML page", "info", 0,
                 f"{perf['html_kb']} KB of HTML.", "Paginate or lazy-load content.", cat)
