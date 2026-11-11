"""Security response headers."""
from __future__ import annotations

import re


def _csp_directives(csp: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        name, _, value = part.partition(" ")
        out.setdefault(name.lower(), value.strip().lower())
    return out


def _meta_csp(scan) -> str:
    if not scan.soup:
        return ""
    tag = scan.soup.find("meta", attrs={"http-equiv": lambda v: v and v.lower() == "content-security-policy"})
    return (tag.get("content") or "").strip() if tag else ""


def check_headers(scan) -> None:
    h = scan.response.headers
    cat = "headers"

    # --- Content-Security-Policy ------------------------------------------
    csp = h.get("Content-Security-Policy", "").strip()
    meta_csp = _meta_csp(scan)
    if not csp and not meta_csp:
        scan.add("missing_csp", "Content-Security-Policy is missing", "medium", 6,
                 "No CSP header or <meta> CSP found. Injected scripts would run freely.",
                 "Add a Content-Security-Policy header, start with default-src 'self'.", cat)
    elif not csp:
        scan.add("csp_meta_only", "CSP is only set via <meta>", "info", 0,
                 "A <meta> CSP cannot use frame-ancestors or report-uri.",
                 "Prefer sending CSP as an HTTP header.", cat)

    directives = _csp_directives(csp or meta_csp)
    script_src = directives.get("script-src", directives.get("default-src"))
    if script_src is not None:
        has_nonce_or_hash = "'nonce-" in script_src or re.search(r"'sha(256|384|512)-", script_src)
        weak = []
        if "'unsafe-inline'" in script_src and not has_nonce_or_hash:
            weak.append("'unsafe-inline'")
        if "'unsafe-eval'" in script_src:
            weak.append("'unsafe-eval'")
        if weak:
            scan.add("csp_weak_scripts", "CSP allows unsafe script sources", "low", 2,
                     f"script-src permits {', '.join(weak)}, which weakens XSS protection.",
                     "Use nonces or hashes instead of 'unsafe-inline'/'unsafe-eval'.", cat)

    # --- HSTS (only meaningful over HTTPS) ---------------------------------
    if scan.is_https:
        hsts = h.get("Strict-Transport-Security", "")
        if not hsts:
            scan.add("missing_hsts", "Strict-Transport-Security is missing", "medium", 5,
                     "Browsers may still try plain HTTP first (SSL-strip risk).",
                     "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains", cat)
        else:
            m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
            age = int(m.group(1)) if m else 0
            if age < 15552000:  # 180 days
                scan.add("hsts_short", "HSTS max-age is short", "low", 2,
                         f"max-age={age} seconds (less than 180 days).",
                         "Use max-age=31536000 (one year) or more.", cat)

    # --- Clickjacking -------------------------------------------------------
    if "X-Frame-Options" not in h and "frame-ancestors" not in _csp_directives(csp):
        scan.add("missing_clickjacking", "Clickjacking protection is missing", "medium", 4,
                 "Neither X-Frame-Options nor CSP frame-ancestors is set.",
                 "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'.", cat)

    xcto = h.get("X-Content-Type-Options", "")
    if xcto.strip().lower() != "nosniff":
        scan.add("missing_nosniff", "X-Content-Type-Options: nosniff is missing", "medium", 4,
                 "Browsers may MIME-sniff responses into executable content." if not xcto
                 else f"Unexpected value: {xcto}",
                 "Add X-Content-Type-Options: nosniff", cat)

    ref = h.get("Referrer-Policy", "").strip().lower()
    if not ref:
        scan.add("missing_referrer_policy", "Referrer-Policy is missing", "low", 3,
                 "Full URLs (with tokens in query strings) may leak to other sites.",
                 "Add Referrer-Policy: strict-origin-when-cross-origin", cat)
    elif "unsafe-url" in ref:
        scan.add("weak_referrer_policy", "Referrer-Policy is unsafe-url", "low", 3,
                 "Full URLs are sent to every site, even over HTTP.",
                 "Use strict-origin-when-cross-origin or no-referrer.", cat)

    if "Permissions-Policy" not in h:
        scan.add("missing_permissions_policy", "Permissions-Policy is missing", "low", 2,
                 "Browser features (camera, mic, geolocation) are not restricted.",
                 "Add e.g. Permissions-Policy: camera=(), microphone=(), geolocation=()", cat)

    # --- Information disclosure --------------------------------------------
    server = h.get("Server", "").strip()
    if server:
        if re.search(r"\d", server):
            scan.add("server_version_exposed", "Server version is exposed", "low", 2,
                     f"Server: {server}",
                     "Hide version numbers (e.g. nginx server_tokens off; Apache ServerTokens Prod).",
                     cat)
        else:
            scan.add("server_banner", "Server banner present", "info", 0,
                     f"Server: {server}", "", cat)

    for name in ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"):
        value = h.get(name, "").strip()
        if value:
            scan.add(f"disclosure_{name.lower()}", f"{name} header is exposed", "low", 2,
                     f"{name}: {value}", f"Remove the {name} header.", cat)
