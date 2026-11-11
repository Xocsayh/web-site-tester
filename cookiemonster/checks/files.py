"""Well-known files and accidentally exposed sensitive files.

Exposure probes are single, bounded GET requests to a short list of
well-known paths. Every hit is confirmed by content signature, so a
"200 OK" soft-404 page is never reported as a leak.
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

from cookiemonster.scanner import Probe


# ---- well-known files -------------------------------------------------------
def _is_robots(p: Probe) -> bool:
    return not p.looks_html and re.search(r"(?im)^\s*(user-agent|disallow|allow|sitemap)\s*:", p.text) is not None


def _is_security_txt(p: Probe) -> bool:
    return not p.looks_html and re.search(r"(?im)^\s*contact\s*:", p.text) is not None


def _is_sitemap(p: Probe) -> bool:
    t = p.text[:2048].lower()
    return "<urlset" in t or "<sitemapindex" in t


def check_well_known(scan) -> None:
    items = [
        ("robots.txt", "/robots.txt", _is_robots),
        ("security.txt", "/.well-known/security.txt", _is_security_txt),
        ("sitemap.xml", "/sitemap.xml", _is_sitemap),
    ]
    found = {}
    with ThreadPoolExecutor(max_workers=3) as ex:
        results = list(ex.map(lambda it: (it[0], scan.probe(it[1], allow_redirects=True), it[2]), items))
    for name, probe, valid in results:
        found[name] = bool(probe and probe.status == 200 and valid(probe))
    scan.info["well_known"] = found

    if not found["security.txt"]:
        scan.add("missing_security_txt", "security.txt is missing", "low", 1,
                 "Researchers have no documented way to report vulnerabilities.",
                 "Publish /.well-known/security.txt with at least a Contact: line (RFC 9116).",
                 "files")
    for name in ("robots.txt", "sitemap.xml"):
        if not found[name]:
            scan.add(f"missing_{name.replace('.', '_')}", f"{name} not found", "info", 0,
                     f"No valid {name} (this is about SEO, not security).", "", "files")


# ---- exposure probes --------------------------------------------------------
Sig = Callable[[Probe], bool]


def _git_head(p: Probe) -> bool:
    return p.text.startswith("ref: refs/") or re.fullmatch(r"[0-9a-f]{40}\s*", p.text) is not None


def _git_config(p: Probe) -> bool:
    return "[core]" in p.text and not p.looks_html


def _env(p: Probe) -> bool:
    if p.looks_html:
        return False
    lines = [l for l in p.text.splitlines() if l.strip() and not l.lstrip().startswith("#")]
    kv = [l for l in lines if re.match(r"^\s*(export\s+)?[A-Z][A-Z0-9_]*\s*=", l)]
    return len(kv) >= 2 and len(kv) >= len(lines) * 0.6


def _ds_store(p: Probe) -> bool:
    return p.body[:8] == b"\x00\x00\x00\x01Bud1"


def _zip(p: Probe) -> bool:
    return p.body[:4] == b"PK\x03\x04"


def _gzip_tar(p: Probe) -> bool:
    return p.body[:2] == b"\x1f\x8b"


def _sql(p: Probe) -> bool:
    return not p.looks_html and re.search(r"(?i)\b(create table|insert into|mysql dump|postgresql database dump)\b", p.text) is not None


def _phpinfo(p: Probe) -> bool:
    return "phpinfo()" in p.text and "PHP Version" in p.text


def _server_status(p: Probe) -> bool:
    return "Apache Server Status" in p.text or "Server uptime:" in p.text


def _wp_config(p: Probe) -> bool:
    return "DB_PASSWORD" in p.text and "define(" in p.text


def _svn(p: Probe) -> bool:
    return p.body[:16].startswith(b"SQLite format 3") and not p.looks_html


def _dir_listing(p: Probe) -> bool:
    t = p.text[:4096]
    return "<title>Index of /" in t or "<h1>Index of /" in t


EXPOSURE_PROBES: list[tuple[str, str, str, int, Sig, str]] = [
    # path, title, severity, penalty, signature, fix
    ("/.git/HEAD", "Git repository is exposed", "high", 30, _git_head,
     "Block /.git in the web server and never deploy the .git folder; the full source code can be downloaded."),
    ("/.git/config", "Git config is exposed", "high", 30, _git_config,
     "Block /.git in the web server; it can reveal remotes and credentials."),
    ("/.env", ".env file is exposed", "high", 35, _env,
     "Remove .env from the web root, block dotfiles, and ROTATE every secret in it."),
    ("/.svn/wc.db", "SVN working copy is exposed", "high", 25, _svn,
     "Block /.svn and do not deploy version-control folders."),
    ("/wp-config.php.bak", "WordPress config backup is exposed", "high", 35, _wp_config,
     "Delete the backup and rotate the database password."),
    ("/backup.sql", "Database dump is exposed", "high", 35, _sql,
     "Delete the dump from the web root; assume the data is leaked."),
    ("/dump.sql", "Database dump is exposed", "high", 35, _sql,
     "Delete the dump from the web root; assume the data is leaked."),
    ("/db.sql", "Database dump is exposed", "high", 35, _sql,
     "Delete the dump from the web root; assume the data is leaked."),
    ("/backup.zip", "Backup archive is exposed", "high", 25, _zip,
     "Move backups outside the web root."),
    ("/site.zip", "Backup archive is exposed", "high", 25, _zip,
     "Move backups outside the web root."),
    ("/backup.tar.gz", "Backup archive is exposed", "high", 25, _gzip_tar,
     "Move backups outside the web root."),
    ("/phpinfo.php", "phpinfo() page is public", "medium", 8, _phpinfo,
     "Delete phpinfo.php; it reveals versions, paths and environment variables."),
    ("/info.php", "phpinfo() page is public", "medium", 8, _phpinfo,
     "Delete info.php; it reveals versions, paths and environment variables."),
    ("/server-status", "Apache server-status is public", "medium", 6, _server_status,
     "Restrict /server-status to localhost."),
    ("/.DS_Store", ".DS_Store file is exposed", "low", 3, _ds_store,
     "Delete .DS_Store files; they list file names in the folder."),
]


def check_exposed_files(scan) -> None:
    if not scan.options.probe_files:
        return

    def run(item):
        path = item[0]
        return item, scan.probe(path, max_bytes=8192)

    hits = []
    with ThreadPoolExecutor(max_workers=min(scan.options.workers, len(EXPOSURE_PROBES))) as ex:
        for item, probe in ex.map(run, EXPOSURE_PROBES):
            path, title, severity, penalty, signature, fix = item
            if probe and probe.status == 200 and probe.body and signature(probe):
                hits.append(path)
                key = "exposed_" + re.sub(r"\W+", "_", title.lower()).strip("_")
                scan.add(key if key not in scan._keys else key + path, title, severity, penalty,
                         f"{scan.base}{path} is publicly readable.", fix, "exposure")
    scan.info["exposed_paths"] = hits

    # Directory listing on the site root's common asset folders
    for path in ("/uploads/", "/backup/", "/files/"):
        p = scan.probe(path, max_bytes=4096)
        if p and p.status == 200 and _dir_listing(p):
            scan.add("directory_listing", "Directory listing is enabled", "medium", 5,
                     f"{scan.base}{path} lists its files.",
                     "Disable autoindex/Options Indexes in the web server.", "exposure")
            break
