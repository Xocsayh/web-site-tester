from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from cookiemonster import __version__
from cookiemonster.utils import (
    LEVEL_MOODS,
    SEVERITY_ORDER,
    base_url,
    clamp_score,
    detect_level,
)

USER_AGENT = f"CookieMonster/{__version__} (+passive security audit; om nom nom)"

# Hosts behind these platforms often enforce controls at the edge, so header
# findings are more likely to be false positives.
EDGE_PLATFORMS = {"Cloudflare", "Vercel", "Netlify", "Akamai", "Fastly", "Google"}


@dataclass
class Finding:
    key: str
    title: str
    severity: str  # info | low | medium | high
    penalty: int
    detail: str
    fix: str = ""
    category: str = "general"


@dataclass
class ScanOptions:
    timeout: float = 8.0
    threshold: int = 50
    probe_files: bool = True
    check_links: bool = True
    max_links: int = 30
    verify_tls: bool = True
    user_agent: str = USER_AGENT
    workers: int = 8
    http_fallback: bool = False  # user typed no scheme: try http:// if https:// fails


@dataclass
class Probe:
    status: int
    headers: dict[str, str]
    body: bytes
    url: str

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").lower()

    @property
    def looks_html(self) -> bool:
        head = self.text[:512].lstrip().lower()
        return "html" in self.content_type or head.startswith(("<!doctype html", "<html"))


class Scan:
    """Holds everything the individual checks need and collect."""

    def __init__(self, url: str, options: ScanOptions | None = None) -> None:
        self.url = url
        self.options = options or ScanOptions()
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.options.user_agent})
        self.session.verify = self.options.verify_tls
        self.response: requests.Response | None = None
        self.soup: BeautifulSoup | None = None
        self.error: str | None = None
        self.findings: list[Finding] = []
        self.technology: set[str] = set()
        self.info: dict[str, Any] = {}
        self._keys: set[str] = set()

    # ---- helpers used by checks -------------------------------------------
    @property
    def final_url(self) -> str:
        return self.response.url if self.response is not None else self.url

    @property
    def is_https(self) -> bool:
        return urlparse(self.final_url).scheme == "https"

    @property
    def base(self) -> str:
        return base_url(self.final_url)

    @property
    def host(self) -> str:
        return urlparse(self.final_url).hostname or ""

    def absolute(self, link: str) -> str:
        return urljoin(self.final_url, link)

    def add(self, key: str, title: str, severity: str, penalty: int, detail: str,
            fix: str = "", category: str = "general") -> None:
        if key in self._keys:
            return
        self._keys.add(key)
        self.findings.append(Finding(key, title, severity, penalty, detail, fix, category))

    def probe(self, path_or_url: str, max_bytes: int = 4096, method: str = "GET",
              headers: dict[str, str] | None = None,
              allow_redirects: bool = False) -> Probe | None:
        """Small, bounded request. Never follows redirects by default so a
        redirect to a login/404 page is not mistaken for an exposed file."""
        url = path_or_url if "://" in path_or_url else urljoin(self.base + "/", path_or_url.lstrip("/"))
        try:
            with self.session.request(method, url, timeout=self.options.timeout,
                                      allow_redirects=allow_redirects, stream=True,
                                      headers=headers) as resp:
                body = b""
                if method != "HEAD":
                    for chunk in resp.iter_content(1024):
                        body += chunk
                        if len(body) >= max_bytes:
                            break
                return Probe(resp.status_code,
                             {k.lower(): v for k, v in resp.headers.items()},
                             body[:max_bytes], resp.url)
        except (requests.RequestException, ValueError):
            return None

    # ---- main flow ---------------------------------------------------------
    def _get(self, url: str) -> requests.Response:
        return self.session.get(url, timeout=self.options.timeout, allow_redirects=True)

    def fetch(self) -> bool:
        try:
            self.response = self._get(self.url)
        except requests.RequestException as exc:
            cert_problem = isinstance(exc, requests.exceptions.SSLError) and "CERTIFICATE_VERIFY_FAILED" in str(exc)
            if cert_problem:
                self.error = f"TLS certificate error: {exc}. Use --insecure (-k) to scan anyway."
                return False
            if not (self.options.http_fallback and self.url.startswith("https://")):
                self.error = f"Connection failed: {exc}"
                return False
            # No scheme was typed and HTTPS does not work -> try plain HTTP.
            try:
                self.response = self._get("http://" + self.url[len("https://"):])
            except requests.RequestException:
                self.error = f"Connection failed (tried https and http): {exc}"
                return False
            self.info["https_unavailable"] = str(exc)
        content_type = self.response.headers.get("Content-Type", "").lower()
        if "html" in content_type or self.response.text.lstrip()[:15].lower().startswith(("<!doctype", "<html")):
            self.soup = BeautifulSoup(self.response.text, "html.parser")
        return True

    def run(self, checks: list[Callable[["Scan"], None]] | None = None) -> dict[str, Any]:
        from cookiemonster.checks import ALL_CHECKS

        started = datetime.now(timezone.utc)
        if self.fetch():
            for check in checks if checks is not None else ALL_CHECKS:
                try:
                    check(self)
                except Exception as exc:  # one broken check must not kill the scan
                    self.info.setdefault("check_errors", []).append(
                        f"{getattr(check, '__name__', check)}: {exc}")
        return self.build_result(started)

    def build_result(self, started: datetime) -> dict[str, Any]:
        findings = sorted(self.findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), -f.penalty))
        result: dict[str, Any] = {
            "tool": "CookieMonster",
            "version": __version__,
            "target": self.url,
            "final_url": self.final_url,
            "scanned_at": started.isoformat(timespec="seconds"),
            "threshold": self.options.threshold,
        }
        if self.error:
            result.update(status="unreachable", score=None, level="unreachable",
                          message=self.error, findings=[], technology_hints=[],
                          summary={}, info=self.info)
            return result

        score = clamp_score(100 - sum(f.penalty for f in findings))
        level = detect_level(score)
        summary = {sev: 0 for sev in SEVERITY_ORDER}
        for f in findings:
            summary[f.severity] = summary.get(f.severity, 0) + 1

        result.update(
            status="ok",
            score=score,
            level=level,
            mood=LEVEL_MOODS[level],
            summary=summary,
            technology_hints=sorted(self.technology),
            findings=[asdict(f) for f in findings],
            info=self.info,
        )
        if score < 50:
            result["message"] = "Site needs urgent attention."
        elif score < 70:
            result["message"] = "Site needs improvement."
        if self.technology & EDGE_PLATFORMS:
            result["note"] = ("Site is behind an edge/CDN platform that may apply its own "
                              "security controls. Some header findings can be false positives.")
        return result


def scan(url: str, options: ScanOptions | None = None) -> dict[str, Any]:
    return Scan(url, options).run()
