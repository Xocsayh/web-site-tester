from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from web_site_tester.utils import clamp_score, detect_level


@dataclass
class Finding:
    title: str
    severity: str
    penalty: int
    detail: str


class WebSiteTesterScanner:
    def __init__(self, url: str, timeout: int = 8, threshold: int = 70) -> None:
        self.url = url
        self.timeout = timeout
        self.threshold = threshold
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "WebSiteTester/1.0 (+Passive Security Audit Tool)"
        })
        self.response: requests.Response | None = None
        self.soup: BeautifulSoup | None = None
        self.score = 100
        self.findings: list[Finding] = []
        self.technology_hints: list[str] = []

    def add_finding(self, title: str, severity: str, penalty: int, detail: str) -> None:
        self.findings.append(Finding(title=title, severity=severity, penalty=penalty, detail=detail))
        self.score -= penalty

    def fetch(self) -> bool:
        try:
            self.response = self.session.get(self.url, timeout=self.timeout, allow_redirects=True)
            content_type = self.response.headers.get("Content-Type", "").lower()
            if "html" in content_type:
                self.soup = BeautifulSoup(self.response.text, "html.parser")
            return True
        except requests.RequestException as exc:
            self.add_finding("Website unreachable", "high", 60, f"Connection failed: {exc}")
            return False

    def check_https(self) -> None:
        current = self.response.url if self.response else self.url
        if urlparse(current).scheme != "https":
            self.add_finding("HTTPS is not enabled", "high", 25, "The website is running over HTTP instead of HTTPS.")

    def check_security_headers(self) -> None:
        if not self.response:
            return

        headers = self.response.headers
        required = {
            "Content-Security-Policy": (12, "Content Security Policy is missing."),
            "Strict-Transport-Security": (10, "HSTS header is missing."),
            "X-Frame-Options": (8, "X-Frame-Options is missing."),
            "X-Content-Type-Options": (6, "X-Content-Type-Options is missing."),
            "Referrer-Policy": (5, "Referrer-Policy is missing."),
            "Permissions-Policy": (4, "Permissions-Policy is missing."),
        }

        for header_name, (penalty, detail) in required.items():
            if header_name not in headers:
                self.add_finding(f"{header_name} is missing", "medium", penalty, detail)

        server = headers.get("Server", "").strip()
        powered_by = headers.get("X-Powered-By", "").strip()

        if server:
            self.add_finding("Server banner exposed", "low", 3, f"Server information is exposed: {server}")
            self.technology_hints.append(f"Server: {server}")

        if powered_by:
            self.add_finding("X-Powered-By exposed", "low", 4, f"Technology stack information is exposed: {powered_by}")
            self.technology_hints.append(f"X-Powered-By: {powered_by}")

    def check_cookies(self) -> None:
        if not self.response:
            return

        for cookie in self.response.cookies:
            missing_flags: list[str] = []

            if not cookie.secure:
                missing_flags.append("Secure")

            if "httponly" not in str(cookie._rest).lower():
                missing_flags.append("HttpOnly")

            same_site = None
            for key, value in cookie._rest.items():
                if key.lower() == "samesite":
                    same_site = value
                    break

            if same_site is None:
                missing_flags.append("SameSite")

            if missing_flags:
                self.add_finding(
                    f"Cookie security flags missing: {cookie.name}",
                    "medium",
                    7,
                    f"Missing flags: {', '.join(missing_flags)}"
                )

    def check_common_files(self) -> None:
        current = self.response.url if self.response else self.url
        parsed = urlparse(current)
        base = f"{parsed.scheme}://{parsed.netloc}"

        paths = [
            ("robots.txt", "/robots.txt", 2, "robots.txt was not found."),
            ("security.txt", "/.well-known/security.txt", 5, "security.txt was not found."),
            ("sitemap.xml", "/sitemap.xml", 1, "sitemap.xml was not found."),
        ]

        def worker(item: tuple[str, str, int, str]) -> tuple[str, bool, int, str]:
            name, path, penalty, detail = item
            try:
                resp = self.session.get(urljoin(base, path), timeout=self.timeout)
                ok = resp.status_code == 200 and bool(resp.text.strip())
                return name, ok, penalty, detail
            except requests.RequestException:
                return name, False, penalty, detail

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(worker, item) for item in paths]
            for future in as_completed(futures):
                name, ok, penalty, detail = future.result()
                if not ok:
                    severity = "medium" if name == "security.txt" else "low"
                    self.add_finding(f"{name} is missing", severity, penalty, detail)

    def check_forms(self) -> None:
        if not self.soup or not self.response:
            return

        forms = self.soup.find_all("form")
        for form in forms:
            inputs = form.find_all("input")
            password_inputs = [i for i in inputs if i.get("type", "").lower() == "password"]
            if not password_inputs:
                continue

            action = form.get("action", "").strip()
            full_action = urljoin(self.response.url, action) if action else self.response.url

            if full_action.startswith("http://"):
                self.add_finding(
                    "Login form submits to an insecure endpoint",
                    "high",
                    20,
                    f"Form action uses HTTP: {full_action}"
                )

            hidden_names = [
                (inp.get("name") or "").lower()
                for inp in inputs if inp.get("type", "").lower() == "hidden"
            ]
            token_patterns = ["csrf", "token", "authenticity"]
            has_csrf_hint = any(any(token in name for token in token_patterns) for name in hidden_names)

            if not has_csrf_hint:
                self.add_finding(
                    "No visible CSRF token hint found in login form",
                    "low",
                    4,
                    "No hidden input suggesting CSRF protection was detected."
                )

    def detect_technology(self) -> None:
        if not self.soup or not self.response:
            return

        generator = self.soup.find("meta", attrs={"name": lambda v: v and v.lower() == "generator"})
        if generator and generator.get("content"):
            self.technology_hints.append(f"Generator: {generator.get('content').strip()}")

        html = self.response.text.lower()
        patterns = {
            "wordpress": "WordPress",
            "wp-content": "WordPress",
            "woocommerce": "WooCommerce",
            "react": "React",
            "next": "Next.js",
            "vue": "Vue",
            "angular": "Angular",
            "bootstrap": "Bootstrap",
            "jquery": "jQuery",
            "cloudflare": "Cloudflare",
        }

        for needle, label in patterns.items():
            if needle in html and label not in self.technology_hints:
                self.technology_hints.append(label)

        scripts = [script.get("src", "") for script in self.soup.find_all("script")]
        for src in scripts:
            lowered = src.lower()
            if "cdn.jsdelivr.net" in lowered and "Bootstrap" not in self.technology_hints:
                self.technology_hints.append("Bootstrap")
            if "react" in lowered and "React" not in self.technology_hints:
                self.technology_hints.append("React")

    def build_result(self) -> dict[str, Any]:
        self.score = clamp_score(self.score)
        level = detect_level(self.score)
        message = "Site needs attention." if self.score < self.threshold else None

        result: dict[str, Any] = {
            "target": self.response.url if self.response else self.url,
            "score": self.score,
            "level": level,
            "threshold": self.threshold,
            "technology_hints": sorted(set(self.technology_hints)),
            "findings": [asdict(item) for item in self.findings],
        }
        if message:
            result["message"] = message
        return result

    def run(self) -> dict[str, Any]:
        self.fetch()
        if self.response:
            self.check_https()
            self.check_security_headers()
            self.check_cookies()
            self.check_common_files()
            self.check_forms()
            self.detect_technology()
        return self.build_result()