from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from web_site_tester.utils import clamp_score, detect_level


RISK_WEIGHTS = {
    "https_disabled": 20,
    "login_insecure_submit": 20,
    "cookie_missing_secure_sensitive": 10,
    "cookie_missing_secure_regular": 4,
    "cookie_missing_httponly_sensitive": 8,
    "cookie_missing_httponly_regular": 3,
    "cookie_missing_samesite_sensitive": 6,
    "cookie_missing_samesite_regular": 2,
    "missing_csp": 6,
    "missing_hsts": 5,
    "missing_x_frame_options": 4,
    "missing_x_content_type_options": 4,
    "missing_referrer_policy": 3,
    "missing_permissions_policy": 2,
    "server_banner_exposed": 1,
    "x_powered_by_exposed": 2,
    "missing_security_txt": 1,
    "missing_robots_txt": 0,
    "missing_sitemap_xml": 0,
    "missing_csrf_hint": 2,
}


@dataclass
class Finding:
    title: str
    severity: str
    penalty: int
    detail: str


class WebSiteTesterScanner:
    def __init__(self, url: str, timeout: int = 8, threshold: int = 50) -> None:
        self.url = url
        self.timeout = timeout
        self.threshold = threshold
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "WebSiteTester/2.0 (+Passive Security Audit Tool)"
        })
        self.response: requests.Response | None = None
        self.soup: BeautifulSoup | None = None
        self.score = 100
        self.findings: list[Finding] = []
        self.technology_hints: list[str] = []
        self.finding_keys: set[str] = set()

    def add_finding(self, key: str, title: str, severity: str, penalty: int, detail: str) -> None:
        if key in self.finding_keys:
            return
        self.finding_keys.add(key)
        self.findings.append(
            Finding(title=title, severity=severity, penalty=penalty, detail=detail)
        )
        self.score -= penalty

    def fetch(self) -> bool:
        try:
            self.response = self.session.get(
                self.url,
                timeout=self.timeout,
                allow_redirects=True
            )
            content_type = self.response.headers.get("Content-Type", "").lower()
            if "html" in content_type:
                self.soup = BeautifulSoup(self.response.text, "html.parser")
            return True
        except requests.RequestException as exc:
            self.add_finding(
                "website_unreachable",
                "Website unreachable",
                "high",
                60,
                f"Connection failed: {exc}"
            )
            return False

    def check_https(self) -> None:
        current = self.response.url if self.response else self.url
        if urlparse(current).scheme != "https":
            self.add_finding(
                "https_disabled",
                "HTTPS is not enabled",
                "high",
                RISK_WEIGHTS["https_disabled"],
                "The website is running over HTTP instead of HTTPS."
            )

    def check_security_headers(self) -> None:
        if not self.response:
            return

        headers = self.response.headers
        checks = [
            (
                "Content-Security-Policy",
                "missing_csp",
                "Content-Security-Policy is missing",
                "medium",
                "Content Security Policy is missing. This may increase script injection risk."
            ),
            (
                "Strict-Transport-Security",
                "missing_hsts",
                "Strict-Transport-Security is missing",
                "medium",
                "HSTS header is missing."
            ),
            (
                "X-Frame-Options",
                "missing_x_frame_options",
                "X-Frame-Options is missing",
                "medium",
                "Clickjacking protection header is missing."
            ),
            (
                "X-Content-Type-Options",
                "missing_x_content_type_options",
                "X-Content-Type-Options is missing",
                "medium",
                "MIME sniffing protection header is missing."
            ),
            (
                "Referrer-Policy",
                "missing_referrer_policy",
                "Referrer-Policy is missing",
                "low",
                "Referrer-Policy is missing."
            ),
            (
                "Permissions-Policy",
                "missing_permissions_policy",
                "Permissions-Policy is missing",
                "low",
                "Permissions-Policy is missing."
            ),
        ]

        for header_name, key, title, severity, detail in checks:
            if header_name not in headers:
                self.add_finding(key, title, severity, RISK_WEIGHTS[key], detail)

        server = headers.get("Server", "").strip()
        if server:
            self.add_finding(
                "server_banner_exposed",
                "Server banner exposed",
                "info",
                RISK_WEIGHTS["server_banner_exposed"],
                f"Server information is exposed: {server}"
            )
            self.technology_hints.append(f"Server: {server}")

        powered_by = headers.get("X-Powered-By", "").strip()
        if powered_by:
            self.add_finding(
                "x_powered_by_exposed",
                "X-Powered-By exposed",
                "low",
                RISK_WEIGHTS["x_powered_by_exposed"],
                f"Technology stack information is exposed: {powered_by}"
            )
            self.technology_hints.append(f"X-Powered-By: {powered_by}")

    def check_cookies(self) -> None:
        if not self.response:
            return

        sensitive_names = ["session", "auth", "token", "jwt", "secure", "login"]

        for cookie in self.response.cookies:
            cookie_name = cookie.name.lower()
            is_sensitive = any(word in cookie_name for word in sensitive_names)

            if not cookie.secure:
                penalty = (
                    RISK_WEIGHTS["cookie_missing_secure_sensitive"]
                    if is_sensitive else
                    RISK_WEIGHTS["cookie_missing_secure_regular"]
                )
                severity = "medium" if is_sensitive else "low"
                self.add_finding(
                    f"cookie_secure_{cookie.name}",
                    f"Cookie missing Secure flag: {cookie.name}",
                    severity,
                    penalty,
                    "Cookie is transmitted without Secure flag."
                )

            if "httponly" not in str(cookie._rest).lower():
                penalty = (
                    RISK_WEIGHTS["cookie_missing_httponly_sensitive"]
                    if is_sensitive else
                    RISK_WEIGHTS["cookie_missing_httponly_regular"]
                )
                severity = "medium" if is_sensitive else "low"
                self.add_finding(
                    f"cookie_httponly_{cookie.name}",
                    f"Cookie missing HttpOnly flag: {cookie.name}",
                    severity,
                    penalty,
                    "Cookie is missing HttpOnly flag."
                )

            same_site = None
            for key, value in cookie._rest.items():
                if key.lower() == "samesite":
                    same_site = value
                    break

            if same_site is None:
                penalty = (
                    RISK_WEIGHTS["cookie_missing_samesite_sensitive"]
                    if is_sensitive else
                    RISK_WEIGHTS["cookie_missing_samesite_regular"]
                )
                severity = "medium" if is_sensitive else "low"
                self.add_finding(
                    f"cookie_samesite_{cookie.name}",
                    f"Cookie missing SameSite flag: {cookie.name}",
                    severity,
                    penalty,
                    "Cookie is missing SameSite flag."
                )

    def check_common_files(self) -> None:
        current = self.response.url if self.response else self.url
        parsed = urlparse(current)
        base = f"{parsed.scheme}://{parsed.netloc}"

        paths = [
            (
                "robots.txt",
                "/robots.txt",
                "missing_robots_txt",
                "robots.txt is missing",
                "info",
                "robots.txt was not found."
            ),
            (
                "security.txt",
                "/.well-known/security.txt",
                "missing_security_txt",
                "security.txt is missing",
                "low",
                "security.txt was not found."
            ),
            (
                "sitemap.xml",
                "/sitemap.xml",
                "missing_sitemap_xml",
                "sitemap.xml is missing",
                "info",
                "sitemap.xml was not found."
            ),
        ]

        def worker(item: tuple[str, str, str, str, str, str]) -> tuple[str, str, str, int, str, bool]:
            _, path, key, title, severity, detail = item
            try:
                resp = self.session.get(urljoin(base, path), timeout=self.timeout)
                ok = resp.status_code == 200 and bool(resp.text.strip())
                penalty = RISK_WEIGHTS[key]
                return key, title, severity, penalty, detail, ok
            except requests.RequestException:
                penalty = RISK_WEIGHTS[key]
                return key, title, severity, penalty, detail, False

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(worker, item) for item in paths]
            for future in as_completed(futures):
                key, title, severity, penalty, detail, ok = future.result()
                if not ok:
                    self.add_finding(key, title, severity, penalty, detail)

    def check_forms(self) -> None:
        if not self.soup or not self.response:
            return

        forms = self.soup.find_all("form")
        for form in forms:
            inputs = form.find_all("input")
            password_inputs = [
                inp for inp in inputs
                if inp.get("type", "").lower() == "password"
            ]
            if not password_inputs:
                continue

            action = form.get("action", "").strip()
            full_action = urljoin(self.response.url, action) if action else self.response.url

            if full_action.startswith("http://"):
                self.add_finding(
                    "login_insecure_submit",
                    "Login form submits to an insecure endpoint",
                    "high",
                    RISK_WEIGHTS["login_insecure_submit"],
                    f"Form action uses HTTP: {full_action}"
                )

            hidden_names = [
                (inp.get("name") or "").lower()
                for inp in inputs
                if inp.get("type", "").lower() == "hidden"
            ]
            token_patterns = ["csrf", "token", "authenticity"]
            has_csrf_hint = any(
                any(token in name for token in token_patterns)
                for name in hidden_names
            )

            if not has_csrf_hint:
                self.add_finding(
                    "missing_csrf_hint",
                    "No visible CSRF token hint found in login form",
                    "low",
                    RISK_WEIGHTS["missing_csrf_hint"],
                    "No hidden input suggesting CSRF protection was detected."
                )

    def detect_technology(self) -> None:
        if not self.soup or not self.response:
            return

        generator = self.soup.find(
            "meta",
            attrs={"name": lambda v: v and v.lower() == "generator"}
        )
        if generator and generator.get("content"):
            self.technology_hints.append(
                f"Generator: {generator.get('content').strip()}"
            )

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
            "vercel": "Vercel",
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

        message = None
        if self.score < 50:
            message = "Site needs urgent attention."
        elif self.score < 70:
            message = "Site needs improvement."

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

        advanced_markers = {
            "Server: gws",
            "Server: Vercel",
            "Cloudflare",
            "Next.js",
            "React",
            "Vercel",
        }

        if any(item in advanced_markers for item in result["technology_hints"]):
            result["note"] = (
                "Advanced platforms may use custom security controls. "
                "Some findings can be false positives."
            )

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