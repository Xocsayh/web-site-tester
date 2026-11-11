"""Offline tests: a local HTTP server plays the target website.

Run:  python -m unittest discover -s tests -v
"""
from __future__ import annotations

import io
import json
import threading
import time
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from betterpent.checks import (
    check_cookies, check_cors, check_exposed_files, check_forms, check_headers,
    check_links, check_mixed_content, check_performance, check_well_known, detect_technology,
)
from betterpent.cli import main
from betterpent.reporting import render_html
from betterpent.scanner import Scan, ScanOptions
from betterpent.utils import days_until, normalize_url, parse_set_cookie

LOCAL_CHECKS = [detect_technology, check_headers, check_cookies, check_forms, check_mixed_content,
                check_cors, check_well_known, check_exposed_files, check_links, check_performance]


class Site:
    """routes: path -> (status, headers(list of tuples), body str|bytes)"""

    def __init__(self, routes, server="BaseHTTP/0.6 Python/3"):
        self.routes = routes
        site = self

        class Handler(BaseHTTPRequestHandler):
            server_version = server
            sys_version = ""

            def log_message(self, *a):
                pass

            def _serve(self, with_body):
                path = self.path.split("?")[0]
                status, headers, body = site.routes.get(path, (404, [("Content-Type", "text/html")], "<html>nope</html>"))
                if callable(body):
                    body = body(self)
                data = body.encode() if isinstance(body, str) else body
                self.send_response(status)
                for k, v in headers:
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                if with_body:
                    self.wfile.write(data)

            def do_GET(self):
                self._serve(True)

            def do_HEAD(self):
                self._serve(False)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}/"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def run_scan(routes, checks=None, server="BaseHTTP/0.6 Python/3", **opts):
    site = Site(routes, server)
    try:
        return Scan(site.url, ScanOptions(timeout=3, **opts)).run(LOCAL_CHECKS if checks is None else checks)
    finally:
        site.close()


def keys(result):
    return {f["key"] for f in result["findings"]}


HTML = [("Content-Type", "text/html; charset=utf-8")]


class UtilsTest(unittest.TestCase):
    def test_normalize_url(self):
        self.assertEqual(normalize_url("example.com"), "https://example.com/")
        self.assertEqual(normalize_url(" http://a.b/x "), "http://a.b/x")
        with self.assertRaises(ValueError):
            normalize_url("   ")

    def test_parse_set_cookie(self):
        name, attrs = parse_set_cookie("sessionid=abc=def; Path=/; Secure; HttpOnly; SameSite=Lax")
        self.assertEqual(name, "sessionid")
        self.assertIn("secure", attrs)
        self.assertIn("httponly", attrs)
        self.assertEqual(attrs["samesite"], "Lax")

    def test_days_until(self):
        now = time.mktime(time.strptime("2026-01-01", "%Y-%m-%d"))
        self.assertGreater(days_until("Jun  1 12:00:00 2026 GMT", now), 140)
        self.assertLess(days_until("Jun  1 12:00:00 2025 GMT", now), 0)


class ScanTest(unittest.TestCase):
    def test_unreachable_is_not_scored(self):
        result = Scan("http://127.0.0.1:9/", ScanOptions(timeout=1)).run()
        self.assertEqual(result["status"], "unreachable")
        self.assertIsNone(result["score"])

    def test_http_fallback_when_no_scheme(self):
        # The local server only speaks HTTP, so https:// fails with an SSL error.
        site = Site({"/": (200, HTML, "<html>plain</html>")})
        try:
            host = site.url.split("://", 1)[1]
            r = Scan("https://" + host, ScanOptions(timeout=3, http_fallback=True)).run(
                [__import__("betterpent.checks", fromlist=["check_https"]).check_https])
            r2 = Scan("https://" + host, ScanOptions(timeout=3, http_fallback=False)).run([])
        finally:
            site.close()
        self.assertEqual(r["status"], "ok")
        self.assertTrue(r["final_url"].startswith("http://"))
        self.assertIn("https_disabled", keys(r))
        self.assertEqual(r2["status"], "unreachable")

    def test_bare_site_findings(self):
        r = run_scan({"/": (200, HTML, "<html><body>hi</body></html>")})
        k = keys(r)
        for expected in ("missing_csp", "missing_clickjacking", "missing_nosniff",
                         "missing_referrer_policy", "missing_permissions_policy", "missing_security_txt"):
            self.assertIn(expected, k)
        self.assertNotIn("missing_hsts", k)  # HSTS is meaningless over plain HTTP
        self.assertEqual(r["status"], "ok")

    def test_hardened_site_is_clean(self):
        headers = HTML + [
            ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "strict-origin-when-cross-origin"),
            ("Permissions-Policy", "camera=()"),
            ("Set-Cookie", "session=1; Path=/; HttpOnly; SameSite=Lax"),
        ]
        r = run_scan({
            "/": (200, headers, "<html><body>ok</body></html>"),
            "/.well-known/security.txt": (200, [("Content-Type", "text/plain")], "Contact: mailto:a@b.c\n"),
            "/robots.txt": (200, [("Content-Type", "text/plain")], "User-agent: *\nDisallow:\n"),
            "/sitemap.xml": (200, [("Content-Type", "application/xml")], "<urlset></urlset>"),
        }, server="hardened")
        penalised = [f for f in r["findings"] if f["penalty"]]
        self.assertEqual(penalised, [], penalised)
        self.assertEqual(r["score"], 100)

    def test_frame_ancestors_counts_as_clickjacking_protection(self):
        r = run_scan({"/": (200, HTML + [("Content-Security-Policy", "frame-ancestors 'self'")], "<html></html>")},
                     checks=[check_headers])
        self.assertNotIn("missing_clickjacking", keys(r))

    def test_weak_csp(self):
        r = run_scan({"/": (200, HTML + [("Content-Security-Policy", "script-src 'self' 'unsafe-inline'")], "x")},
                     checks=[check_headers])
        self.assertIn("csp_weak_scripts", keys(r))

    def test_server_version_vs_banner(self):
        r = run_scan({"/": (200, HTML, "x")}, checks=[check_headers])
        # BaseHTTPRequestHandler sends "Server: BaseHTTP/0.6 Python/3.x" -> version exposed
        self.assertIn("server_version_exposed", keys(r))

    def test_cookies_from_redirect_are_checked(self):
        r = run_scan({
            "/": (302, [("Location", "/home"), ("Set-Cookie", "auth_token=x; Path=/")], ""),
            "/home": (200, HTML, "<html>home</html>"),
        }, checks=[check_cookies])
        k = keys(r)
        self.assertIn("cookie_httponly_auth_token", k)
        self.assertIn("cookie_samesite_auth_token", k)

    def test_samesite_none_without_secure(self):
        r = run_scan({"/": (200, HTML + [("Set-Cookie", "pref=1; SameSite=None")], "x")}, checks=[check_cookies])
        self.assertIn("cookie_samesite_none_pref", keys(r))

    def test_soft_404_is_not_a_file(self):
        soft = (200, HTML, "<!doctype html><html><title>Not found</title>Contact: us</html>")
        r = run_scan({"/": (200, HTML, "x"), "/robots.txt": soft, "/.well-known/security.txt": soft,
                      "/sitemap.xml": soft, "/.env": soft, "/.git/HEAD": soft},
                     checks=[check_well_known, check_exposed_files])
        self.assertIn("missing_security_txt", keys(r))
        self.assertFalse(r["info"]["exposed_paths"])

    def test_exposed_files_detected(self):
        r = run_scan({
            "/": (200, HTML, "x"),
            "/.git/HEAD": (200, [("Content-Type", "text/plain")], "ref: refs/heads/main\n"),
            "/.env": (200, [("Content-Type", "text/plain")], "DB_HOST=x\nDB_PASSWORD=secret\nAPP_KEY=1\n"),
            "/.DS_Store": (200, [("Content-Type", "application/octet-stream")], b"\x00\x00\x00\x01Bud1rest"),
        }, checks=[check_exposed_files])
        self.assertEqual(set(r["info"]["exposed_paths"]), {"/.git/HEAD", "/.env", "/.DS_Store"})
        self.assertLess(r["score"], 50)

    def test_no_probe_flag(self):
        r = run_scan({"/": (200, HTML, "x"), "/.env": (200, [], "A=1\nB=2\n")},
                     checks=[check_exposed_files], probe_files=False)
        self.assertEqual(r["findings"], [])

    def test_login_form(self):
        page = ('<html><form method="get" action="http://evil.example/login">'
                '<input name="u"><input type="password" name="p"></form></html>')
        r = run_scan({"/": (200, HTML, page)}, checks=[check_forms])
        self.assertTrue({"login_insecure_submit", "login_get_method", "missing_csrf_hint"} <= keys(r))

    def test_login_form_with_csrf(self):
        page = ('<html><form method="post" action="/login"><input type="hidden" name="csrf_token" value="1">'
                '<input type="password" name="p"></form></html>')
        r = run_scan({"/": (200, HTML, page)}, checks=[check_forms])
        self.assertEqual(keys(r), {"login_insecure_submit"})  # only because the test server is plain HTTP

    def test_cors_reflection(self):
        routes = {"/": (200, HTML, "x")}
        site = Site(routes)

        class H(site.server.RequestHandlerClass):
            def end_headers(self):
                origin = self.headers.get("Origin")
                if origin:
                    self.send_header("Access-Control-Allow-Origin", origin)
                    self.send_header("Access-Control-Allow-Credentials", "true")
                super().end_headers()
        site.server.RequestHandlerClass = H
        try:
            r = Scan(site.url, ScanOptions(timeout=3)).run([check_cors])
        finally:
            site.close()
        self.assertIn("cors_reflect_credentials", keys(r))

    def test_technology_no_false_positives(self):
        page = "<html><body>Click next to see how we react to a nice vue of the angular hills.</body></html>"
        r = run_scan({"/": (200, HTML, page)}, checks=[detect_technology])
        self.assertFalse({"Next.js", "React", "Vue", "Angular"} & set(r["technology_hints"]))

    def test_technology_real_markers(self):
        page = ('<html><head><script src="/_next/static/chunks/main.js"></script>'
                '<link rel="stylesheet" href="/wp-content/themes/x/style.css"></head></html>')
        r = run_scan({"/": (200, HTML, page)}, checks=[detect_technology])
        self.assertTrue({"Next.js", "WordPress"} <= set(r["technology_hints"]))

    def test_broken_links(self):
        page = '<html><a href="/ok">a</a><a href="/dead">b</a><a href="https://other.example/x">c</a><a href="#top">d</a></html>'
        r = run_scan({"/": (200, HTML, page), "/ok": (200, HTML, "ok")}, checks=[check_links])
        self.assertEqual(r["info"]["links"], {"found": 2, "checked": 2, "broken": 1})
        self.assertIn("broken_links", keys(r))

    def test_performance_never_penalises(self):
        r = run_scan({"/": (200, HTML, "<html>" + "a" * 20000 + "</html>")}, checks=[check_performance])
        self.assertIn("perf_no_compression", keys(r))
        self.assertEqual(r["score"], 100)


class ReportTest(unittest.TestCase):
    def test_html_report_escapes_untrusted_values(self):
        evil = "<script>alert(1)</script>"
        data = {"target": evil, "final_url": evil, "score": 10, "level": "critical", "status": "ok",
                "technology_hints": [evil], "summary": {"high": 1},
                "findings": [{"key": "x", "title": evil, "severity": "high'><img src=x onerror=alert(1)>",
                              "penalty": 1, "detail": evil, "fix": evil, "category": evil}],
                "info": {"cookies": [evil]}}
        html = render_html(data)
        self.assertNotIn("<script>alert", html)
        self.assertNotIn("<img src=x", html)
        self.assertIn("&lt;script&gt;", html)


class CliTest(unittest.TestCase):
    def test_json_stdout_and_exit_code(self):
        site = Site({"/": (200, HTML, "<html>x</html>")})
        buf = io.StringIO()
        try:
            with redirect_stdout(buf), self.assertRaises(SystemExit) as cm:
                main([site.url, "--json", "-", "--no-links", "--no-probe", "--threshold", "101"])
        finally:
            site.close()
        data = json.loads(buf.getvalue())
        self.assertEqual(data["tool"], "BetterPent")
        self.assertEqual(cm.exception.code, 1)  # score < 101

    def test_unreachable_exit_code(self):
        buf = io.StringIO()
        with redirect_stdout(buf), self.assertRaises(SystemExit) as cm:
            main(["http://127.0.0.1:9/", "-t", "1", "--no-color"])
        self.assertEqual(cm.exception.code, 2)
        self.assertIn("unreachable", buf.getvalue())

    def test_missing_target(self):
        with redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as cm:
            import contextlib
            with contextlib.redirect_stderr(io.StringIO()):
                main([])
        self.assertEqual(cm.exception.code, 3)


if __name__ == "__main__":
    unittest.main()
