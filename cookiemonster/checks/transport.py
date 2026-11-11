"""HTTPS, redirect and TLS certificate checks."""
from __future__ import annotations

import socket
import ssl
from urllib.parse import urlparse

import requests

from cookiemonster.utils import days_until


def check_https(scan) -> None:
    resp = scan.response
    chain = [r.url for r in resp.history] + [resp.url]

    if not scan.is_https:
        no_tls = " (port 443 did not answer)" if "https_unavailable" in scan.info else ""
        scan.add("https_disabled", "HTTPS is not used", "high", 20,
                 f"The site is served over plain HTTP{no_tls}: {resp.url}",
                 "Serve the site over HTTPS (e.g. Let's Encrypt) and redirect HTTP to HTTPS.",
                 "transport")
        return

    # https -> http somewhere in the redirect chain
    for prev, nxt in zip(chain, chain[1:]):
        if urlparse(prev).scheme == "https" and urlparse(nxt).scheme == "http":
            scan.add("redirect_downgrade", "Redirect downgrades HTTPS to HTTP", "medium", 6,
                     f"{prev} redirects to {nxt}",
                     "Make every redirect target an https:// URL.", "transport")
            break

    # Does plain http:// redirect to https:// ?
    http_url = "http://" + urlparse(resp.url).netloc + "/"
    try:
        r = scan.session.get(http_url, timeout=scan.options.timeout, allow_redirects=True)
    except requests.RequestException:
        scan.info["http_port"] = "closed or unreachable"
        return
    if urlparse(r.url).scheme != "https":
        scan.add("no_https_redirect", "HTTP does not redirect to HTTPS", "medium", 5,
                 f"{http_url} is served without redirecting to HTTPS.",
                 "Add a permanent (301/308) redirect from http:// to https://.", "transport")


def _legacy_tls_accepted(host: str, port: int, timeout: float) -> bool | None:
    """True if the server accepts TLS 1.0/1.1, False if not, None if untestable
    (e.g. the local OpenSSL refuses to speak legacy TLS at all)."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
    except (ValueError, AttributeError, ssl.SSLError):
        return None
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except ssl.SSLError as exc:
        text = str(exc).lower()
        if "no protocols available" in text or "no ciphers available" in text:
            return None
        return False
    except OSError:
        return None


def _trust_context() -> ssl.SSLContext:
    """System trust store + certifi (python.org builds on macOS ship without
    system CAs; on Kali both are present)."""
    ctx = ssl.create_default_context()
    try:
        import certifi
        ctx.load_verify_locations(certifi.where())
    except (ImportError, OSError, ssl.SSLError):
        pass
    return ctx


def check_tls(scan) -> None:
    if not scan.is_https:
        return
    parsed = urlparse(scan.final_url)
    host, port = parsed.hostname, parsed.port or 443
    timeout = scan.options.timeout
    tls: dict = {}
    scan.info["tls"] = tls

    try:
        ctx = _trust_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
                tls["protocol"] = s.version()
                tls["cipher"] = (s.cipher() or ("?",))[0]
    except ssl.SSLCertVerificationError as exc:
        tls["error"] = exc.verify_message or str(exc)
        scan.add("tls_cert_invalid", "TLS certificate is not trusted", "high", 25,
                 f"Certificate verification failed: {tls['error']}",
                 "Install a valid certificate from a trusted CA that matches the hostname "
                 "and includes the full chain.", "tls")
        return
    except (OSError, ssl.SSLError) as exc:
        tls["error"] = str(exc)
        return

    issuer = dict(x[0] for x in cert.get("issuer", ()))
    tls["issuer"] = issuer.get("organizationName") or issuer.get("commonName", "?")
    tls["expires"] = cert.get("notAfter")
    days = days_until(cert["notAfter"]) if cert.get("notAfter") else None
    tls["days_left"] = days

    if days is not None:
        if days < 0:
            scan.add("tls_cert_expired", "TLS certificate has expired", "high", 25,
                     f"Expired {-days} day(s) ago ({tls['expires']}).",
                     "Renew the certificate and enable automatic renewal.", "tls")
        elif days < 14:
            scan.add("tls_cert_expiring", "TLS certificate expires very soon", "medium", 8,
                     f"Only {days} day(s) left ({tls['expires']}).",
                     "Renew now and check that auto-renewal works.", "tls")
        elif days < 30:
            scan.add("tls_cert_expiring", "TLS certificate expires soon", "low", 3,
                     f"{days} day(s) left ({tls['expires']}).",
                     "Make sure auto-renewal is configured.", "tls")

    if tls.get("protocol") in ("TLSv1", "TLSv1.1", "SSLv3"):
        scan.add("tls_old_negotiated", "Outdated TLS version negotiated", "medium", 8,
                 f"Server negotiated {tls['protocol']} with a modern client.",
                 "Enable TLS 1.2 and 1.3, disable everything older.", "tls")
    else:
        legacy = _legacy_tls_accepted(host, port, timeout)
        tls["legacy_tls_accepted"] = legacy
        if legacy:
            scan.add("tls_legacy_enabled", "Server still accepts TLS 1.0/1.1", "medium", 6,
                     "A client offering only TLS 1.0/1.1 could connect.",
                     "Set the minimum TLS version to 1.2.", "tls")
