from __future__ import annotations

import ssl
import time
from urllib.parse import urlparse

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

LEVEL_MOODS = {
    "good": "Locked tight. Nothing to write home about.",
    "fair": "A few doors left unlocked.",
    "needs_improvement": "A red team would have a good day here.",
    "critical": "Game over - the red team is already inside.",
}


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url:
        raise ValueError("URL is empty")
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    parsed = urlparse(url)
    if not parsed.netloc:
        raise ValueError(f"Invalid URL: {url}")
    if not parsed.path:
        url += "/"
    return url


def base_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def clamp_score(score: int) -> int:
    return max(0, min(100, score))


def detect_level(score: int) -> str:
    if score >= 85:
        return "good"
    if score >= 70:
        return "fair"
    if score >= 50:
        return "needs_improvement"
    return "critical"


def parse_set_cookie(header: str) -> tuple[str, dict[str, str]]:
    """Parse one Set-Cookie header -> (name, {lowercased attribute: value}).

    Flag attributes (Secure, HttpOnly) get an empty string value.
    """
    parts = [p.strip() for p in header.split(";")]
    first = parts[0] if parts else ""
    name = first.split("=", 1)[0].strip()
    attrs: dict[str, str] = {}
    for part in parts[1:]:
        if not part:
            continue
        if "=" in part:
            key, value = part.split("=", 1)
            attrs[key.strip().lower()] = value.strip()
        else:
            attrs[part.lower()] = ""
    return name, attrs


def set_cookie_headers(response) -> list[str]:
    """All raw Set-Cookie headers of a requests.Response (not merged)."""
    raw = getattr(response, "raw", None)
    headers = getattr(raw, "headers", None)
    if headers is not None and hasattr(headers, "getlist"):
        try:
            return list(headers.getlist("Set-Cookie"))
        except Exception:  # pragma: no cover - defensive
            pass
    value = response.headers.get("Set-Cookie")
    return [value] if value else []


def days_until(not_after: str, now: float | None = None) -> int:
    """Days until a certificate 'notAfter' string (e.g. 'Jun  1 12:00:00 2027 GMT')."""
    expires = ssl.cert_time_to_seconds(not_after)
    now = time.time() if now is None else now
    return int((expires - now) // 86400)


def short(text: str, limit: int = 160) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."
