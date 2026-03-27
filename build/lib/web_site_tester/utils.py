from __future__ import annotations

from urllib.parse import urlparse


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        return f"https://{url}"
    return url


def clamp_score(score: int) -> int:
    return max(0, min(100, score))


def detect_level(score: int) -> str:
    if score >= 90:
        return "excellent"
    if score >= 75:
        return "good"
    if score >= 60:
        return "warning"
    return "critical"


def target_host(url: str) -> str:
    parsed = urlparse(url)
    return parsed.netloc or parsed.path