"""Cookie flags. The monster's favourite part."""
from __future__ import annotations

from cookiemonster.utils import parse_set_cookie, set_cookie_headers

SENSITIVE_WORDS = ("sess", "auth", "token", "jwt", "login", "sid", "remember", "csrf", "xsrf")


def _is_sensitive(name: str) -> bool:
    n = name.lower()
    return any(w in n for w in SENSITIVE_WORDS)


def check_cookies(scan) -> None:
    responses = list(scan.response.history) + [scan.response]
    seen: dict[str, dict[str, str]] = {}
    for resp in responses:
        for header in set_cookie_headers(resp):
            name, attrs = parse_set_cookie(header)
            if name:
                seen[name] = attrs  # later responses override earlier ones

    scan.info["cookies"] = sorted(seen)
    cat = "cookies"
    for name, attrs in seen.items():
        sensitive = _is_sensitive(name)
        kind = "session/auth cookie" if sensitive else "cookie"

        if "secure" not in attrs and scan.is_https:
            scan.add(f"cookie_secure_{name}", f"Cookie without Secure flag: {name}",
                     "medium" if sensitive else "low", 10 if sensitive else 4,
                     f"This {kind} can travel over plain HTTP, where anyone on the network can nom it.",
                     "Add the Secure attribute.", cat)

        if "httponly" not in attrs and sensitive:
            # Non-sensitive cookies are often read by JS on purpose (theme, consent...)
            scan.add(f"cookie_httponly_{name}", f"Cookie without HttpOnly flag: {name}",
                     "medium", 8,
                     "Any JavaScript on the page (including injected scripts) can eat this cookie.",
                     "Add the HttpOnly attribute.", cat)

        samesite = attrs.get("samesite")
        if samesite is None:
            scan.add(f"cookie_samesite_{name}", f"Cookie without SameSite attribute: {name}",
                     "low", 4 if sensitive else 1,
                     "Browsers default to Lax, but explicit is better (and older browsers send it everywhere).",
                     "Add SameSite=Lax (or Strict).", cat)
        elif samesite.lower() == "none" and "secure" not in attrs:
            scan.add(f"cookie_samesite_none_{name}", f"SameSite=None without Secure: {name}",
                     "medium", 5,
                     "Modern browsers reject this cookie; older ones send it cross-site over HTTP.",
                     "SameSite=None must be combined with Secure.", cat)
