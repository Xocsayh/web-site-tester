"""Page content: login forms, mixed content and technology fingerprints."""
from __future__ import annotations

import re
from urllib.parse import urlparse

CSRF_NAMES = ("csrf", "xsrf", "token", "authenticity", "nonce", "__requestverificationtoken")


def check_forms(scan) -> None:
    if not scan.soup:
        return
    cat = "forms"
    forms = scan.soup.find_all("form")
    scan.info["forms"] = len(forms)
    for form in forms:
        inputs = form.find_all("input")
        if not any((i.get("type") or "").lower() == "password" for i in inputs):
            continue
        action = (form.get("action") or "").strip()
        target = scan.absolute(action) if action else scan.final_url
        method = (form.get("method") or "get").strip().lower()

        if urlparse(target).scheme == "http":
            scan.add("login_insecure_submit", "Login form submits over HTTP", "high", 20,
                     f"Password form posts to {target}",
                     "Submit login forms to an https:// endpoint only.", cat)
        if method == "get":
            scan.add("login_get_method", "Login form uses GET", "medium", 6,
                     "Passwords end up in the URL, browser history and server logs.",
                     'Use method="post" for login forms.', cat)

        hidden = [(i.get("name") or "").lower() for i in inputs
                  if (i.get("type") or "").lower() == "hidden"]
        if not any(any(t in n for t in CSRF_NAMES) for n in hidden):
            scan.add("missing_csrf_hint", "No CSRF token seen in login form", "low", 2,
                     "No hidden input that looks like a CSRF token. (SameSite cookies or "
                     "headers may still protect it - verify manually.)",
                     "Add a per-session CSRF token to state-changing forms.", cat)


# tag, attribute, active?  (active mixed content can run code -> worse)
_MIXED = [
    ("script", "src", True), ("iframe", "src", True), ("link", "href", True),
    ("object", "data", True), ("embed", "src", True),
    ("img", "src", False), ("audio", "src", False), ("video", "src", False),
    ("source", "src", False),
]


def check_mixed_content(scan) -> None:
    if not scan.soup or not scan.is_https:
        return
    active, passive = [], []
    for tag, attr, is_active in _MIXED:
        for el in scan.soup.find_all(tag):
            if tag == "link" and "stylesheet" not in [r.lower() for r in (el.get("rel") or [])]:
                continue
            val = (el.get(attr) or "").strip()
            if val.lower().startswith("http://"):
                (active if is_active else passive).append(val)
    for form in scan.soup.find_all("form"):
        action = (form.get("action") or "").strip()
        if action.lower().startswith("http://"):
            active.append(action)

    cat = "content"
    if active:
        scan.add("mixed_content_active", "Active mixed content (scripts/styles over HTTP)", "medium", 8,
                 f"{len(active)} resource(s), e.g. {active[0]}",
                 "Load every script, stylesheet and iframe over https://.", cat)
    if passive:
        scan.add("mixed_content_passive", "Passive mixed content (images/media over HTTP)", "low", 2,
                 f"{len(passive)} resource(s), e.g. {passive[0]}",
                 "Load images and media over https://.", cat)


def detect_technology(scan) -> None:
    tech = scan.technology
    h = {k.lower(): v for k, v in scan.response.headers.items()}

    server = h.get("server", "").lower()
    for needle, label in (("cloudflare", "Cloudflare"), ("nginx", "nginx"), ("apache", "Apache"),
                          ("microsoft-iis", "IIS"), ("litespeed", "LiteSpeed"), ("vercel", "Vercel"),
                          ("netlify", "Netlify"), ("gws", "Google"), ("openresty", "OpenResty"),
                          ("caddy", "Caddy"), ("uvicorn", "Uvicorn"), ("gunicorn", "Gunicorn")):
        if needle in server:
            tech.add(label)
    if "cf-ray" in h:
        tech.add("Cloudflare")
    if "x-vercel-id" in h:
        tech.add("Vercel")
    if "x-nf-request-id" in h:
        tech.add("Netlify")
    if "x-amz-cf-id" in h:
        tech.add("Amazon CloudFront")
    if "x-akamai-transformed" in h or "akamai" in server:
        tech.add("Akamai")
    if "x-served-by" in h and "cache-" in h.get("x-served-by", ""):
        tech.add("Fastly")
    powered = h.get("x-powered-by", "")
    if powered:
        for needle, label in (("php", "PHP"), ("express", "Express"), ("asp.net", "ASP.NET"),
                              ("next.js", "Next.js"), ("nuxt", "Nuxt")):
            if needle in powered.lower():
                tech.add(label)

    if not scan.soup:
        return
    soup = scan.soup
    gen = soup.find("meta", attrs={"name": lambda v: v and v.lower() == "generator"})
    if gen and gen.get("content"):
        content = gen["content"].strip()
        tech.add(f"Generator: {content}")
        if "wordpress" in content.lower():
            tech.add("WordPress")

    html = scan.response.text
    srcs = " ".join((s.get("src") or "") for s in soup.find_all("script")).lower()
    hrefs = " ".join((l.get("href") or "") for l in soup.find_all("link")).lower()
    assets = srcs + " " + hrefs

    # Specific markers only - no bare words like "next" or "react" in page text.
    markers = [
        (r"/wp-content/|/wp-includes/", "WordPress"),
        (r"woocommerce", "WooCommerce"),
        (r"__NEXT_DATA__|/_next/static/", "Next.js"),
        (r"__NUXT__|/_nuxt/", "Nuxt"),
        (r"data-reactroot|react(\.production|-dom)", "React"),
        (r"ng-version=", "Angular"),
        (r"data-v-[0-9a-f]{8}|vue(\.runtime)?(\.global)?(\.prod)?(\.min)?\.js", "Vue"),
        (r"cdn\.shopify\.com|Shopify\.theme", "Shopify"),
        (r"static\.wixstatic\.com", "Wix"),
        (r"squarespace\.com", "Squarespace"),
        (r"/sites/default/files/|Drupal\.settings", "Drupal"),
        (r"/media/jui/|joomla", "Joomla"),
        (r"__sveltekit|svelte-[a-z0-9]{6}", "Svelte"),
        (r"gatsby-", "Gatsby"),
    ]
    for pattern, label in markers:
        if re.search(pattern, html, re.I):
            tech.add(label)
    for needle, label in (("jquery", "jQuery"), ("bootstrap", "Bootstrap"), ("tailwind", "Tailwind CSS"),
                          ("googletagmanager", "Google Tag Manager"), ("google-analytics", "Google Analytics"),
                          ("cloudflareinsights", "Cloudflare"), ("recaptcha", "reCAPTCHA"),
                          ("js.stripe.com", "Stripe"), ("alpinejs", "Alpine.js"), ("htmx", "htmx")):
        if needle in assets:
            tech.add(label)
