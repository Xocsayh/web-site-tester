"""CORS misconfiguration: does the site trust any Origin?"""
from __future__ import annotations

EVIL_ORIGIN = "https://evil-origin.betterpent.invalid"


def check_cors(scan) -> None:
    probe = scan.probe(scan.final_url, max_bytes=1, headers={"Origin": EVIL_ORIGIN})
    if probe is None:
        return
    acao = probe.headers.get("access-control-allow-origin", "").strip()
    acac = probe.headers.get("access-control-allow-credentials", "").strip().lower() == "true"
    scan.info["cors"] = {"allow_origin": acao or None, "allow_credentials": acac}
    cat = "cors"

    if acao == EVIL_ORIGIN or acao == "null":
        if acac:
            scan.add("cors_reflect_credentials", "CORS trusts any origin WITH credentials", "high", 20,
                     f"Origin {EVIL_ORIGIN} was reflected and Access-Control-Allow-Credentials is true. "
                     "Any website can read logged-in users' data.",
                     "Only allow an explicit list of trusted origins.", cat)
        else:
            scan.add("cors_reflect", "CORS reflects any origin", "medium", 6,
                     f"Origin {EVIL_ORIGIN} was echoed back in Access-Control-Allow-Origin.",
                     "Only allow an explicit list of trusted origins.", cat)
    elif acao == "*":
        scan.add("cors_wildcard", "CORS allows all origins (*)", "info", 0,
                 "Fine for public data; browsers refuse credentials with '*'.",
                 "Make sure no private data is served from this endpoint.", cat)
