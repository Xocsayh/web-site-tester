from __future__ import annotations

import argparse
import sys

from colorama import Fore, Style, init

from cookiemonster import __version__
from cookiemonster.reporting import save_html, save_json
from cookiemonster.scanner import USER_AGENT, Scan, ScanOptions
from cookiemonster.utils import normalize_url

EXIT_OK, EXIT_BELOW_THRESHOLD, EXIT_UNREACHABLE, EXIT_USAGE = 0, 1, 2, 3

BANNER = rf"""{Fore.BLUE}
   ____            _    _      __  __                 _
  / ___|___   ___ | | _(_) ___|  \/  | ___  _ __  ___| |_ ___ _ __
 | |   / _ \ / _ \| |/ / |/ _ \ |\/| |/ _ \| '_ \/ __| __/ _ \ '__|
 | |__| (_) | (_) |   <| |  __/ |  | | (_) | | | \__ \ ||  __/ |
  \____\___/ \___/|_|\_\_|\___|_|  |_|\___/|_| |_|___/\__\___|_|
{Fore.YELLOW}        .-""-.
       / o  o \    Om nom nom... sniffing your cookies (passively).
       \ .__. /    v{__version__} - only scan sites you are allowed to test.
        '-..-'{Style.RESET_ALL}
"""

SEV_COLOR = {"high": Fore.RED, "medium": Fore.LIGHTRED_EX, "low": Fore.YELLOW, "info": Fore.CYAN}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cookiemonster",
        description="CookieMonster - passive website security auditor. Om nom nom.",
        epilog="Exit codes: 0 ok, 1 score below threshold, 2 site unreachable, 3 bad usage.",
    )
    p.add_argument("target", nargs="?", help="Target URL or hostname (e.g. example.com)")
    p.add_argument("-u", "--url", help="Target URL (same as the positional argument)")
    p.add_argument("-t", "--timeout", type=float, default=8, help="Request timeout in seconds (default: 8)")
    p.add_argument("--threshold", type=int, default=50, help="Exit with 1 if score is below this (default: 50)")
    p.add_argument("--json", dest="json_file", metavar="FILE", help="Save JSON report ('-' prints to stdout)")
    p.add_argument("--html", dest="html_file", metavar="FILE", help="Save HTML report")
    p.add_argument("-v", "--verbose", action="store_true", help="Show every finding with fixes")
    p.add_argument("-q", "--quiet", action="store_true", help="Print nothing unless there is a risk")
    p.add_argument("--banner", action="store_true", help="Show the banner")
    p.add_argument("--no-color", action="store_true", help="Disable colors")
    p.add_argument("--no-probe", action="store_true",
                   help="Skip sensitive-file probes (.git, .env, backups...)")
    p.add_argument("--no-links", action="store_true", help="Skip broken-link check")
    p.add_argument("--max-links", type=int, default=30, help="Max internal links to check (default: 30)")
    p.add_argument("-k", "--insecure", action="store_true",
                   help="Do not verify TLS certificates (still reported as a finding)")
    p.add_argument("--user-agent", default=USER_AGENT, help="Custom User-Agent")
    p.add_argument("--version", action="version", version=f"CookieMonster {__version__}")
    return p


def c(color: str, text: str) -> str:
    return f"{color}{text}{Style.RESET_ALL}"


def score_color(score: int) -> str:
    return Fore.GREEN if score >= 85 else Fore.YELLOW if score >= 70 else Fore.LIGHTRED_EX if score >= 50 else Fore.RED


def print_summary(result: dict) -> None:
    if result["status"] != "ok":
        print(c(Fore.RED, f"[x] {result['final_url']} - unreachable"))
        print(f"    {result['message']}")
        return
    s = result["summary"]
    score = result["score"]
    print(f"{c(Fore.CYAN, 'Target:')} {result['final_url']}")
    print(f"{c(Fore.CYAN, 'Score:')}  {c(score_color(score), f'{score}/100')}  ({result['level']}) - {result['mood']}")
    print(f"{c(Fore.CYAN, 'Found:')}  " + "  ".join(
        c(SEV_COLOR[k], f"{k} {s.get(k, 0)}") for k in ("high", "medium", "low", "info")))


def print_verbose(result: dict) -> None:
    print_summary(result)
    if result["status"] != "ok":
        return
    if result.get("note"):
        print(c(Fore.YELLOW, f"Note: {result['note']}"))
    if result["technology_hints"]:
        print(f"{c(Fore.CYAN, 'Tech:')}   {', '.join(result['technology_hints'])}")

    info = result.get("info", {})
    tls = info.get("tls") or {}
    if tls.get("protocol"):
        print(f"{c(Fore.CYAN, 'TLS:')}    {tls['protocol']}, {tls.get('issuer', '?')}, "
              f"expires in {tls.get('days_left', '?')} days")
    perf = info.get("performance") or {}
    if perf:
        print(f"{c(Fore.CYAN, 'Speed:')}  {perf['response_ms']} ms, {perf['html_kb']} KB HTML, "
              f"compression: {perf['compression'] or 'none'}, redirects: {perf['redirects']}")

    findings = result["findings"]
    if not findings:
        print(c(Fore.GREEN, "\nNo findings. The monster went home hungry."))
    else:
        print()
        for f in findings:
            tag = c(SEV_COLOR.get(f["severity"], ""), f"[{f['severity'].upper():^6}]")
            pen = f" (-{f['penalty']})" if f["penalty"] else ""
            print(f"{tag} {f['title']}{pen}")
            print(f"         {f['detail']}")
            if f.get("fix"):
                print(c(Fore.GREEN, f"         fix: {f['fix']}"))
    for err in info.get("check_errors", []):
        print(c(Fore.YELLOW, f"[!] check failed: {err}"))
    if result.get("message"):
        print(c(Fore.RED, f"\n[!] {result['message']}"))


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    init(autoreset=True, strip=True if args.no_color or not sys.stdout.isatty() else None)

    raw = args.url or args.target
    if not raw:
        parser.print_usage(sys.stderr)
        print("cookiemonster: error: a target URL is required (e.g. cookiemonster example.com)", file=sys.stderr)
        sys.exit(EXIT_USAGE)
    try:
        url = normalize_url(raw)
    except ValueError as exc:
        print(f"cookiemonster: error: {exc}", file=sys.stderr)
        sys.exit(EXIT_USAGE)

    json_to_stdout = args.json_file == "-"
    if args.banner and not json_to_stdout:
        print(BANNER)

    options = ScanOptions(
        timeout=args.timeout, threshold=args.threshold, probe_files=not args.no_probe,
        check_links=not args.no_links, max_links=max(0, args.max_links),
        verify_tls=not args.insecure, user_agent=args.user_agent,
        http_fallback=not raw.strip().lower().startswith(("http://", "https://")),
    )
    if args.insecure:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    result = Scan(url, options).run()

    if args.json_file:
        save_json(result, args.json_file)
    if args.html_file:
        save_html(result, args.html_file)

    if not json_to_stdout:
        risky = result["status"] != "ok" or result.get("message")
        if args.verbose:
            print_verbose(result)
        elif not args.quiet or risky:
            print_summary(result)
            if not args.quiet and result["status"] == "ok" and result["findings"]:
                print(c(Fore.CYAN, "Run with -v to see every finding and how to fix it."))

    if result["status"] != "ok":
        sys.exit(EXIT_UNREACHABLE)
    sys.exit(EXIT_BELOW_THRESHOLD if result["score"] < args.threshold else EXIT_OK)


if __name__ == "__main__":
    main()
