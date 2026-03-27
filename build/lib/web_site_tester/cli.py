from __future__ import annotations

import argparse
import sys

from colorama import Fore, Style, init

from web_site_tester.reporting import save_html, save_json
from web_site_tester.scanner import WebSiteTesterScanner
from web_site_tester.utils import normalize_url


BANNER = rf"""
{Fore.CYAN}
 __        __   _       ____  _ _        _____         _            
 \ \      / /__| |__   / ___|(_) |_ ___ |_   _|__  ___| |_ ___ _ __ 
  \ \ /\ / / _ \ '_ \  \___ \| | __/ _ \  | |/ _ \/ __| __/ _ \ '__|
   \ V  V /  __/ |_) |  ___) | | ||  __/  | |  __/\__ \ ||  __/ |   
    \_/\_/ \___|_.__/  |____/|_|\__\___|  |_|\___||___/\__\___|_|   
{Style.RESET_ALL}
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="web-site-tester",
        description="Web Site Tester - Passive website security audit tool"
    )
    parser.add_argument("--url", required=True, help="Target website URL")
    parser.add_argument("--timeout", type=int, default=8, help="Request timeout in seconds")
    parser.add_argument("--threshold", type=int, default=70, help="Alert threshold. Default: 70")
    parser.add_argument("--json", dest="json_file", help="Save JSON report to file")
    parser.add_argument("--html", dest="html_file", help="Save HTML report to file")
    parser.add_argument("--verbose", action="store_true", help="Print full terminal output")
    parser.add_argument("--banner", action="store_true", help="Show banner")
    return parser


def print_verbose(result: dict) -> None:
    score = result["score"]
    level = result["level"]
    target = result["target"]
    tech = result.get("technology_hints", [])
    findings = result.get("findings", [])

    color = Fore.GREEN
    if score < 75:
        color = Fore.YELLOW
    if score < 60:
        color = Fore.RED

    print(f"{Fore.CYAN}Target:{Style.RESET_ALL} {target}")
    print(f"{Fore.CYAN}Score:{Style.RESET_ALL} {color}{score}/100{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Level:{Style.RESET_ALL} {level}")

    if tech:
        print(f"{Fore.CYAN}Technology hints:{Style.RESET_ALL}")
        for item in tech:
            print(f"  - {item}")

    if findings:
        print(f"{Fore.CYAN}Findings:{Style.RESET_ALL}")
        for item in findings:
            sev_color = Fore.YELLOW
            if item["severity"] == "medium":
                sev_color = Fore.LIGHTRED_EX
            if item["severity"] == "high":
                sev_color = Fore.RED
            print(f"  - {item['title']} [{sev_color}{item['severity']}{Style.RESET_ALL}] (-{item['penalty']})")
            print(f"    {item['detail']}")
    else:
        print(f"{Fore.GREEN}No findings detected.{Style.RESET_ALL}")

    if result.get("message"):
        print(f"\n{Fore.RED}[!] {result['message']}{Style.RESET_ALL}")


def print_silent(result: dict) -> None:
    if result.get("message"):
        print(f"[!] Risk Score: {result['score']}/100")
        print(f"[!] {result['message']}")


def main() -> None:
    init(autoreset=True)
    parser = build_parser()
    args = parser.parse_args()

    url = normalize_url(args.url)

    if args.banner:
        print(BANNER)

    scanner = WebSiteTesterScanner(url=url, timeout=args.timeout, threshold=args.threshold)
    result = scanner.run()

    if args.json_file:
        save_json(result, args.json_file)
    if args.html_file:
        save_html(result, args.html_file)

    if args.verbose:
        print_verbose(result)
    else:
        print_silent(result)

    if result["score"] < args.threshold:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()