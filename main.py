#!/usr/bin/env python3
"""SafeScan — CLI entry-point.

Usage examples
--------------
  python main.py https://your-own-site.com
  python main.py https://your-own-site.com --param search
  python main.py https://your-own-site.com --param q --json --html
  python main.py https://your-own-site.com --output ./my_reports --json --html
"""

from __future__ import annotations

import argparse
import sys

from safescan.scanner import run_scan
from safescan.report import (
    print_console_report,
    save_json_report,
    save_html_report,
)

BANNER = r"""
   ____        __      ____
  / __/__ ___ / /__   / __/______ ____
 _\ \/ _ `/ // / -_) _\ \/ __/ _ `/ _ \
/___/\_,_/\___/\__/ /___/\__/\_,_/_//_/
       Safe Educational Scanner v1.0
"""

DISCLAIMER = (
    "\033[93m⚠  DISCLAIMER: Only scan URLs you own or have explicit permission to test.\n"
    "   Unauthorized scanning may violate computer-fraud laws.\033[0m\n"
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="safescan",
        description="SafeScan — safe educational web vulnerability scanner.",
        epilog="Example: python main.py https://your-own-site.com --param search --json --html",
    )
    parser.add_argument("url", help="Target URL to scan (must be one you own).")
    parser.add_argument(
        "--param",
        default=None,
        help="Query parameter name for XSS / SQLi probing (e.g., 'search').",
    )
    parser.add_argument(
        "--json",
        dest="json_report",
        action="store_true",
        default=False,
        help="Save a JSON report to the output directory.",
    )
    parser.add_argument(
        "--html",
        dest="html_report",
        action="store_true",
        default=False,
        help="Save an HTML report to the output directory.",
    )
    parser.add_argument(
        "--output",
        default="reports",
        help="Output directory for reports (default: reports/).",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    print(BANNER)
    print(DISCLAIMER)

    url: str = args.url
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    print(f"  Target : {url}")
    if args.param:
        print(f"  Param  : {args.param}")
    print()

    # ── Run all checks ────────────────────────────────────────────────────
    findings = run_scan(url, param=args.param)

    # ── Console output (always) ───────────────────────────────────────────
    print_console_report(findings, url)

    # ── JSON report ───────────────────────────────────────────────────────
    # If neither --json nor --html is supplied we default to JSON.
    if args.json_report or (not args.json_report and not args.html_report):
        path = save_json_report(findings, url, output_dir=args.output)
        print(f"  [+] JSON report saved to {path}")

    # ── HTML report ───────────────────────────────────────────────────────
    if args.html_report:
        path = save_html_report(findings, url, output_dir=args.output)
        print(f"  [+] HTML report saved to {path}")

    print()


if __name__ == "__main__":
    main()
