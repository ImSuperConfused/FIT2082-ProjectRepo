#!/usr/bin/env python3
"""
Usage on Kali Linux:
  python3 unified_vuln_parser.py niktoreport.json zapreport.json
  python3 unified_vuln_parser.py niktoreport.json zapreport.json -o combined.json
  python3 unified_vuln_parser.py report1.json report2.json report3.json -o out.json
"""
import argparse
import html
import json
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin


DEFAULT_OUTPUT = "default-parsed-report.json"

CWE_CVE = re.compile(r"C(W|V)E-[0-9]+(-[0-9]+)*$")  # reserved for optional Type field
SENTENCE_END = re.compile(r"(?<=[.!?])\s+")
HTML_BREAKS = re.compile(r"</p\s*>|<br\s*/?>", re.IGNORECASE)
HTML_TAGS = re.compile(r"<[^>]+>")


def output(findings: list, output_filename: str = DEFAULT_OUTPUT) -> Path:
    """
    Output: Write findings to JSON.
    """
    output_path: Path = Path(output_filename).expanduser().resolve()

    with open(output_path, "w", encoding="utf-8") as output_file:
        json.dump(findings, output_file, indent=3)

    return output_path


def finding(scanner: str, site_url: str, title: str, method: str, description: str, references: str, **extra) -> dict:
    """
    Output: One finding in the unified format. Empty values become None so every scanner is treated the same. 
    Optional extra fields (Type, Risk, Confidence, ...) are appended after the six standard fields.
    """
    return {
        "Scanner": scanner or None,
        "Site URL": site_url or None,
        "Title": title or None,
        "Method": method or None,
        "Description": description or None,
        "References": references or None,
        **extra,
    }


def parse_nikto(reports: list) -> list:
    """
    Input: List of loaded Nikto host objects.
    Output: Clean list of findings in the unified format.
    """
    results: list = []
    for report in reports:
        # Site URL = host:port (falls back to ip) + the finding url
        host = report.get("host") or report.get("ip") or ""
        port = report.get("port")
        base = f"{host}:{port}" if host and port else host

        for vuln in report.get("vulnerabilities") or []:
            msg: str = vuln.get("msg") or ""
            results.append(
                finding(
                    scanner="Nikto",
                    site_url=f"{base}{vuln.get('url') or ''}",
                    title=SENTENCE_END.split(msg.strip(), maxsplit=1)[0] if msg.strip() else None,
                    method=vuln.get("method"),
                    description=msg or None,
                    references=vuln.get("references"),
                )
            )
    return results


def parse_zap(reports: list) -> list:
    """
    Input: List of loaded OWASP ZAP reports.
    Output: Clean list of findings (one per alert instance) in the unified format.
    """
    results: list = []
    for report in reports:
        scanner: str = report.get("@programName") or "ZAP"

        sites = report.get("site") or []

        # ZAP may store a single site as a dict or multiple as a list
        if isinstance(sites, dict):
            sites = [sites]

        for site in sites:
            site_name = site.get("@name") or ""

            for alert in site.get("alerts") or []:
                # ZAP stores these as HTML; convert to plain text once per alert
                desc, ref = (
                    html.unescape(
                        HTML_TAGS.sub("", HTML_BREAKS.sub("\n", alert.get(key) or ""))
                    ).strip()
                    for key in ("desc", "reference")
                )

                instances = alert.get("instances") or [{}]
                for inst in instances:
                    uri: str = inst.get("uri") or ""
                    if uri.startswith(("http://", "https://")):
                        site_url = uri
                    else:
                        site_url = urljoin(site_name, uri) if site_name else uri

                    results.append(
                        finding(
                            scanner=scanner,
                            site_url=site_url or None,
                            title=alert.get("alert") or alert.get("name"),
                            method=inst.get("method"),
                            description=desc or None,
                            references=ref or None,
                            # Optional extras (uncomment independently if needed):
                            # Risk=alert.get("riskdesc"),
                            # Confidence=alert.get("confidence"),
                        )
                    )
    return results


# (name, detect, parse)
# ZAP reports have "@programName": "ZAP"; Nikto reports have a "vulnerabilities" list
PARSERS = [
    ("Nikto", lambda reports: any("vulnerabilities" in r for r in reports), parse_nikto),
    ("OWASP ZAP", lambda reports: any(r.get("@programName") == "ZAP" for r in reports), parse_zap),
]


def load_reports(path: str) -> list:
    """Load a JSON file and return a list of dict objects only."""
    with open(path, "rb") as fstr:
        data = json.loads(fstr.read().decode("utf-8"))

    reports: list = []

    for item in data if isinstance(data, list) else [data]:
        if isinstance(item, dict):
            reports.append(item)

    return reports


def parser(path: str) -> list:
    """
    Input: Path of a supported JSON report.
    Output: Clean list of findings in the unified format.
    """
    reports = load_reports(path)

    if not reports:
        raise ValueError(f"No JSON objects found in {path}")

    for name, detect, parse in PARSERS:
        if detect(reports):
            print(f"[+] Detected report type: {name} ({path})", file=sys.stderr)
            try:
                return parse(reports)
            except (AttributeError, TypeError, KeyError) as err:
                raise ValueError(f"{name} report is not in the expected format: {err}") from err

    supported = ", ".join(name for name, _, _ in PARSERS)
    raise ValueError(f"Unrecognised report format in {path}. Supported types: {supported}.")


def unrecognised(message: str) -> None:
    """
    Replace argparse's default error with a short message and exit 1.
    """
    print(f"\n[-] Unrecognised command, type {args_parser.prog} -h for help.", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    args_parser = argparse.ArgumentParser(
        description="Parse Web Vulnerability Scanner Reports into one unified JSON report."
    )
    # Accept one or more report files
    args_parser.add_argument(
        "reports",
        nargs="+",
        metavar="REPORT",
        help="Path(s) of Nikto and/or OWASP ZAP JSON report(s) to parse.",
    )
    args_parser.add_argument(
        "-o",
        metavar="FILENAME",
        default=DEFAULT_OUTPUT,
        help=f"Output filename or full path (e.g. ~/reports/out.json). Default: {DEFAULT_OUTPUT}",
    )

    args_parser.error = unrecognised
    args = args_parser.parse_args()

    start_timer = time.perf_counter()
    print(f"\n[+] Started at {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}", file=sys.stderr)

    all_findings: list = []
    errors: list = []

    for report_path in args.reports:
        try:
            findings = parser(report_path)
            all_findings.extend(findings)
            print(f"[+] Parsed {len(findings)} finding(s) from {report_path}",file=sys.stderr)
            
        except (OSError, ValueError, json.JSONDecodeError) as err:
            # OSError = file problems; ValueError / JSONDecodeError = bad content / format
            msg = f"Could not parse {report_path}: {err}"
            print(f"[-] {msg}", file=sys.stderr)
            errors.append(msg)

    if not all_findings and errors:
        print("\n[-] No findings produced. Exiting.", file=sys.stderr)
        sys.exit(1)

    try:
        saved_path = output(all_findings, args.o)
    except OSError as err:
        print(f"\n[-] Could not write report: {err}", file=sys.stderr)
        sys.exit(1)

    print(f"\n[+] Total: {len(all_findings)} finding(s). Report written to: {saved_path}",file=sys.stderr)
    if errors:
        print(f"[!] {len(errors)} file(s) had errors (see messages above).",file=sys.stderr)

    print(f"\n[+] Finished at {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}. Elapsed: {time.perf_counter() - start_timer:.2f} seconds",file=sys.stderr)