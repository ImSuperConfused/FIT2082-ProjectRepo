#!/usr/bin/env python3
"""
Parse Nikto **and/or OWASP ZAP JSON** reports into one unified JSON report.

Usage:
  python3 MultiScannerParser.py niktoreport.json zapreport.json
  python3 MultiScannerParser.py niktoreport.json zapreport.json -o combined.json
  python3 MultiScannerParser.py report1.json report2.json report3.json -o out.json
"""

# Score using any CVE/CWE references to CVSS.
# https://api.first.org/data/v1/epss?cve=A,B for EPSS
# https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=... for CVSS

# Cleaned up formatting with Claude.
import argparse
import html
import json
import re
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin

DEFAULT_OUTPUT = "default-parsed-report.json"

# Compiled regexes
CWE_CVE = re.compile(r"C(W|V)E-[0-9]+(-[0-9]+)*$") 
CVE_EXTRACT = re.compile(r"CVE-\d{4}-\d{4,}")
SENTENCE_END = re.compile(r"(?<=[.!?])\s+")
HTML_BREAKS = re.compile(r"</p\s*>|<br\s*/?>", re.IGNORECASE)
HTML_TAGS = re.compile(r"<[^>]+>")

def output(findings: list, output_filename: str = DEFAULT_OUTPUT) -> Path:
    output_path: Path = Path(output_filename).expanduser().resolve()
    with open(output_path, "w", encoding="utf-8") as output_file:
        json.dump(findings, output_file, indent=3)
    return output_path

def finding(scanner: str, title: str, site_url: str, method: str, description: str, references: str, **extra) -> dict:
    result = {
        "Scanner": scanner or None,
        "Title": title or None,
        "Site URL": site_url or None,
        "Method": method or None,
        "Description": description or None,
        "References": references or None
    }
    # Append any optional extra fields
    result.update(extra)
    return result

def fetch_cve_scores(cves: set) -> dict:
    """
    Looks up EPSS and CVSS scores for a set of unique CVEs.
    Returns a dictionary mapped by CVE ID.
    """
    scores = {cve: {"cvss": None, "cvss_version": None, "epss": None, "epss_percentile": None, "epss_date": None} for cve in cves}
    if not cves:
        return scores

    print(f"[*] Fetching scores for {len(cves)} unique CVE(s)...", file=sys.stderr)

    # 1. EPSS Lookup (Batch)
    # The API allows comma-separated CVEs up to 2000 chars.
    epss_url = f"https://api.first.org/data/v1/epss?cve={','.join(cves)}"
    try:
        req = urllib.request.Request(epss_url, headers={'User-Agent': 'MultiScannerParser'})
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
            for item in data.get("data", []):
                cve_id = item.get("cve")
                if cve_id in scores:
                    scores[cve_id]["epss"] = float(item.get("epss", 0))
                    scores[cve_id]["epss_percentile"] = float(item.get("percentile", 0))
                    scores[cve_id]["epss_date"] = item.get("date")
    except Exception as err:
        print(f"[!] EPSS API error: {err}", file=sys.stderr)

    # 2. NVD CVSS Lookup (One by one)
    # Without an API key, the limit is 5 requests per rolling 30 seconds. 
    # We sleep for 6 seconds between requests to be safe.
    for i, cve in enumerate(cves):
        if i > 0:
            time.sleep(6.1) 
            
        nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
        try:
            req = urllib.request.Request(nvd_url, headers={'User-Agent': 'MultiScannerParser'})
            with urllib.request.urlopen(req, timeout=15) as response:
                data = json.loads(response.read().decode())
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    metrics = vulns[0].get("cve", {}).get("metrics", {})
                    # Fallback through versions
                    if "cvssMetricV31" in metrics:
                        scores[cve]["cvss"] = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                        scores[cve]["cvss_version"] = "3.1"
                    elif "cvssMetricV30" in metrics:
                        scores[cve]["cvss"] = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
                        scores[cve]["cvss_version"] = "3.0"
                    elif "cvssMetricV2" in metrics:
                        scores[cve]["cvss"] = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
                        scores[cve]["cvss_version"] = "2.0"
        except Exception as err:
            print(f"[!] NVD API error for {cve}: {err}", file=sys.stderr)

    return scores

def parse_nikto(reports: list, fetch_scores: bool = False) -> list:
    groups: dict = {}
    raw_count: int = 0
    unique_cves = set()

    for report in reports:
        host = report.get("host") or report.get("ip") or ""
        port = report.get("port")
        base = f"{host}:{port}" if host and port else host

        for vuln in report.get("vulnerabilities") or []:
            raw_count += 1
            msg = vuln.get("msg") or ""
            title = SENTENCE_END.split(msg.strip(), maxsplit=1)[0]
            url = f"{base}{vuln.get('url') or ''}"
            key = title or f"untitled-{len(groups)}"

            if key not in groups:
                groups[key] = {"title": title, "msg": msg, "vuln": vuln, "urls": [], "cves": []}

            if url not in groups[key]["urls"]:
                groups[key]["urls"].append(url)
                
            # Extract CVEs from references
            refs = vuln.get("references") or ""
            found_cves = CVE_EXTRACT.findall(refs)
            for cve in found_cves:
                if cve not in groups[key]["cves"]:
                    groups[key]["cves"].append(cve)
                    unique_cves.add(cve)

    print(f"[+] Nikto: {raw_count} raw, {len(groups)} unique, {raw_count - len(groups)} duplicate(s) merged", file=sys.stderr)
    
    # Fetch scores if flag is enabled
    cve_data = fetch_cve_scores(unique_cves) if fetch_scores and unique_cves else {}
    results: list = []

    for group in groups.values():
        vuln = group["vuln"]
        cves = group["cves"]
        
        extra_fields = {}
        if cves:
            extra_fields["CVE"] = ", ".join(cves)
            
            if fetch_scores:
                max_cvss = None
                max_cvss_ver = None
                max_epss = None
                max_epss_perc = None
                
                for cve in cves:
                    data = cve_data.get(cve, {})
                    cvss = data.get("cvss")
                    epss = data.get("epss")
                    
                    if cvss is not None and (max_cvss is None or cvss > max_cvss):
                        max_cvss = cvss
                        max_cvss_ver = data.get("cvss_version")
                        
                    if epss is not None and (max_epss is None or epss > max_epss):
                        max_epss = epss
                        max_epss_perc = data.get("epss_percentile")
                
                extra_fields["CVSS"] = max_cvss
                extra_fields["CVSS Version"] = max_cvss_ver
                extra_fields["EPSS"] = max_epss
                extra_fields["EPSS Percentile"] = max_epss_perc

        results.append(
            finding(
                scanner="Nikto",
                title=group["title"],
                site_url=", ".join(group["urls"]),
                method=vuln.get("method"),
                description=group["msg"],
                references=vuln.get("references"),
                **extra_fields
            )
        )

    return results

def parse_zap(reports: list, fetch_scores: bool = False) -> list:
    results: list = []
    for report in reports:
        scanner: str = report.get("@programName")
        sites = report.get("site")

        if isinstance(sites, dict):
            sites = [sites]

        for site in sites:
            site_name = site.get("@name") or ""

            for alert in site.get("alerts") or []:
                desc, ref = (
                    html.unescape(HTML_TAGS.sub("", HTML_BREAKS.sub("\n", alert.get(key) or ""))).strip()
                    for key in ("desc", "reference")
                )

                for inst in alert.get("instances") or []:
                    uri: str = inst.get("uri") or ""
                    if uri.startswith(("http://", "https://")):
                        site_url = uri
                    else:
                        site_url = urljoin(site_name, uri) if site_name else uri

                    results.append(
                        finding(
                            scanner=scanner,
                            title=alert.get("alert") or alert.get("name"),
                            site_url=site_url,
                            method=inst.get("method"),
                            description=desc,
                            references=ref
                        )
                    )

    return results

PARSERS = [
    ("Nikto", lambda reports: any("vulnerabilities" in r for r in reports), parse_nikto),
    ("OWASP ZAP", lambda reports: any(r.get("@programName") == "ZAP" for r in reports), parse_zap)
]

def load_reports(path: str) -> list:
    with open(path, "rb") as fstr:
        data = json.loads(fstr.read().decode("utf-8"))
    reports: list = []
    for item in data if isinstance(data, list) else [data]:
        if isinstance(item, dict):
            reports.append(item)
    return reports

def parser(path: str, fetch_scores: bool = False) -> list:
    reports = load_reports(path)
    if not reports:
        raise ValueError(f"No JSON objects found in {path}")

    for name, detect, parse in PARSERS:
        if detect(reports):
            print(f"[+] Detected report type: {name} ({path})", file=sys.stderr)
            try:
                return parse(reports, fetch_scores)
            except (AttributeError, TypeError, KeyError) as err:
                raise ValueError(f"{name} report is not in the expected format: {err}") from err

    supported = ", ".join(name for name, _, _ in PARSERS)
    raise ValueError(f"Unrecognised report format in {path}. Supported types: {supported}.")

def unrecognised(message: str) -> None:
    print(f"\n[-] Unrecognised command, type {args_parser.prog} -h for help.", file=sys.stderr)
    sys.exit(1)

if __name__ == "__main__":
    args_parser = argparse.ArgumentParser(
        description="Parse web vulnerability scanner reports into one unified JSON report."
    )
    args_parser.add_argument(
        "reports",
        nargs="+",
        metavar="REPORT",
        help="path(s) of the Nikto and/or OWASP ZAP JSON report(s) to parse",
    )
    args_parser.add_argument(
        "-o",
        metavar="FILENAME",
        default=DEFAULT_OUTPUT,
        help=f"output filename or full path such as ~/reports/out.json (default: {DEFAULT_OUTPUT})",
    )
    args_parser.add_argument(
        "--scores",
        action="store_true",
        help="Look up EPSS and CVSS scores for parsed CVEs (slower)",
    )

    args_parser.error = unrecognised
    args = args_parser.parse_args()

    start_timer = time.perf_counter()
    print(f"\n[+] Started at {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}", file=sys.stderr)

    all_findings: list = []
    errors: list = []

    for report_path in args.reports:
        try:
            findings = parser(report_path, fetch_scores=args.scores)
            all_findings.extend(findings)
            print(f"[+] Parsed {len(findings)} finding(s) from {report_path}", file=sys.stderr)
        except (OSError, ValueError) as err:
            message = f"Could not parse {report_path}: {err}"
            print(f"[-] {message}", file=sys.stderr)
            errors.append(message)

    if not all_findings and errors:
        print("\n[-] No findings produced. Exiting.", file=sys.stderr)
        sys.exit(1)

    try:
        saved_path = output(all_findings, args.o)
    except OSError as err:
        print(f"\n[-] Could not write report: {err}", file=sys.stderr)
        sys.exit(1)

    print(f"\n[+] Total: {len(all_findings)} finding(s). Report written to: {saved_path}", file=sys.stderr)

    if errors:
        print(f"[!] {len(errors)} file(s) had errors (see messages above).", file=sys.stderr)

    print(f"\n[+] Finished at {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}. Elapsed: {time.perf_counter() - start_timer:.2f} seconds", file=sys.stderr)