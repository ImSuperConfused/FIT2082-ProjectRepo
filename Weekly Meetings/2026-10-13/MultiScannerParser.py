#!/usr/bin/env python3
"""
Parse Nikto and/or OWASP ZAP JSON reports into one unified JSON report.

Usage:
  python3 MultiScannerParser.py niktoreport.json zapreport.json
  python3 MultiScannerParser.py niktoreport.json zapreport.json -o combined.json
  python3 MultiScannerParser.py report1.json report2.json report3.json -o out.json

Nikto findings are also scored (needs internet access; set the NVD_API_KEY environment variable to speed it up):
  - A finding that references a CVE gets the CVSS score (from NVD) and EPSS score (from FIRST) of that CVE.
  - A finding that references only a CWE gets the average CVSS and EPSS of the CVEs NVD lists for that CWE.
  - A finding that references neither is not scored.
"""

# Score using any CVE/CWE references to CVSS.
# https://api.first.org/data/v1/epss?cve=A,B for EPSS
# https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=... for the CVSS of one CVE
# https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=... for the CVEs (and their CVSS) of one CWE

# Cleaned up formatting with Claude.
import argparse
import html
import json
import os
import re
import sys
import time
import urllib.request
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin

DEFAULT_OUTPUT: str = "default-parsed-report.json"

EPSS_URL: str = "https://api.first.org/data/v1/epss"
EPSS_BATCH: int = 100    # CVE IDs per request, keeps the cve= parameter under the API's 2000 character limit
NVD_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY")  # Optional free key from NVD, only ever sent to NVD
NVD_DELAY: float = 1 if NVD_API_KEY else 6.1  # Seconds between NVD requests (5 requests per rolling 30 seconds without an API key)

MAX_REPORT_BYTES: int = 100 * 1024 * 1024    # Refuse report files larger than 100 MB (json.load needs about 3x the file size in memory)
MAX_API_BYTES: int = 5 * 1024 * 1024         # 5 MB, for single CVE and EPSS responses
MAX_NVD_PAGE_BYTES: int = 30 * 1024 * 1024   # 30 MB, for one page of CVEs listed by CWE

CWE_MAX_CVES: int = 2000   # Most CVEs used for one CWE average, a common CWE can have thousands of CVEs
CWE_PAGE_SIZE: int = 500   # CVEs per NVD request for a CWE (NVD allows up to 2000)

# CVSS versions to try, in order of preference: (key in the NVD response, version label).
# NVD does not publish CVSS v2.0 for newly published CVEs, but older CVEs may only have v2.0.
CVSS_VERSIONS = (
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)

# Compiled once up front
CVE_EXTRACT = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
CWE_EXTRACT = re.compile(r"CWE-[0-9]+")
SENTENCE_END = re.compile(r"(?<=[.!?])\s+")
HTML_BREAKS = re.compile(r"</p\s*>|<br\s*/?>", re.IGNORECASE)
HTML_TAGS = re.compile(r"<[^>]+>")

# Scores already looked up during this run, so the same CVE or CWE is never requested twice
SCORE_CACHE: dict = {}
CWE_CACHE: dict = {}

# When the last NVD request was made, used to keep every NVD request (CVE or CWE) inside the rate limit
NVD_LAST_CALL: dict = {"time": float("-inf")}


def output(findings: list, output_filename: str = DEFAULT_OUTPUT) -> Path:
    """
    Output: Write the findings to a JSON file and return its full path.
    """
    # expanduser turns a leading ~ into the home directory; a bare filename resolves to the working directory
    output_path: Path = Path(output_filename).expanduser().resolve()

    with open(output_path, "w", encoding="utf-8") as output_file:
        json.dump(findings, output_file, indent=3)

    return output_path


def finding(scanner: str, title: str, site_url: str, method: str, description: str, references: str, **extra) -> dict:
    """
    Output: One finding in the unified format. Empty values become None so every scanner is treated the same.
    Optional extra fields (CVE, CVSS, ...) are added after the six standard fields exactly as given.
    """
    return {
        "Scanner": scanner or None,
        "Title": title or None,
        "Site URL": site_url or None,
        "Method": method or None,
        "Description": description or None,
        "References": references or None,
        **extra,
    }


def get_json(url: str, timeout: int, max_bytes: int = MAX_API_BYTES) -> dict:
    """
    Output: The JSON response of a GET request.
    Raises OSError (no connection, HTTP error, timeout) or ValueError (invalid JSON, response too large) on failure.
    """
    headers = {"User-Agent": "MultiScannerParser"}

    # NVD only: wait if needed to stay inside its rate limit, and send the API key (never send it to any other site)
    if url.startswith(NVD_URL):
        wait = NVD_DELAY - (time.monotonic() - NVD_LAST_CALL["time"])

        if wait > 0:
            time.sleep(wait)

        NVD_LAST_CALL["time"] = time.monotonic()

        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY

    request = urllib.request.Request(url, headers=headers)

    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read(max_bytes + 1)

        if len(body) > max_bytes:
            raise ValueError(f"Response larger than {max_bytes} bytes.")

        return json.loads(body.decode("utf-8"))


def cvss_scores(metrics: dict) -> dict:
    """
    Input: The "metrics" object of one NVD CVE record.
    Output: {CVSS version: base score} for every version that has a score, most preferred version first.
    """
    scores: dict = {}

    for key, version in CVSS_VERSIONS:
        if metrics.get(key):
            scores[version] = metrics[key][0]["cvssData"]["baseScore"]

    return scores


def fetch_epss(cves: list) -> dict:
    """
    Input: List of CVE IDs.
    Output: {CVE ID: {epss, percentile, date}} for every CVE that FIRST has a score for.
    A failed request prints a warning and its CVEs are simply missing from the result.
    """
    found: dict = {}

    for start in range(0, len(cves), EPSS_BATCH):
        batch = cves[start:start + EPSS_BATCH]

        try:
            data = get_json(f"{EPSS_URL}?cve={','.join(batch)}", timeout=10)

            for item in data.get("data") or []:
                found[item["cve"]] = {
                    "epss": float(item["epss"]),
                    "percentile": float(item["percentile"]),
                    "date": item.get("date"),
                }
        except (OSError, ValueError, KeyError, TypeError) as err:
            print(f"[!] EPSS lookup failed: {err}", file=sys.stderr)

    return found


def fetch_cve_scores(cves: set) -> dict:
    """
    Input: Set of unique CVE IDs.
    Output: {CVE ID: {cvss, cvss_version, epss, epss_percentile, epss_date}}, with None for anything not found.
    A failed lookup prints a warning and leaves that score as None, so it never stops the parse.
    """
    # Only look up CVEs that were not already looked up for an earlier report
    new_cves = sorted(cve for cve in cves if cve not in SCORE_CACHE)

    for cve in new_cves:
        SCORE_CACHE[cve] = {"cvss": None, "cvss_version": None, "epss": None, "epss_percentile": None, "epss_date": None}

    if new_cves:
        wait = round(NVD_DELAY * (len(new_cves) - 1))
        print(f"[*] Looking up scores for {len(new_cves)} CVE(s), NVD is rate limited so this takes about {wait}s...", file=sys.stderr)

    # 1. EPSS (FIRST): one request per batch of CVEs
    for cve, item in fetch_epss(new_cves).items():
        score = SCORE_CACHE.get(cve)

        # CVEs missing from the response keep None, which is not the same as an EPSS of 0
        if score is not None:
            score["epss"] = item["epss"]
            score["epss_percentile"] = item["percentile"]
            score["epss_date"] = item["date"]

    # 2. CVSS (NVD): one request per CVE (get_json spaces the requests out to stay inside the rate limit)
    for cve in new_cves:
        try:
            data = get_json(f"{NVD_URL}?cveId={cve}", timeout=15)
            vulns = data.get("vulnerabilities") or []
            metrics = vulns[0].get("cve", {}).get("metrics", {}) if vulns else {}
            scores = cvss_scores(metrics)

            # The preferred CVSS version that has a score for this CVE comes first
            if scores:
                version, base_score = next(iter(scores.items()))
                SCORE_CACHE[cve]["cvss"] = base_score
                SCORE_CACHE[cve]["cvss_version"] = version
        except (OSError, ValueError, KeyError, IndexError, TypeError) as err:
            print(f"[!] NVD lookup failed for {cve}: {err}", file=sys.stderr)

    return {cve: SCORE_CACHE[cve] for cve in cves}


def fetch_cwe_scores(cwes: set) -> dict:
    """
    Input: Set of CWE IDs, for findings that reference a CWE but no CVE.
    Output: {CWE ID: {cvss, cvss_version, epss, cve_count}}, the average CVSS and EPSS of the CVEs NVD lists for that
            CWE (at most CWE_MAX_CVES of them), with None for anything not found.
    """
    for cwe in sorted(cwe for cwe in cwes if cwe not in CWE_CACHE):
        CWE_CACHE[cwe] = {"cvss": None, "cvss_version": None, "epss": None, "cve_count": 0}
        print(f"[*] Looking up the CVEs for {cwe} (up to {CWE_MAX_CVES}), then their scores...", file=sys.stderr)

        # 1. CVEs that have this CWE, together with their CVSS scores, from NVD (one page at a time)
        cvss_by_cve: dict = {}
        start = 0

        try:
            while start < CWE_MAX_CVES:
                size = min(CWE_PAGE_SIZE, CWE_MAX_CVES - start)
                url = f"{NVD_URL}?cweId={cwe}&resultsPerPage={size}&startIndex={start}"
                data = get_json(url, timeout=60, max_bytes=MAX_NVD_PAGE_BYTES)
                vulns = data.get("vulnerabilities") or []

                for item in vulns:
                    cvss_by_cve[item["cve"]["id"]] = cvss_scores(item["cve"].get("metrics", {}))

                start += len(vulns)

                # Stop after the last page
                if not vulns or start >= data.get("totalResults", 0):
                    break
        except (OSError, ValueError, KeyError, IndexError, TypeError) as err:
            print(f"[!] NVD lookup failed for {cwe}: {err}", file=sys.stderr)

        if not cvss_by_cve:
            print(f"[!] No CVEs found for {cwe}, so it is not scored.", file=sys.stderr)
            continue

        # 2. Average CVSS. CVSS versions are not comparable, so only the version that covers the most CVEs is used
        counts: dict = {}

        for scores in cvss_by_cve.values():
            for version in scores:
                counts[version] = counts.get(version, 0) + 1

        if counts:
            # Ties go to the more preferred version, because CVSS_VERSIONS is in order of preference
            version = max((v for _, v in CVSS_VERSIONS if v in counts), key=counts.get)
            values = [scores[version] for scores in cvss_by_cve.values() if version in scores]

            CWE_CACHE[cwe]["cvss"] = round(sum(values) / len(values), 1)
            CWE_CACHE[cwe]["cvss_version"] = version

        # 3. Average EPSS over the same CVEs
        epss_values = [item["epss"] for item in fetch_epss(sorted(cvss_by_cve)).values()]

        if epss_values:
            CWE_CACHE[cwe]["epss"] = round(sum(epss_values) / len(epss_values), 5)

        CWE_CACHE[cwe]["cve_count"] = len(cvss_by_cve)

    return {cwe: CWE_CACHE[cwe] for cwe in cwes}


def parse_nikto(reports: list) -> list:
    """
    Input: List of loaded Nikto host objects.
    Output: Findings in the unified format with duplicates removed and CVSS/EPSS scores added.
            Findings that share a title are merged into one, and their URLs are comma separated.
    """
    # Hash-map: title -> the first finding seen with that title, plus every URL, CVE and CWE found for it
    groups: dict = {}
    raw_count: int = 0

    for report in reports:
        # Base URL = host:port (falls back to ip when there is no host)
        host = report.get("host") or report.get("ip") or ""
        port = report.get("port")
        base = f"{host}:{port}" if host and port else host

        for vuln in report.get("vulnerabilities") or []:
            raw_count += 1
            msg = vuln.get("msg") or ""

            # Nikto has no title field, so the title is the first sentence of the message
            title = SENTENCE_END.split(msg.strip(), maxsplit=1)[0]
            url = f"{base}{vuln.get('url') or ''}"

            # A finding with no title gets its own key, so empty messages are never merged together
            key = title or f"UNKNOWN-{len(groups)}"

            # First time this title is seen: store it (later duplicates only add their URL, CVEs and CWEs)
            if key not in groups:
                groups[key] = {"title": title, "msg": msg, "vuln": vuln, "urls": {}, "cves": {}, "cwes": {}}

            group = groups[key]
            group["urls"][url] = None

            # CVE and CWE IDs in the references (a dict is used as an insertion-ordered set)
            references = vuln.get("references") or ""

            for cve in CVE_EXTRACT.findall(references):
                group["cves"][cve] = None

            for cwe in CWE_EXTRACT.findall(references):
                group["cwes"][cwe] = None

    print(f"[+] Nikto: {raw_count} raw, {len(groups)} unique, {raw_count - len(groups)} duplicate(s) merged", file=sys.stderr)

    # A finding with a CVE is scored by that CVE. Only a finding with a CWE and no CVE is scored by its CWE.
    unique_cves: set = set()
    unique_cwes: set = set()

    for group in groups.values():
        if group["cves"]:
            unique_cves.update(group["cves"])
        else:
            unique_cwes.update(group["cwes"])

    cve_data = fetch_cve_scores(unique_cves)
    cwe_data = fetch_cwe_scores(unique_cwes)
    results: list = []

    for group in groups.values():
        vuln = group["vuln"]
        cves = group["cves"]
        cwes = group["cwes"]

        if cves:
            scored = [cve_data[cve] for cve in cves if cve in cve_data]
            basis = "CVE"
        else:
            scored = [cwe_data[cwe] for cwe in cwes if cwe in cwe_data]
            used = [f"{cwe}: {cwe_data[cwe]['cve_count']} CVEs" for cwe in cwes if cwe in cwe_data]
            basis = "CWE average (" + ", ".join(used) + ")"

        # With several CVEs (or CWEs) on one finding, keep the highest CVSS and the highest EPSS
        top_cvss = max((s for s in scored if s["cvss"] is not None), key=lambda s: s["cvss"], default={})
        top_epss = max((s for s in scored if s["epss"] is not None), key=lambda s: s["epss"], default={})

        # Every Nikto finding gets the same extra fields, None when there is nothing to fill in
        extra = {"CVE": ",".join(cves) or None}
        extra["CWE"] = ",".join(cwes) or None
        extra["CVSS"] = top_cvss.get("cvss")
        extra["CVSS Version"] = top_cvss.get("cvss_version")
        extra["EPSS"] = top_epss.get("epss")
        extra["Score Basis"] = basis if (top_cvss or top_epss) else None

        results.append(finding("Nikto", group["title"], ",".join(group["urls"]), vuln.get("method"), group["msg"], vuln.get("references"), **extra))

    return results


def parse_zap(reports: list) -> list:
    """
    Input: List of loaded OWASP ZAP reports.
    Output: Findings in the unified format (one finding per alert instance). ZAP alerts have no CVE
            references, so ZAP findings are not scored.
    """
    results: list = []

    for report in reports:
        scanner: str = report.get("@programName")
        sites = report.get("site")

        # ZAP may store a single site as a dict or several as a list
        if isinstance(sites, dict):
            sites = [sites]

        for site in sites:
            site_name = site.get("@name") or ""

            for alert in site.get("alerts") or []:
                # ZAP stores these two fields as HTML, so convert them to plain text (once per alert)
                desc, ref = (
                    html.unescape(HTML_TAGS.sub("", HTML_BREAKS.sub("\n", alert.get(key) or ""))).strip()
                    for key in ("desc", "reference")
                )

                # One finding per instance, since the URL and method are stored per instance
                for inst in alert.get("instances") or []:
                    # ZAP normally stores the full URL in 'uri'; a relative one is joined onto the site name
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
                            references=ref,
                        )
                    )

    return results


# (name, detect, parse) - to support a new scanner, write a parse(reports) function and add one line here.
# ZAP reports have "@programName": "ZAP"; Nikto reports have a "vulnerabilities" list.
PARSERS = [
    ("Nikto", lambda reports: any("vulnerabilities" in r for r in reports), parse_nikto),
    ("OWASP ZAP", lambda reports: any(r.get("@programName") == "ZAP" for r in reports), parse_zap),
]


def main_parse_handler(path: str) -> list:
    """
    Input: Path of a supported JSON report (see the PARSERS list above).
    Output: Findings in the unified format.
    """
    # Refuse huge files before reading them, json.load needs roughly 3x the file size in memory
    if Path(path).stat().st_size > MAX_REPORT_BYTES:
        raise ValueError(f"{path} is larger than {MAX_REPORT_BYTES // (1024 * 1024)} MB")

    try:
        # utf-8-sig also accepts files that start with a byte order mark (plain utf-8 rejects them)
        with open(path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
    except (RecursionError, MemoryError) as err:
        # Deeply nested JSON raises RecursionError, which is not a ValueError, so convert it
        raise ValueError(f"{path} could not be loaded ({type(err).__name__})") from err

    reports: list = []

    # A single object is wrapped in a list so every report type is handled the same way
    for item in data if isinstance(data, list) else [data]:
        if isinstance(item, dict):
            reports.append(item)

    if not reports:
        raise ValueError(f"No JSON objects found in {path}")

    # The first scanner whose detect test matches parses the report
    for name, detect, parse in PARSERS:
        if detect(reports):
            print(f"[+] Detected report type: {name} ({path})! Parsing . . .", file=sys.stderr)

            try:
                return parse(reports)
            except (AttributeError, TypeError, KeyError) as err:
                raise ValueError(f"{name} report is not in the expected format: {err}") from err

    supported = ", ".join(name for name, _, _ in PARSERS)
    raise ValueError(f"Unrecognised report format in {path}. Supported types: {supported}.")


def main():
    args_parser = argparse.ArgumentParser(
        prog="Python Web Vulnerability Prioritiser",
        description="Parse web vulnerability scanner reports into one unified JSON report.",
        epilog="Have fun!"
    )

    # One or more report files
    args_parser.add_argument(
        "reports",
        nargs="+",
        help="Path(s) of the Nikto and/or OWASP ZAP JSON report(s) to parse.",
        metavar="REPORT"
    )
    args_parser.add_argument(
        "-o",
        "--output",
        help=f"Output filename or full path such as ~/reports/out.json (default: {DEFAULT_OUTPUT} in the working directory).",
        metavar="FILENAME",
        default=DEFAULT_OUTPUT
    )

    # Replaces argparse's default error with a short message and exit code 1
    def unrecognised(message: str) -> None:
        print(f"\n[-] Unrecognised command, type {Path(sys.argv[0]).name} -h for help.", file=sys.stderr)
        sys.exit(1)

    args_parser.error = unrecognised
    args = args_parser.parse_args()

    start_timer = time.perf_counter()
    print(f"\n[+] Started at {datetime.now().strftime('%a %b %e %H:%M:%S %Z %Y')} . . .", file=sys.stderr)

    all_findings: list = []
    error_count: int = 0

    # A bad file is reported and skipped, so the remaining reports are still parsed
    for report_path in args.reports:
        try:
            findings = main_parse_handler(report_path)
            all_findings.extend(findings)
            print(f"[+] Parsed {len(findings)} finding(s) from {report_path}", file=sys.stderr)
        except (OSError, ValueError) as err:
            # OSError = file problems, ValueError = bad JSON / bad encoding / unrecognised report format
            error_count += 1
            print(f"\n[-] Could not parse {report_path}: {err}", file=sys.stderr)

    if not all_findings and error_count > 0:
        print("\n[!] No findings produced. Exiting . . .", file=sys.stderr)
        sys.exit(1)

    try:
        saved_path = output(all_findings, args.output)
    except OSError as err:
        # e.g. the folder in the given path does not exist, or the path is a folder
        print(f"\n[!] Could not write report: {err}", file=sys.stderr)
        sys.exit(1)

    print(f"\n[+] Total: {len(all_findings)} finding(s). Report written to: {saved_path} . . .", file=sys.stderr)

    if error_count > 0:
        print(f"[-] {error_count} file(s) had errors (see messages above) . . .", file=sys.stderr)

    print(f"\n[+] Finished at {datetime.now().strftime('%a %b %e %H:%M:%S %Z %Y')}. Elapsed: {time.perf_counter() - start_timer:.2f} seconds.", file=sys.stderr)


if __name__ == "__main__":
    main()