#!/usr/bin/env python3
"""
Parse Nikto and/or OWASP ZAP JSON reports into one unified report (JSON or PDF).

Usage:
  python3 MultiScannerParser.py niktoreport.json zapreport.json
  python3 MultiScannerParser.py niktoreport.json zapreport.json -o combined.json
  python3 MultiScannerParser.py report1.json report2.json report3.json -o out.json
  python3 MultiScannerParser.py niktoreport.json zapreport.json -o merged.pdf

The extension of the -o file picks the output format (.json or .pdf). Any other extension is an error.

Findings are processed in four steps:
  1. Merge within each scanner: findings that share at least one reference (links are separated by whitespace),
     or that report the same missing security header, become one.
  2. Merge between scanners: merged findings of different scanners that share at least one reference, or that
     report the same missing security header, become one.
  3. Score what is left (Composite Score, below).
  4. Sort. Findings are sorted by Composite Score from 10 down to 0, with unscored findings last. Ties keep a fixed order.

Each finding in the output has these fields:
  ID                 position after sorting (1 = highest score)
  Title              the shortest of the merged titles (the others are listed under "Also Reported As")
  Severity           ZAP's risk label (Informational, Low, Medium, High); null if no ZAP alert is part of the finding
  Confidence         ZAP's confidence label; null if no ZAP alert is part of the finding
  Scanners           the scanners that found it
  Affected           one {url, method} pair per place it was found
  Description        the fullest description
  Solution           the first solution given (ZAP only), else null
  CVE, CWE           IDs found in the finding (each a list)
  References         links (CVE and CWE IDs are in their own fields)
  Also Reported As   the other titles the scanners gave this finding
  Composite Score    EPSS * CVSS (see below), or null if it could not be scored

Composite Score = EPSS * CVSS (needs internet access; set the NVD_API_KEY environment variable to speed it up):
  - A finding that references a CVE uses the CVSS score (from NVD) and EPSS score (from FIRST) of that CVE.
  - A finding that references only a CWE uses the average CVSS and EPSS of the CVEs NVD lists for that CWE.
  - If no such score can be found, a ZAP finding gets its own risk code (0 to 3) * 2.5, and any other finding gets null.
"""

# Score using any CVE/CWE references to CVSS.
# https://api.first.org/data/v1/epss?cve=A,B for EPSS
# https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=... for the CVSS of one CVE
# https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=... for the CVEs (and their CVSS) of one CWE

import argparse
import html
import json
import os
import re
import sys
import textwrap
import time
import urllib.request
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin

DEFAULT_OUTPUT: str = "default-parsed-report.json"

NO_SCORE: int = -1             # Internal score of a finding that could not be scored (written to the output as null)
ZAP_RISK_WEIGHT: float = 2.5   # A ZAP finding that could not be scored gets its ZAP risk code (0 to 3) * this

# ZAP's numeric codes as the labels shown in the output
SEVERITY_NAMES = {0: "Informational", 1: "Low", 2: "Medium", 3: "High"}
CONFIDENCE_NAMES = {0: "False Positive", 1: "Low", 2: "Medium", 3: "High", 4: "Confirmed"}

PDF_CHARS: int = 100   # Characters per line in a PDF (Courier 8 pt on an A4 page)
PDF_LINES: int = 75    # Lines per PDF page

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
NON_LETTERS = re.compile(r"[^a-z]")

# Security headers that scanners report under different titles and with different reference links.
# Canonical name -> spellings to look for in a title that has everything except lowercase letters removed.
HEADER_ALIASES = {
    "content-security-policy": ("contentsecuritypolicy",),
    "x-content-type-options": ("xcontenttypeoptions",),
    "strict-transport-security": ("stricttransportsecurity",),
    "permissions-policy": ("permissionspolicy",),
    "referrer-policy": ("referrerpolicy",),
    "x-frame-options": ("xframeoptions", "anticlickjacking"),
}

# A title only counts as a "header missing" finding if it also says so (in the same letters-only form).
# This keeps ZAP titles such as "CSP: Wildcard Directive" or "Strict-Transport-Security Multiple Header Entries"
# from being merged into a "header not set" finding.
HEADER_MISSING_WORDS = ("missing", "notset", "notpresent", "notfound")

# The fields of a record that hold a set of values (a dict used as an insertion-ordered set, so each value is listed once)
RECORD_SETS = ("scanners", "titles", "affected", "descriptions", "solutions", "links", "cves", "cwes")

# Scores already looked up during this run, so the same CVE or CWE is never requested twice
SCORE_CACHE: dict = {}
CWE_CACHE: dict = {}

# When the last NVD request was made, used to keep every NVD request (CVE or CWE) inside the rate limit
NVD_LAST_CALL: dict = {"time": float("-inf")}


def write_json(findings: list, output_path: Path) -> None:
    """
    Output: Write the findings to a JSON file.
    """
    with open(output_path, "w", encoding="utf-8") as output_file:
        json.dump(findings, output_file, indent=3, ensure_ascii=False)


def write_pdf(findings: list, output_path: Path) -> None:
    """
    Output: Write the findings to a PDF file using only the standard library: plain text in the built-in Courier font,
            wrapped to the page width, one block per finding.
    """
    def wrap(first: str, text, indent: str) -> list:
        # One value wrapped to the page width: its first line starts with `first`, the other lines with `indent`
        lines: list = []

        for part in str(text).splitlines() or [""]:
            start = indent if lines else first
            lines += textwrap.wrap(part, PDF_CHARS, initial_indent=start, subsequent_indent=indent,
                                   break_long_words=True, break_on_hyphens=False) or [start.rstrip()]

        return lines

    def show(entry) -> str:
        # An {url, method} pair is shown as "url (METHOD)"; empty values as "-"
        if isinstance(entry, dict):
            return f"{entry.get('url')} ({entry.get('method') or '-'})"

        return "-" if entry is None else str(entry)

    text_lines: list = ["Merged vulnerability report", f"{len(findings)} finding(s)", ""]

    for number, item in enumerate(findings, start=1):
        text_lines.append(f"Finding {number}")

        for key, value in item.items():
            values = value if isinstance(value, list) else [value]

            # One value goes on the same line as its name, several values go in a list below it
            if len(values) == 1:
                text_lines += wrap(f"  {key}: ", show(values[0]), "      ")
            else:
                text_lines.append(f"  {key}:" if values else f"  {key}: -")

                for entry in values:
                    text_lines += wrap("    - ", show(entry), "      ")

        text_lines.append("")

    pages = [text_lines[i:i + PDF_LINES] for i in range(0, len(text_lines), PDF_LINES)] or [[]]

    def escape(line: str) -> bytes:
        # The built-in font uses Windows-1252, so other characters become "?". Brackets and backslashes are escaped.
        line = "".join(char if char.isprintable() else " " for char in line)
        return line.encode("cp1252", "replace").replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")

    # PDF objects in order: 1 = catalog, 2 = list of pages (filled in below), 3 = font, then a page and its text per page
    objects: list = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>",
    ]
    kids: list = []

    for page in pages:
        page_number = len(objects) + 1
        kids.append(f"{page_number} 0 R")

        # Move to the top left of the page, then show each line (the ' operator moves down one line before showing)
        content = b"BT /F1 8 Tf 10 TL 40 802 Td\n"

        for index, line in enumerate(page):
            content += b"(" + escape(line) + (b") Tj\n" if index == 0 else b") '\n")

        content += b"ET"

        objects.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R >> >> /Contents {page_number + 1} 0 R >>".encode())
        objects.append(f"<< /Length {len(content)} >>\nstream\n".encode() + content + b"\nendstream")

    objects[1] = f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {len(kids)} >>".encode()

    # File layout: header, the objects, a table of where each object starts (xref), and a trailer that points to it
    pdf = bytearray(b"%PDF-1.4\n")
    offsets: list = []

    for number, body in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf += f"{number} 0 obj\n".encode() + body + b"\nendobj\n"

    xref_start = len(pdf)
    pdf += f"xref\n0 {len(objects) + 1}\n".encode() + b"0000000000 65535 f \n"

    for offset in offsets:
        pdf += f"{offset:010d} 00000 n \n".encode()

    pdf += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_start}\n%%EOF\n".encode()
    output_path.write_bytes(bytes(pdf))


# File extension -> the function that writes that format. To support a new format, write a function and add one line here.
OUTPUTS = {
    ".json": write_json,
    ".pdf": write_pdf,
}


def clean_html(text) -> str:
    """
    Output: Plain text. ZAP stores several fields as HTML, so line breaks are kept, tags are removed and entities converted.
    """
    return html.unescape(HTML_TAGS.sub("", HTML_BREAKS.sub("\n", text or ""))).strip()


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


def header_keys(record: dict) -> list:
    """
    Input: A record (see merge_and_score).
    Output: One ("header", name) key per title that says a security header is missing or not set, so findings about
            the same header merge even when their titles and reference links differ (ZAP's "X-Content-Type-Options
            Header Missing" and Nikto's "The X-Content-Type-Options header is not set." both give the same key).
            If a title names several headers, only the first one counts (Nikto's X-Frame-Options title also
            mentions Content-Security-Policy). Titles that are about something else, such as "CSP: Wildcard
            Directive", give no key.
    """
    keys: list = []

    for title in record["titles"]:
        flat = NON_LETTERS.sub("", title.lower())

        if not any(word in flat for word in HEADER_MISSING_WORDS):
            continue

        hits = [(flat.find(alias), name) for name, aliases in HEADER_ALIASES.items() for alias in aliases if alias in flat]

        if hits:
            keys.append(("header", min(hits)[1]))

    return keys


def merge_records(records: list, by_title: bool) -> list:
    """
    Input: Records (see merge_and_score), and by_title: whether records with no references are merged when they share a title.
    Output: The records, where every group of records that share at least one reference (or the same missing security
            header, see header_keys) is merged into one record.
            A chain counts: if A shares a reference with B, and B with C, then A, B and C are merged.
    """
    # Union-find: every record starts in its own group, and records that share a reference are joined into one group
    parent = list(range(len(records)))

    def find(index: int) -> int:
        # Follow the parents up to the root of the group, shortening the path on the way
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]

        return index

    first_seen: dict = {}  # reference or key -> the first record that had it

    for index, record in enumerate(records):
        # Records share a reference link or a header name. Without any links, records with the same title also
        # count as sharing one (only when by_title is True).
        shared = list(record["links"]) + header_keys(record)

        if not record["links"] and by_title:
            shared += [("title", title) for title in record["titles"]]

        for reference in shared:
            if reference in first_seen:
                parent[find(index)] = find(first_seen[reference])
            else:
                first_seen[reference] = index

    # Hash-map: group root -> the merged record
    merged: dict = {}

    for index, record in enumerate(records):
        root = find(index)

        if root not in merged:
            merged[root] = {field: {} for field in RECORD_SETS}
            merged[root]["fallback"] = {}

        target = merged[root]

        # update() keeps the position of values that are already there, so each value is only listed once
        for field in RECORD_SETS:
            target[field].update(record[field])

        # The scanner's own scores (numbers): keep the highest one when records are merged
        for name, value in record["fallback"].items():
            if name not in target["fallback"] or value > target["fallback"][name]:
                target["fallback"][name] = value

    return list(merged.values())


def score_records(records: list) -> list:
    """
    Input: Merged records (see merge_records).
    Output: A list of (Composite Score, finding), one per record. The finding has the fields listed at the top of this
            file (without the ID, which is given after sorting).
    """
    # A finding with a CVE is scored by that CVE. Only a finding with a CWE and no CVE is scored by its CWE.
    unique_cves: set = set()
    unique_cwes: set = set()

    for record in records:
        if record["cves"]:
            unique_cves.update(record["cves"])
        else:
            unique_cwes.update(record["cwes"])

    cve_data = fetch_cve_scores(unique_cves)
    cwe_data = fetch_cwe_scores(unique_cwes)
    results: list = []

    for record in records:
        scored: list = []

        if record["cves"]:
            scored = [cve_data[cve] for cve in record["cves"] if cve in cve_data]
        elif record["cwes"]:
            scored = [cwe_data[cwe] for cwe in record["cwes"] if cwe in cwe_data]

        # With several CVEs (or CWEs) on one finding, keep the highest CVSS and the highest EPSS
        top_cvss = max((s for s in scored if s["cvss"] is not None), key=lambda s: s["cvss"], default={})
        top_epss = max((s for s in scored if s["epss"] is not None), key=lambda s: s["epss"], default={})

        # The Composite Score needs both scores
        composite = round(top_cvss["cvss"] * top_epss["epss"], 5) if top_cvss and top_epss else None

        if composite is None:
            # No CVE/CWE score could be found: a ZAP finding is scored by its own risk code, anything else gets NO_SCORE
            risk = record["fallback"].get("ZAP Risk")
            composite = risk * ZAP_RISK_WEIGHT if risk is not None else NO_SCORE

        titles = list(record["titles"])
        descriptions = list(record["descriptions"])
        title = min(titles, key=len) if titles else None   # the shortest title is usually the clearest

        results.append((composite, {
            "Title": title,
            "Severity": SEVERITY_NAMES.get(record["fallback"].get("ZAP Risk")),
            "Confidence": CONFIDENCE_NAMES.get(record["fallback"].get("ZAP Confidence")),
            "Scanners": list(record["scanners"]),
            "Affected": [{"url": url, "method": method} for url, method in record["affected"]],
            "Description": max(descriptions, key=len) if descriptions else None,
            "Solution": next(iter(record["solutions"]), None),
            "CVE": list(record["cves"]),
            "CWE": list(record["cwes"]),
            # CVE and CWE IDs have their own fields, so only real links stay here
            "References": [link for link in record["links"] if not (CVE_EXTRACT.fullmatch(link) or CWE_EXTRACT.fullmatch(link))],
            "Also Reported As": [t for t in titles if t != title],
            "Composite Score": None if composite == NO_SCORE else composite,
        }))

    return results


def merge_and_score(items: list) -> list:
    """
    Input: The raw findings of every report, each a dict with: scanner, title, url, method, description, solution,
           references, cves, cwes and fallback (the scanner's own ratings, used when no CVSS/EPSS score can be worked out).
    Output: Findings in the unified format (see the top of this file), made in four steps:
            1. Merge within each scanner (findings that share at least one reference or missing header, or with no references a title).
            2. Merge between scanners (the merged findings that share at least one reference or missing header).
            3. Score what is left (see score_records).
            4. Sort, highest Composite Score first and unscored last, and give every finding its ID (its position).
    """
    # 1. Merge within each scanner (a scanner's findings from several report files are merged together too)
    by_scanner: dict = {}

    for item in items:
        references = item["references"] or ""

        # A raw finding becomes a record that can be merged: each field is a dict used as an insertion-ordered set
        by_scanner.setdefault(item["scanner"], []).append({
            "scanners": {item["scanner"]: None},
            "titles": {item["title"]: None} if item["title"] else {},
            "affected": {(item["url"], item["method"]): None} if item["url"] else {},
            "descriptions": {item["description"]: None} if item["description"] else {},
            "solutions": {item["solution"]: None} if item.get("solution") else {},
            "links": dict.fromkeys(references.split()),  # Each single reference, links are separated by whitespace
            "cves": dict.fromkeys(item["cves"]),
            "cwes": dict.fromkeys(item["cwes"]),
            "fallback": dict(item["fallback"]),
        })

    records: list = []

    for scanner, scanner_records in by_scanner.items():
        merged = merge_records(scanner_records, by_title=True)
        print(f"[+] {scanner}: {len(scanner_records)} raw, {len(merged)} unique, {len(scanner_records) - len(merged)} duplicate(s) merged", file=sys.stderr)
        records.extend(merged)

    # 2. Merge between scanners (after step 1 only findings of different scanners can still share a reference or header)
    if len(by_scanner) > 1:
        before = len(records)
        records = merge_records(records, by_title=False)
        print(f"[+] Between scanners: {before} unique, {len(records)} after merging, {before - len(records)} duplicate(s) merged", file=sys.stderr)

    # 3. Score the merged findings: a list of (Composite Score, finding)
    scored = score_records(records)

    # 4. Sort from the highest Composite Score (10) down to the lowest (0), with unscored (NO_SCORE) last. The position
    #    before sorting breaks ties between equal scores, so the order is always the same. Then number the findings.
    ranked = [(score, number, finding) for number, (score, finding) in enumerate(scored, start=1)]
    ranked.sort(key=lambda entry: (-entry[0], entry[1]))

    return [{"ID": rank, **finding} for rank, (_, _, finding) in enumerate(ranked, start=1)]


def parse_nikto(reports: list) -> list:
    """
    Input: List of loaded Nikto host objects.
    Output: The raw findings, one per Nikto finding (merged and scored later, see merge_and_score).
    """
    items: list = []

    for report in reports:
        # Base URL = host:port (falls back to ip when there is no host)
        host = report.get("host") or report.get("ip") or ""
        port = report.get("port")
        base = f"{host}:{port}" if host and port else host

        for vuln in report.get("vulnerabilities") or []:
            msg = vuln.get("msg") or ""
            references = vuln.get("references") or ""

            items.append({
                "scanner": "Nikto",
                # Nikto has no title field, so the title is the first sentence of the message
                "title": SENTENCE_END.split(msg.strip(), maxsplit=1)[0],
                "url": f"{base}{vuln.get('url') or ''}",
                "method": vuln.get("method"),
                "description": msg,
                "solution": None,  # Nikto has no solution field
                "references": references,
                "cves": CVE_EXTRACT.findall(references),
                "cwes": CWE_EXTRACT.findall(references),
                "fallback": {},  # Nikto has no score of its own
            })

    return items


def parse_zap(reports: list) -> list:
    """
    Input: List of loaded OWASP ZAP reports.
    Output: The raw findings, one per alert instance (merged and scored later, see merge_and_score).
            Each carries ZAP's own risk and confidence codes, the risk code is used when no CVE/CWE score is available.
    """
    items: list = []

    for report in reports:
        scanner: str = report.get("@programName") or "ZAP"
        sites = report.get("site") or []

        # ZAP may store a single site as a dict or several as a list
        for site in [sites] if isinstance(sites, dict) else sites:
            site_name = site.get("@name") or ""

            for alert in site.get("alerts") or []:
                # ZAP stores these fields as HTML, so convert them to plain text (once per alert)
                desc = clean_html(alert.get("desc"))
                references = clean_html(alert.get("reference"))
                other = clean_html(alert.get("otherinfo"))
                solution = clean_html(alert.get("solution")) or None

                # ZAP's own CWE id; 0 or a negative number (e.g. -1) means it has none
                cweid = str(alert.get("cweid") or "").strip()
                cwes = [f"CWE-{cweid}"] if cweid.isdecimal() and int(cweid) > 0 else []

                # ZAP's risk code is stored as text such as "2" (0 = Informational, 1 = Low, 2 = Medium, 3 = High),
                # its confidence code the same way (0 = False Positive, 1 = Low, 2 = Medium, 3 = High, 4 = Confirmed)
                risk = str(alert.get("riskcode", "")).strip()
                confidence = str(alert.get("confidence", "")).strip()
                fallback: dict = {}

                if risk.isdecimal():
                    fallback["ZAP Risk"] = int(risk)

                if confidence.isdecimal():
                    fallback["ZAP Confidence"] = int(confidence)

                # CVE IDs can be mentioned in the description, references or extra information
                alert_cves = CVE_EXTRACT.findall(" ".join((desc, references, other)))

                # One raw finding per instance, since the URL and method are stored per instance
                for inst in alert.get("instances") or [{}]:
                    # ZAP normally stores the full URL in 'uri'; a relative one is joined onto the site name
                    uri: str = inst.get("uri") or ""

                    if uri.startswith(("http://", "https://")):
                        url = uri
                    else:
                        url = urljoin(site_name, uri) if site_name else uri

                    items.append({
                        "scanner": scanner,
                        "title": alert.get("alert") or alert.get("name"),
                        "url": url,
                        "method": inst.get("method"),
                        "description": desc,
                        "solution": solution,
                        "references": references,
                        "cves": alert_cves + CVE_EXTRACT.findall(clean_html(inst.get("otherinfo"))),
                        "cwes": cwes,
                        "fallback": fallback,
                    })

    return items


# (name, detect, parse) - to support a new scanner, write a parse(reports) function and add one line here.
# ZAP reports have "@programName": "ZAP"; Nikto reports have a "vulnerabilities" list.
PARSERS = [
    ("Nikto", lambda reports: any("vulnerabilities" in r for r in reports), parse_nikto),
    ("OWASP ZAP", lambda reports: any(r.get("@programName") == "ZAP" for r in reports), parse_zap),
]


def main_parse_handler(path: str) -> list:
    """
    Input: Path of a supported JSON report (see the PARSERS list above).
    Output: The raw findings of the report (merged and scored later, see merge_and_score).
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
        help=f"Output filename or full path such as ~/reports/out.json. The extension sets the format ({', '.join(OUTPUTS)}), any other extension is an error (default: {DEFAULT_OUTPUT} in the working directory).",
        metavar="FILENAME",
        default=DEFAULT_OUTPUT
    )

    # Replaces argparse's default error with a short message and exit code 1
    def unrecognised(message: str) -> None:
        print(f"\n[-] Unrecognised command, type {Path(sys.argv[0]).name} -h for help.", file=sys.stderr)
        sys.exit(1)

    args_parser.error = unrecognised
    args = args_parser.parse_args()

    # Check the output file type now, so a wrong extension fails before any slow work
    suffix = Path(args.output).suffix.lower()

    if suffix not in OUTPUTS:
        kind = f"'{suffix}' files" if suffix else "files with no extension"
        print(f"\n[!] No output method for {kind} ({args.output}). Supported extensions: {', '.join(OUTPUTS)}.", file=sys.stderr)
        sys.exit(1)

    start_timer = time.perf_counter()
    print(f"\n[+] Started at {datetime.now().strftime('%a %b %e %H:%M:%S %Z %Y')} . . .", file=sys.stderr)

    all_items: list = []
    error_count: int = 0

    # A bad file is reported and skipped, so the remaining reports are still parsed
    for report_path in args.reports:
        try:
            findings = main_parse_handler(report_path)
            all_items.extend(findings)
            print(f"[+] Parsed {len(findings)} finding(s) from {report_path}", file=sys.stderr)
        except (OSError, ValueError) as err:
            # OSError = file problems, ValueError = bad JSON / bad encoding / unrecognised report format
            error_count += 1
            print(f"\n[-] Could not parse {report_path}: {err}", file=sys.stderr)

    if not all_items and error_count > 0:
        print("\n[!] No findings produced. Exiting . . .", file=sys.stderr)
        sys.exit(1)

    # Merge within scanners, then between scanners, then score (all reports are needed first, so this is done once here)
    try:
        all_findings = merge_and_score(all_items)
    except (AttributeError, TypeError, KeyError) as err:
        print(f"\n[!] Could not merge the findings: {err}", file=sys.stderr)
        sys.exit(1)

    try:
        # expanduser turns a leading ~ into the home directory; a bare filename resolves to the working directory
        saved_path = Path(args.output).expanduser().resolve()
        OUTPUTS[suffix](all_findings, saved_path)
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