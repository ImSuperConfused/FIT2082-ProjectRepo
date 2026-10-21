#!/usr/bin/env python3
"""
Parse Nikto and/or OWASP ZAP JSON reports into one unified report (JSON or PDF).

Usage:
  python3 VulnScannerPrioritiser.py report1.json report2.json
  python3 VulnScannerPrioritiser.py report1.json report2.json report3.json -o(--output) out.json
  python3 VulnScannerPrioritiser.py report1.json report2.json -o(--output) merged.pdf
"""

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

NO_SCORE: int = -1             # The Composite Score of a finding that could not be scored
ZAP_RISK_WEIGHT: float = 2.5   # A ZAP finding that could not be scored gets its ZAP risk code (0 to 3) * this

EPSS_URL: str = "https://api.first.org/data/v1/epss"
EPSS_BATCH: int = 100    # CVE IDs per request, keeps the cve= parameter under the API's 2000 character limit
NVD_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY")  # Optional free key from NVD
NVD_DELAY: float = 1 if NVD_API_KEY else 6.1  # Seconds between NVD requests

MAX_REPORT_BYTES: int = 100 * 1024 * 1024    # Refuse report files larger than 100 MB
MAX_API_BYTES: int = 5 * 1024 * 1024         # 5 MB, for single CVE and EPSS responses
MAX_NVD_PAGE_BYTES: int = 30 * 1024 * 1024   # 30 MB, for one page of CVEs listed by CWE

CWE_MAX_CVES: int = 2000   # Most CVEs used for one CWE average
CWE_PAGE_SIZE: int = 500   # CVEs per NVD request for a CWE

# CVSS versions to try, in order of preference
CVSS_VERSIONS = (
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)

# Compiled regex patterns
CVE_EXTRACT = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}", re.IGNORECASE)
CWE_EXTRACT = re.compile(r"CWE-?[0-9]+", re.IGNORECASE)
SENTENCE_END = re.compile(r"(?<=[.!?])\s+")
HTML_BREAKS = re.compile(r"</p\s*>|<br\s*/?>", re.IGNORECASE)
HTML_TAGS = re.compile(r"<[^>]+>")

RECORD_SETS = ("scanners", "titles", "urls", "methods", "descriptions", "links", "cves", "cwes")

SCORE_CACHE: dict = {}
CWE_CACHE: dict = {}
NVD_LAST_CALL: dict = {"time": float("-inf")}


def write_json(findings: list, output_path: Path) -> None:
    """Output: Write the findings to a JSON file."""
    with open(output_path, "w", encoding="utf-8") as output_file:
        json.dump(findings, output_file, indent=3)


def write_pdf(findings: list, output_path: Path) -> None:
    """
    Output: Write findings to a styled PDF report using Python standard library only.
    Features:
      - Blue interactive PDF hyperlinks.
      - Dynamic CVE / CWE URL generation without a static dictionary.
      - Continuous Green -> Blue -> Red RGB gradient transition for severity score badges.
      - Card layouts, custom header banner, and automatic multi-page flow.
    """
    PAGE_WIDTH = 595   # Standard A4 width in pt
    PAGE_HEIGHT = 842  # Standard A4 height in pt
    MARGIN_LEFT = 36
    CONTENT_WIDTH = PAGE_WIDTH - (MARGIN_LEFT * 2)  # 523pt
    
    TOP_Y = 770
    BOTTOM_Y = 50
    CHARS_PER_LINE = 82

    def escape_pdf_str(text: str) -> bytes:
        """Sanitize text and encode to standard WinAnsi / Latin-1 string."""
        clean = "".join(char if char.isprintable() else " " for char in str(text or ""))
        encoded = clean.encode("cp1252", errors="replace")
        return encoded.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")

    def format_link(item: str) -> tuple[str, str]:
        """
        Dynamically converts URLs, CVE IDs, or CWE IDs to (display_text, target_url)
        without needing a static dictionary mapping.
        """
        item_str = str(item or "").strip()
        if not item_str:
            return "", None

        # Standard HTTP/HTTPS Web URL
        if item_str.startswith(("http://", "https://")):
            return item_str, item_str

        # CVE Pattern -> NVD Detail Page
        cve_match = CVE_EXTRACT.search(item_str)
        if cve_match:
            cve_id = cve_match.group(0).upper()
            return item_str, f"https://nvd.nist.gov/vuln/detail/{cve_id}"

        # CWE Pattern -> MITRE CWE Definition Page
        cwe_match = CWE_EXTRACT.search(item_str)
        if cwe_match:
            digits_match = re.search(r"\d+", cwe_match.group(0))
            if digits_match:
                return item_str, f"https://cwe.mitre.org/data/definitions/{digits_match.group(0)}.html"

        return item_str, None

    def get_score_color(score) -> tuple[tuple[float, float, float], str]:
        """
        Calculates RGB color transition from Green (0) -> Blue (5) -> Red (10).
        Green = Low (0.0), Blue = Medium (5.0), Red = High (10.0).
        """
        GREEN = (0.13, 0.69, 0.30)  # Green for Low
        BLUE  = (0.15, 0.45, 0.82)  # Blue for Medium
        RED   = (0.86, 0.15, 0.15)  # Red for High
        GREY  = (0.39, 0.45, 0.55)  # Grey for Unscored

        if not isinstance(score, (int, float)) or score < 0:
            return GREY, "NO SCORE (-1)"

        s = max(0.0, min(10.0, float(score)))

        if s <= 5.0:
            # Interpolate Green -> Blue
            t = s / 5.0
            r = GREEN[0] + t * (BLUE[0] - GREEN[0])
            g = GREEN[1] + t * (BLUE[1] - GREEN[1])
            b = GREEN[2] + t * (BLUE[2] - GREEN[2])
        else:
            # Interpolate Blue -> Red
            t = (s - 5.0) / 5.0
            r = BLUE[0] + t * (RED[0] - BLUE[0])
            g = BLUE[1] + t * (RED[1] - BLUE[1])
            b = BLUE[2] + t * (RED[2] - BLUE[2])

        if score >= 7.0:
            label = f"HIGH ({score:.2f})"
        elif score >= 4.0:
            label = f"MED ({score:.2f})"
        else:
            label = f"LOW ({score:.2f})"

        return (r, g, b), label

    def wrap_text(text: str, width: int) -> list:
        """Wrap text into clean lines while honoring existing linebreaks."""
        lines = []
        for raw_line in str(text or "").splitlines():
            if not raw_line.strip():
                lines.append("")
                continue
            wrapped = textwrap.wrap(
                raw_line,
                width=width,
                break_long_words=True,
                break_on_hyphens=False
            )
            lines.extend(wrapped if wrapped else [""])
        return lines

    cards = []
    for idx, finding in enumerate(findings, start=1):
        score = finding.get("Composite Score", NO_SCORE)
        badge_bg, badge_label = get_score_color(score)

        scanners = ", ".join(finding.get("Scanner", [])) or "-"
        titles = " / ".join(finding.get("Title", [])) or "Untitled Finding"
        
        fields = [
            ("Scanner", scanners),
            ("Site URL", finding.get("Site URL", [])),
            ("Method", finding.get("Method", [])),
            ("Description", finding.get("Description", [])),
            ("References", finding.get("References", [])),
        ]

        cards.append({
            "num": idx,
            "title": titles,
            "badge_bg": badge_bg,
            "badge_label": badge_label,
            "fields": fields
        })

    pages_ops = []  # Stores tuple of (ops_list, page_annotations_list)
    current_ops = []
    current_annots = []
    current_y = TOP_Y

    def start_new_page():
        nonlocal current_ops, current_annots, current_y
        if current_ops:
            pages_ops.append((current_ops, current_annots))
        current_ops = []
        current_annots = []
        current_y = TOP_Y

    start_new_page()

    for card in cards:
        header_height = 22
        card_content_height = header_height
        field_render_data = []

        for label, val in card["fields"]:
            val_items = val if isinstance(val, list) else [val]
            parsed_lines = []
            
            for item in (val_items or ["-"]):
                disp_text, target_url = format_link(item)
                wrapped = wrap_text(disp_text, CHARS_PER_LINE)
                for line in wrapped:
                    parsed_lines.append((line, target_url))

            line_height = max(1, len(parsed_lines)) * 11
            field_height = line_height + 4
            field_render_data.append((label, parsed_lines, field_height))
            card_content_height += field_height

        card_content_height += 10  # Bottom padding

        # Pagination check
        if (current_y - card_content_height < BOTTOM_Y) and (current_y < TOP_Y):
            start_new_page()

        card_top = current_y
        card_box_height = card_content_height

        # Outer Box
        current_ops.append(
            f"0.85 0.88 0.92 RG 0.75 w {MARGIN_LEFT} {card_top - card_box_height} {CONTENT_WIDTH} {card_box_height} re S\n"
        )
        # Header Box
        current_ops.append(
            f"0.95 0.96 0.98 rg {MARGIN_LEFT + 0.5} {card_top - header_height} {CONTENT_WIDTH - 1} {header_height - 0.5} re f\n"
        )
        # Header Divider Line
        current_ops.append(
            f"0.82 0.85 0.89 RG 0.5 w {MARGIN_LEFT} {card_top - header_height} m {MARGIN_LEFT + CONTENT_WIDTH} {card_top - header_height} l S\n"
        )

        title_text = f"#{card['num']}  {card['title']}"
        if len(title_text) > 65:
            title_text = title_text[:62] + "..."

        title_str = escape_pdf_str(title_text).decode("latin1")
        current_ops.append(f"BT /F2 10 Tf 0.12 0.16 0.22 rg {MARGIN_LEFT + 8} {card_top - 15} Td ({title_str}) Tj ET\n")

        # Score Badge
        badge_w, badge_h = 74, 14
        badge_x = MARGIN_LEFT + CONTENT_WIDTH - badge_w - 6
        badge_y = card_top - 18
        r, g, b = card["badge_bg"]
        badge_str = escape_pdf_str(card["badge_label"]).decode("latin1")
        current_ops.append(f"{r:.2f} {g:.2f} {b:.2f} rg {badge_x} {badge_y} {badge_w} {badge_h} re f\n")
        current_ops.append(f"BT /F2 8 Tf 1 1 1 rg {badge_x + 6} {badge_y + 3.5} Td ({badge_str}) Tj ET\n")

        # Render Field Rows
        field_y = card_top - header_height - 12
        for label, parsed_lines, f_height in field_render_data:
            lbl_str = escape_pdf_str(f"{label}:").decode("latin1")
            current_ops.append(f"BT /F2 8.5 Tf 0.25 0.3 0.38 rg {MARGIN_LEFT + 10} {field_y} Td ({lbl_str}) Tj ET\n")

            line_y = field_y
            for idx, (line, url) in enumerate(parsed_lines):
                if idx > 0:
                    line_y -= 11
                text_str = escape_pdf_str(line).decode("latin1")

                if url:
                    # Blue font for active hyperlinks
                    current_ops.append(f"BT /F1 8.5 Tf 0.12 0.38 0.82 rg {MARGIN_LEFT + 80} {line_y} Td ({text_str}) Tj ET\n")

                    # Add interactive PDF link annotation rectangle
                    x1 = MARGIN_LEFT + 80
                    y1 = line_y - 2
                    x2 = x1 + min(len(line) * 5.0, CONTENT_WIDTH - 90)
                    y2 = line_y + 9

                    annot_str = f"<< /Type /Annot /Subtype /Link /Rect [{x1:.1f} {y1:.1f} {x2:.1f} {y2:.1f}] /Border [0 0 0] /A << /S /URI /URI ({escape_pdf_str(url).decode('latin1')}) >> >>"
                    current_annots.append(annot_str)
                else:
                    # Standard dark text
                    current_ops.append(f"BT /F1 8.5 Tf 0.15 0.18 0.23 rg {MARGIN_LEFT + 80} {line_y} Td ({text_str}) Tj ET\n")

            field_y -= f_height

        current_y -= (card_box_height + 14)

    if current_ops:
        pages_ops.append((current_ops, current_annots))

    total_pages = len(pages_ops)
    timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"",  # Placeholder for Pages index
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",      # /F1
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>", # /F2
    ]

    kids = []
    next_obj_id = 5

    # Assign PDF object IDs for pages and URI link annotations
    for p_idx, (page_op_list, page_annots) in enumerate(pages_ops, start=1):
        page_obj_num = next_obj_id
        content_obj_num = page_obj_num + 1
        next_obj_id += 2

        annot_obj_ids = []
        for _ in page_annots:
            annot_obj_ids.append(next_obj_id)
            next_obj_id += 1

        kids.append(f"{page_obj_num} 0 R")

        hdr_title = escape_pdf_str("Vulnerability Assessment Prioritisation Report").decode("latin1")
        hdr_meta = escape_pdf_str(f"Total Findings: {len(findings)}  |  Generated: {timestamp_str}").decode("latin1")

        header_stream = [
            f"0.06 0.09 0.16 rg 0 792 {PAGE_WIDTH} 50 re f\n",
            f"0.25 0.45 0.85 rg 0 788 {PAGE_WIDTH} 4 re f\n",
            f"BT /F2 13 Tf 1 1 1 rg {MARGIN_LEFT} 812 Td ({hdr_title}) Tj ET\n",
            f"BT /F1 8.5 Tf 0.7 0.78 0.9 rg {MARGIN_LEFT} 798 Td ({hdr_meta}) Tj ET\n",
        ]

        ftr_left = escape_pdf_str("Python Vulnerability Prioritiser Audit").decode("latin1")
        ftr_right = escape_pdf_str(f"Page {p_idx} of {total_pages}").decode("latin1")

        footer_stream = [
            f"0.85 0.88 0.92 RG 0.5 w {MARGIN_LEFT} 36 m {PAGE_WIDTH - MARGIN_LEFT} 36 l S\n",
            f"BT /F1 8 Tf 0.45 0.5 0.58 rg {MARGIN_LEFT} 24 Td ({ftr_left}) Tj ET\n",
            f"BT /F2 8 Tf 0.45 0.5 0.58 rg {PAGE_WIDTH - MARGIN_LEFT - 55} 24 Td ({ftr_right}) Tj ET\n"
        ]

        full_content = "".join(header_stream + page_op_list + footer_stream).encode("latin1")

        annots_ref_str = f"/Annots [{' '.join(f'{aid} 0 R' for aid in annot_obj_ids)}]" if annot_obj_ids else ""
        page_dict = f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> {annots_ref_str} /Contents {content_obj_num} 0 R >>".encode("latin1")
        content_dict = f"<< /Length {len(full_content)} >>\nstream\n".encode("latin1") + full_content + b"\nendstream"

        objects.append(page_dict)
        objects.append(content_dict)

        for a_str in page_annots:
            objects.append(a_str.encode("latin1"))

    objects[1] = f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {len(kids)} >>".encode("latin1")

    # Serialize PDF stream
    pdf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []

    for number, body in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf += f"{number} 0 obj\n".encode("latin1") + body + b"\nendobj\n"

    xref_start = len(pdf)
    pdf += f"xref\n0 {len(objects) + 1}\n".encode("latin1") + b"0000000000 65535 f \n"

    for offset in offsets:
        pdf += f"{offset:010d} 00000 n \n".encode("latin1")

    pdf += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_start}\n%%EOF\n".encode("latin1")
    output_path.write_bytes(bytes(pdf))


# Output handler registry
OUTPUTS = {
    ".json": write_json,
    ".pdf": write_pdf,
}


def clean_html(text) -> str:
    """Output: Plain text. Converts HTML tags and entities to plain text."""
    return html.unescape(HTML_TAGS.sub("", HTML_BREAKS.sub("\n", text or ""))).strip()


def get_json(url: str, timeout: int, max_bytes: int = MAX_API_BYTES) -> dict:
    """Output: The JSON response of a GET request."""
    headers = {"User-Agent": "MultiScannerParser"}

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
    """Input: The 'metrics' object of one NVD CVE record."""
    scores: dict = {}
    for key, version in CVSS_VERSIONS:
        if metrics.get(key):
            scores[version] = metrics[key][0]["cvssData"]["baseScore"]
    return scores


def fetch_epss(cves: list) -> dict:
    """Input: List of CVE IDs."""
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
    """Input: Set of unique CVE IDs."""
    new_cves = sorted(cve for cve in cves if cve not in SCORE_CACHE)
    for cve in new_cves:
        SCORE_CACHE[cve] = {"cvss": None, "cvss_version": None, "epss": None, "epss_percentile": None, "epss_date": None}

    if new_cves:
        wait = round(NVD_DELAY * (len(new_cves) - 1))
        print(f"[*] Looking up scores for {len(new_cves)} CVE(s), NVD rate limit takes about {wait}s...", file=sys.stderr)

    for cve, item in fetch_epss(new_cves).items():
        score = SCORE_CACHE.get(cve)
        if score is not None:
            score["epss"] = item["epss"]
            score["epss_percentile"] = item["percentile"]
            score["epss_date"] = item["date"]

    for cve in new_cves:
        try:
            data = get_json(f"{NVD_URL}?cveId={cve}", timeout=15)
            vulns = data.get("vulnerabilities") or []
            metrics = vulns[0].get("cve", {}).get("metrics", {}) if vulns else {}
            scores = cvss_scores(metrics)

            if scores:
                version, base_score = next(iter(scores.items()))
                SCORE_CACHE[cve]["cvss"] = base_score
                SCORE_CACHE[cve]["cvss_version"] = version
        except (OSError, ValueError, KeyError, IndexError, TypeError) as err:
            print(f"[!] NVD lookup failed for {cve}: {err}", file=sys.stderr)

    return {cve: SCORE_CACHE[cve] for cve in cves}


def fetch_cwe_scores(cwes: set) -> dict:
    """Input: Set of CWE IDs."""
    for cwe in sorted(cwe for cwe in cwes if cwe not in CWE_CACHE):
        CWE_CACHE[cwe] = {"cvss": None, "cvss_version": None, "epss": None, "cve_count": 0}
        print(f"[*] Looking up the CVEs for {cwe}...", file=sys.stderr)

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
                if not vulns or start >= data.get("totalResults", 0):
                    break
        except (OSError, ValueError, KeyError, IndexError, TypeError) as err:
            print(f"[!] NVD lookup failed for {cwe}: {err}", file=sys.stderr)

        if not cvss_by_cve:
            print(f"[!] No CVEs found for {cwe}, un-scored.", file=sys.stderr)
            continue

        counts: dict = {}
        for scores in cvss_by_cve.values():
            for version in scores:
                counts[version] = counts.get(version, 0) + 1

        if counts:
            version = max((v for _, v in CVSS_VERSIONS if v in counts), key=counts.get)
            values = [scores[version] for scores in cvss_by_cve.values() if version in scores]

            CWE_CACHE[cwe]["cvss"] = round(sum(values) / len(values), 1)
            CWE_CACHE[cwe]["cvss_version"] = version

        epss_values = [item["epss"] for item in fetch_epss(sorted(cvss_by_cve)).values()]

        if epss_values:
            CWE_CACHE[cwe]["epss"] = round(sum(epss_values) / len(epss_values), 5)

        CWE_CACHE[cwe]["cve_count"] = len(cvss_by_cve)

    return {cwe: CWE_CACHE[cwe] for cwe in cwes}


def merge_records(records: list, by_title: bool) -> list:
    """Merges records sharing common references or titles into combined findings."""
    parent = list(range(len(records)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    first_seen: dict = {}

    for index, record in enumerate(records):
        shared = list(record["links"]) or ([("title", title) for title in record["titles"]] if by_title else [])

        for reference in shared:
            if reference in first_seen:
                parent[find(index)] = find(first_seen[reference])
            else:
                first_seen[reference] = index

    merged: dict = {}

    for index, record in enumerate(records):
        root = find(index)
        if root not in merged:
            merged[root] = {field: {} for field in RECORD_SETS}
            merged[root]["fallback"] = {}

        target = merged[root]
        for field in RECORD_SETS:
            target[field].update(record[field])

        for name, value in record["fallback"].items():
            if name not in target["fallback"] or value > target["fallback"][name]:
                target["fallback"][name] = value

    return list(merged.values())


def score_records(records: list) -> list:
    """Calculates Composite Score = EPSS * CVSS for each finding."""
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

        top_cvss = max((s for s in scored if s["cvss"] is not None), key=lambda s: s["cvss"], default={})
        top_epss = max((s for s in scored if s["epss"] is not None), key=lambda s: s["epss"], default={})

        composite = round(top_cvss["cvss"] * top_epss["epss"], 5) if top_cvss and top_epss else None

        if composite is None:
            risk = record["fallback"].get("ZAP Risk")
            composite = risk * ZAP_RISK_WEIGHT if risk is not None else NO_SCORE

        results.append((composite, {
            "Scanner": list(record["scanners"]),
            "Title": list(record["titles"]),
            "Site URL": list(record["urls"]),
            "Method": list(record["methods"]),
            "Description": list(record["descriptions"]),
            "References": list(record["links"]),
            "Composite Score": composite
        }))

    return results


def merge_and_score(items: list) -> list:
    """Combines, deduplicates, and ranks raw scanner findings."""
    by_scanner: dict = {}

    for item in items:
        references = item["references"] or ""
        by_scanner.setdefault(item["scanner"], []).append({
            "scanners": {item["scanner"]: None},
            "titles": {item["title"]: None} if item["title"] else {},
            "urls": {item["url"]: None} if item["url"] else {},
            "methods": {item["method"]: None} if item["method"] else {},
            "descriptions": {item["description"]: None} if item["description"] else {},
            "links": dict.fromkeys(references.split()),
            "cves": dict.fromkeys(item["cves"]),
            "cwes": dict.fromkeys(item["cwes"]),
            "fallback": dict(item["fallback"]),
        })

    records: list = []
    for scanner, scanner_records in by_scanner.items():
        merged = merge_records(scanner_records, by_title=True)
        print(f"[+] {scanner}: {len(scanner_records)} raw, {len(merged)} unique, {len(scanner_records) - len(merged)} duplicate(s) merged", file=sys.stderr)
        records.extend(merged)

    if len(by_scanner) > 1:
        before = len(records)
        records = merge_records(records, by_title=False)
        print(f"[+] Between scanners: {before} unique, {len(records)} after merging, {before - len(records)} duplicate(s) merged", file=sys.stderr)

    scored = score_records(records)

    ranked = [(score, number, finding) for number, (score, finding) in enumerate(scored, start=1)]
    ranked.sort(key=lambda entry: (-entry[0], entry[1]))

    return [finding for _, _, finding in ranked]


def parse_nikto(reports: list) -> list:
    """Parses Nikto report structures."""
    items: list = []
    for report in reports:
        host = report.get("host") or report.get("ip") or ""
        port = report.get("port")
        base = f"{host}:{port}" if host and port else host

        for vuln in report.get("vulnerabilities") or []:
            msg = vuln.get("msg") or ""
            references = vuln.get("references") or ""

            items.append({
                "scanner": "Nikto",
                "title": SENTENCE_END.split(msg.strip(), maxsplit=1)[0],
                "url": f"{base}{vuln.get('url') or ''}",
                "method": vuln.get("method"),
                "description": msg,
                "references": references,
                "cves": CVE_EXTRACT.findall(references),
                "cwes": CWE_EXTRACT.findall(references),
                "fallback": {},
            })

    return items


def parse_zap(reports: list) -> list:
    """Parses OWASP ZAP report structures."""
    items: list = []
    for report in reports:
        scanner: str = report.get("@programName") or "ZAP"
        sites = report.get("site") or []

        for site in [sites] if isinstance(sites, dict) else sites:
            site_name = site.get("@name") or ""

            for alert in site.get("alerts") or []:
                desc = clean_html(alert.get("desc"))
                references = clean_html(alert.get("reference"))
                other = clean_html(alert.get("otherinfo"))

                cweid = str(alert.get("cweid") or "").strip()
                cwes = [f"CWE-{cweid}"] if cweid.isdecimal() and int(cweid) > 0 else []

                risk = str(alert.get("riskcode", "")).strip()
                fallback = {"ZAP Risk": int(risk)} if risk.isdecimal() else {}

                alert_cves = CVE_EXTRACT.findall(" ".join((desc, references, other)))

                for inst in alert.get("instances") or [{}]:
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
                        "references": references,
                        "cves": alert_cves + CVE_EXTRACT.findall(clean_html(inst.get("otherinfo"))),
                        "cwes": cwes,
                        "fallback": fallback,
                    })

    return items


PARSERS = [
    ("Nikto", lambda reports: any("vulnerabilities" in r for r in reports), parse_nikto),
    ("OWASP ZAP", lambda reports: any(r.get("@programName") == "ZAP" for r in reports), parse_zap),
]


def main_parse_handler(path: str) -> list:
    if Path(path).stat().st_size > MAX_REPORT_BYTES:
        raise ValueError(f"{path} is larger than {MAX_REPORT_BYTES // (1024 * 1024)} MB")

    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
    except (RecursionError, MemoryError) as err:
        raise ValueError(f"{path} could not be loaded ({type(err).__name__})") from err

    reports: list = []
    for item in data if isinstance(data, list) else [data]:
        if isinstance(item, dict):
            reports.append(item)

    if not reports:
        raise ValueError(f"No JSON objects found in {path}")

    for name, detect, parse in PARSERS:
        if detect(reports):
            print(f"[+] Detected report type: {name} ({path})! Parsing . . .", file=sys.stderr)
            try:
                return parse(reports)
            except (AttributeError, TypeError, KeyError) as err:
                raise ValueError(f"{name} report format error: {err}") from err

    supported = ", ".join(name for name, _, _ in PARSERS)
    raise ValueError(f"Unrecognised report format in {path}. Supported: {supported}.")


def main():
    args_parser = argparse.ArgumentParser(
        prog="Python Web Vulnerability Prioritiser",
        description="Parse web vulnerability scanner reports into one unified report.",
        epilog="Have fun!"
    )

    args_parser.add_argument(
        "reports",
        nargs="+",
        help="Path(s) of the Nikto and/or OWASP ZAP JSON report(s) to parse.",
        metavar="REPORT"
    )
    args_parser.add_argument(
        "-o",
        "--output",
        help=f"Output filename or path. Extension sets format ({', '.join(OUTPUTS)}). Default: {DEFAULT_OUTPUT}",
        metavar="FILENAME",
        default=DEFAULT_OUTPUT
    )

    def unrecognised(message: str) -> None:
        print(f"\n[-] Unrecognised command, type {Path(sys.argv[0]).name} -h for help.", file=sys.stderr)
        sys.exit(1)

    args_parser.error = unrecognised
    args = args_parser.parse_args()

    suffix = Path(args.output).suffix.lower()

    if suffix not in OUTPUTS:
        kind = f"'{suffix}' files" if suffix else "files with no extension"
        print(f"\n[!] No output method for {kind} ({args.output}). Supported extensions: {', '.join(OUTPUTS)}.", file=sys.stderr)
        sys.exit(1)

    start_timer = time.perf_counter()
    print(f"\n[+] Started at {datetime.now().strftime('%a %b %e %H:%M:%S %Z %Y')} . . .", file=sys.stderr)

    all_items: list = []
    error_count: int = 0

    for report_path in args.reports:
        try:
            findings = main_parse_handler(report_path)
            all_items.extend(findings)
            print(f"[+] Parsed {len(findings)} finding(s) from {report_path}", file=sys.stderr)
        except (OSError, ValueError) as err:
            error_count += 1
            print(f"\n[-] Could not parse {report_path}: {err}", file=sys.stderr)

    if not all_items and error_count > 0:
        print("\n[!] No findings produced. Exiting . . .", file=sys.stderr)
        sys.exit(1)

    try:
        all_findings = merge_and_score(all_items)
    except (AttributeError, TypeError, KeyError) as err:
        print(f"\n[!] Could not merge findings: {err}", file=sys.stderr)
        sys.exit(1)

    try:
        saved_path = Path(args.output).expanduser().resolve()
        OUTPUTS[suffix](all_findings, saved_path)
    except OSError as err:
        print(f"\n[!] Could not write report: {err}", file=sys.stderr)
        sys.exit(1)

    print(f"\n[+] Total: {len(all_findings)} finding(s). Report written to: {saved_path} . . .", file=sys.stderr)

    if error_count > 0:
        print(f"[-] {error_count} file(s) had errors . . .", file=sys.stderr)

    print(f"\n[+] Finished at {datetime.now().strftime('%a %b %e %H:%M:%S %Z %Y')}. Elapsed: {time.perf_counter() - start_timer:.2f}s.", file=sys.stderr)


if __name__ == "__main__":
    main()