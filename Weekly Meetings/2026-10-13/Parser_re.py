"""
OWASP ZAP Vulnerability Report Parser (with within-ZAP deduplication)

Usage:
    python3 unified_vuln_parser.py zap_report.json
    python3 unified_vuln_parser.py zap_report.json -o zap_parsed.json
    python3 unified_vuln_parser.py zap_chrome.json zap_firefox.json -o zap_parsed.json
    python3 unified_vuln_parser.py zap_chrome.json zap_firefox.json --raw-output zap_raw.json
    python3 unified_vuln_parser.py zap_report.json --no-dedup

Supported scanner:
    - OWASP ZAP JSON reports

Pipeline:
    1. Parse: every ZAP alert instance becomes a separate record, tagged
       with the report file it came from (Source_Report).
    2. Deduplicate within ZAP: records describing the same issue (same
       alert, URL, method and parameter) are collapsed into one, across
       all reports given (e.g. Chrome run + Firefox run).
    3. Score: each finding gets a Score from 0 to 10 (see calculate_score).
    4. Output: deduplicated findings (and optionally the raw findings so
       the duplication step can be reviewed).

Output:
    A JSON list of findings using a consistent schema. Deduplicated
    records also carry:
        Duplicate_Count - how many raw records were merged into this one
        Sources         - list of report files the issue was seen in
        Instance_IDs    - ZAP instance IDs that were merged
        Score           - 0-10, from ZAP risk and confidence (all findings)
        All_Evidence / All_Attacks / All_Other_Info
                        - every distinct value seen across the duplicates

The later ZAP vs Nikto (cross-scanner) deduplication can match on the
normalised "Site URL", "Method" and "Title"/CWE of these records.

Caution: Chat GPT used to help improve the previous ZAP parser.py
"""

import argparse
import html
import json
import re
import sys
import time

from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit


DEFAULT_OUTPUT = "default-parsed-report.json"

SENTENCE_END = re.compile(r"(?<=[.!?])\s+")
HTML_BREAKS = re.compile(r"</p\s*>|<br\s*/?>", re.IGNORECASE)
HTML_TAGS = re.compile(r"<[^>]+>")


# Outputs generated:

def output(findings: list, output_filename: str = DEFAULT_OUTPUT) -> Path:
    """Write parsed findings to a JSON file."""
    output_path = Path(output_filename).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as output_file:
        json.dump(findings, output_file, indent=4, ensure_ascii=False)

    return output_path


def finding(
    scanner: str,
    site_url: str,
    title: str,
    method: str,
    description: str,
    references: str,
    **extra,
) -> dict:
    """Create a finding using the shared output schema."""
    result = {
        "Scanner": scanner or None,
        "Site URL": site_url or None,
        "Title": title or None,
        "Method": method or None,
        "Description": description or None,
        "References": references or None,
    }

    for key, value in extra.items():
        result[key] = value if value != "" else None

    return result


# Helper functions

def clean_html(value) -> str:
    """Convert HTML-formatted text to plain text."""
    if value is None:
        return ""

    text = str(value)
    text = HTML_BREAKS.sub("\n", text)
    text = HTML_TAGS.sub("", text)
    text = html.unescape(text)

    return text.strip()


def first_sentence(value: str):
    """Return the first sentence of a string."""
    if not value or not value.strip():
        return None

    return SENTENCE_END.split(value.strip(), maxsplit=1)[0]


def normalise_risk_code(value):
    """Convert a ZAP risk code to an integer when possible."""
    if value is None:
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return value


def risk_value(value) -> int:
    """Return a risk code as an int for comparison (0 if unknown)."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


# Scoring

MAX_RISK = 3        # ZAP risk codes: 0 info, 1 low, 2 medium, 3 high
MAX_CONFIDENCE = 3  # ZAP confidence: 0 false positive, 1 low, 2 medium, 3 high


def calculate_score(item: dict) -> float:
    """
    Score a finding from 0 to 10.

    Score = (risk / 3) * (confidence / 3) * 10

    So a High-risk, High-confidence finding scores 10.0, a Medium-risk,
    Medium-confidence one scores about 4.4, and Informational findings
    score 0. Confidence 4 (user confirmed) is treated as High and
    confidence 0 (false positive) scores 0. Change the formula here if
    the team agrees on a different one.
    """
    risk = min(max(risk_value(item.get("Risk_Code")), 0), MAX_RISK)

    try:
        confidence = int(item.get("Confidence"))
    except (TypeError, ValueError):
        confidence = 0
    confidence = min(max(confidence, 0), MAX_CONFIDENCE)

    return round((risk / MAX_RISK) * (confidence / MAX_CONFIDENCE) * 10, 1)


def add_scores(findings: list) -> list:
    """Add a Score to every finding."""
    for item in findings:
        item["Score"] = calculate_score(item)

    return findings


def build_site_url(site_name: str, uri: str) -> str:
    """
    Build an absolute URL from the ZAP site name and instance URI.

    Absolute instance URLs are preserved. Relative URLs are resolved
    against the site URL.
    """
    if not uri:
        return site_name or ""

    if urlsplit(uri).scheme in ("http", "https"):
        return uri

    if site_name:
        return urljoin(site_name.rstrip("/") + "/", uri.lstrip("/"))

    return uri


# OWASP ZAP parser- Improved to fit this parser by Chat GPT

def parse_zap(reports: list, source: str = None) -> list:
    """
    Parse OWASP ZAP JSON reports.

    Each alert instance becomes a separate finding. Alert metadata and
    instance evidence are preserved for deduplication and scoring.
    `source` labels which report file the findings came from.
    """
    results = []

    for report in reports:
        scanner = report.get("@programName") or "OWASP ZAP"
        sites = report.get("site") or []

        # Handle a single site represented as a dictionary.
        if isinstance(sites, dict):
            sites = [sites]

        if not isinstance(sites, list):
            continue

        for site in sites:
            if not isinstance(site, dict):
                continue

            site_name = site.get("@name") or ""
            alerts = site.get("alerts") or []

            if not isinstance(alerts, list):
                continue

            for alert in alerts:
                if not isinstance(alert, dict):
                    continue

                description = clean_html(alert.get("desc"))
                references = clean_html(alert.get("reference"))

                instances = alert.get("instances") or [{}]

                if not isinstance(instances, list):
                    continue

                for instance in instances:
                    if not isinstance(instance, dict):
                        continue

                    uri = instance.get("uri") or ""
                    site_url = build_site_url(site_name, uri)

                    results.append(
                        finding(
                            scanner=scanner,
                            site_url=site_url,
                            title=alert.get("alert") or alert.get("name"),
                            method=instance.get("method"),
                            description=description,
                            references=references,

                            # Alert-level metadata.
                            Alert_ID=alert.get("pluginid"),
                            Alert_Ref=alert.get("alertRef"),
                            Risk=alert.get("riskdesc"),
                            Risk_Code=normalise_risk_code(
                                alert.get("riskcode")
                            ),
                            Confidence=alert.get("confidence"),
                            CWE=alert.get("cweid"),
                            WASC=alert.get("wascid"),
                            Systemic=alert.get("systemic"),

                            # Instance-level evidence.
                            Instance_ID=instance.get("id"),
                            Parameter=instance.get("param"),
                            Evidence=instance.get("evidence"),
                            Attack=instance.get("attack"),
                            Other_Info=instance.get("otherinfo"),

                            # Provenance (which report file this came from).
                            Source_Report=source,
                        )
                    )

    return results


# Deduplication within ZAP

def normalise_url(url: str) -> str:
    """
    Normalise a URL so equivalent forms compare equal.

    - lowercase scheme and host; map localhost to 127.0.0.1
    - drop default ports (80 for http, 443 for https)
    - drop fragment and trailing slash
    - sort query parameters (values are left untouched)
    """
    if not url:
        return ""

    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()

    if host == "localhost":
        host = "127.0.0.1"
    if ":" in host:  # IPv6 literal
        host = f"[{host}]"

    port = parts.port
    if port and (scheme, port) not in (("http", 80), ("https", 443)):
        host = f"{host}:{port}"

    path = parts.path.rstrip("/") or "/"

    pairs = sorted(parse_qsl(parts.query, keep_blank_values=True))
    query = f"?{urlencode(pairs)}" if pairs else ""

    return f"{scheme}://{host}{path}{query}"


# Fields whose distinct values are all kept when duplicates are merged.
MERGED_FIELDS = {
    "Evidence": "All_Evidence",
    "Attack": "All_Attacks",
    "Other_Info": "All_Other_Info",
}


def _listed(value) -> list:
    """Return [value] if it is set, else an empty list."""
    return [value] if value else []


def dedup_key(item: dict) -> tuple:
    """
    Define what makes two ZAP findings the same issue.

    Same alert + same normalised URL + same HTTP method + same parameter.
    Instance_ID is excluded (unique per instance). Evidence and Attack are
    excluded so different payloads against one parameter collapse into one
    finding, but their distinct values are all kept on the merged record
    (All_Evidence, All_Attacks, All_Other_Info). Add them here instead if
    the team wants them treated as separate findings.
    """
    return (
        item.get("Alert_Ref") or item.get("Alert_ID") or item.get("Title"),
        normalise_url(item.get("Site URL")),
        (item.get("Method") or "").upper(),
        item.get("Parameter") or "",
    )


def deduplicate_zap(findings: list) -> list:
    """Collapse duplicate findings within ZAP, keeping provenance."""
    seen = {}

    for item in findings:
        key = dedup_key(item)
        source = item.get("Source_Report")

        if key not in seen:
            record = dict(item)
            record.pop("Source_Report", None)
            record["Duplicate_Count"] = 1
            record["Sources"] = [source] if source else []
            record["Instance_IDs"] = _listed(item.get("Instance_ID"))

            # Keep every distinct value so no evidence is lost on merge.
            for field, merged in MERGED_FIELDS.items():
                record[merged] = _listed(item.get(field))

            seen[key] = record
            continue

        kept = seen[key]
        kept["Duplicate_Count"] += 1

        if source and source not in kept["Sources"]:
            kept["Sources"].append(source)

        instance_id = item.get("Instance_ID")
        if instance_id and instance_id not in kept["Instance_IDs"]:
            kept["Instance_IDs"].append(instance_id)

        # Keep the most severe version if risk differs.
        if risk_value(item.get("Risk_Code")) > risk_value(kept.get("Risk_Code")):
            for field in ("Risk", "Risk_Code", "Confidence"):
                kept[field] = item.get(field)

        # Collect distinct evidence / payloads / notes from every duplicate.
        for field, merged in MERGED_FIELDS.items():
            value = item.get(field)
            if value and value not in kept[merged]:
                kept[merged].append(value)

            # Keep the single-value field populated too.
            if not kept.get(field) and value:
                kept[field] = value

    return list(seen.values())


# Load and parse reports

def load_reports(path: str) -> list:
    """Load a ZAP JSON report containing an object or list of objects."""
    input_path = Path(path).expanduser()

    with input_path.open("r", encoding="utf-8-sig") as input_file:
        data = json.load(input_file)

    if isinstance(data, dict):
        return [data]

    if isinstance(data, list):
        if not all(isinstance(item, dict) for item in data):
            raise ValueError(
                f"Expected a JSON object or a list of objects in {path}"
            )
        return data

    raise ValueError(
        f"Expected a JSON object or list of objects in {path}"
    )


def parser(path: str) -> list:
    """Validate and parse one OWASP ZAP JSON report."""
    reports = load_reports(path)

    if not reports:
        raise ValueError(f"No JSON objects found in {path}")

    # ZAP JSON reports normally identify the program as "ZAP".
    # Accept the report if at least one object has the expected structure.
    is_zap_report = any(
        report.get("@programName") == "ZAP"
        and "site" in report
        for report in reports
    )

    if not is_zap_report:
        raise ValueError(
            f"{path} does not appear to be an OWASP ZAP JSON report."
        )

    print(
        f"[+] Detected OWASP ZAP report: {path}",
        file=sys.stderr,
    )

    try:
        return parse_zap(reports, source=Path(path).name)
    except (AttributeError, TypeError, KeyError) as error:
        raise ValueError(
            f"Invalid ZAP report structure in {path}: {error}"
        ) from error


# Command-line interface- Added by Chat GPT for improvement

def main():
    args_parser = argparse.ArgumentParser(
        description=(
            "Parse OWASP ZAP JSON reports into a unified finding format "
            "and remove duplicates within ZAP."
        )
    )

    args_parser.add_argument(
        "reports",
        nargs="+",
        metavar="REPORT",
        help="Path(s) to OWASP ZAP JSON report files.",
    )

    args_parser.add_argument(
        "-o",
        "--output",
        metavar="FILENAME",
        default=DEFAULT_OUTPUT,
        help=f"Output JSON filename (default: {DEFAULT_OUTPUT}).",
    )

    args_parser.add_argument(
        "--raw-output",
        metavar="FILENAME",
        default=None,
        help="Also save the findings before deduplication, for review.",
    )

    args_parser.add_argument(
        "--no-dedup",
        action="store_true",
        help="Skip deduplication and output every instance.",
    )

    args = args_parser.parse_args()
    start_timer = time.perf_counter()

    print(
        f"[+] Started at {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}",
        file=sys.stderr,
    )

    raw_findings = []
    errors = []

    for report_path in args.reports:
        try:
            parsed_findings = parser(report_path)
            raw_findings.extend(parsed_findings)

            print(
                f"[+] Parsed {len(parsed_findings)} finding(s) "
                f"from {report_path}",
                file=sys.stderr,
            )

        except (OSError, ValueError, json.JSONDecodeError) as error:
            message = f"Could not parse {report_path}: {error}"
            print(f"[-] {message}", file=sys.stderr)
            errors.append(message)

    if errors and not raw_findings:
        print(
            "[-] No findings produced. Check the input report(s).",
            file=sys.stderr,
        )
        return 1

    if args.no_dedup:
        final_findings = raw_findings
    else:
        final_findings = deduplicate_zap(raw_findings)
        removed = len(raw_findings) - len(final_findings)
        print(
            f"[+] Deduplication: {len(raw_findings)} -> "
            f"{len(final_findings)} finding(s) ({removed} duplicate(s) removed)",
            file=sys.stderr,
        )

    final_findings = add_scores(final_findings)

    try:
        if args.raw_output:
            raw_path = output(raw_findings, args.raw_output)
            print(f"[+] Raw findings saved to: {raw_path}", file=sys.stderr)

        saved_path = output(final_findings, args.output)
    except OSError as error:
        print(
            f"[-] Could not write output file: {error}",
            file=sys.stderr,
        )
        return 1

    print(
        f"[+] Total findings: {len(final_findings)}",
        file=sys.stderr,
    )
    print(f"[+] Output saved to: {saved_path}", file=sys.stderr)

    if errors:
        print(
            f"[!] {len(errors)} input file(s) could not be parsed.",
            file=sys.stderr,
        )

    elapsed = time.perf_counter() - start_timer

    print(
        f"[+] Finished at {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}",
        file=sys.stderr,
    )
    print(f"[+] Elapsed time: {elapsed:.2f} seconds", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())