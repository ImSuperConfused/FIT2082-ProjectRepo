
"""
OWASP ZAP Vulnerability Report Parser

Usage:
    python3 unified_vuln_parser.py zap_report.json
    python3 unified_vuln_parser.py zap_report.json -o zap_parsed.json
    python3 unified_vuln_parser.py zap_chrome.json zap_firefox.json -o zap_parsed.json

Supported scanner:
    - OWASP ZAP JSON reports

Output:
    A JSON list of findings using a consistent schema.
    Each ZAP alert instance is preserved as a separate record.

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
from urllib.parse import urljoin, urlsplit


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

def parse_zap(reports: list) -> list:
    """
    Parse OWASP ZAP JSON reports.

    Each alert instance becomes a separate finding. Alert metadata and
    instance evidence are preserved for deduplication and scoring.
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
                        )
                    )

    return results


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
        return parse_zap(reports)
    except (AttributeError, TypeError, KeyError) as error:
        raise ValueError(
            f"Invalid ZAP report structure in {path}: {error}"
        ) from error


# Command-line interface- Added by Chat GPT for improvement 

def main():
    args_parser = argparse.ArgumentParser(
        description=(
            "Parse OWASP ZAP JSON reports into a unified finding format."
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

    args = args_parser.parse_args()
    start_timer = time.perf_counter()

    print(
        f"[+] Started at {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}",
        file=sys.stderr,
    )

    all_findings = []
    errors = []

    for report_path in args.reports:
        try:
            parsed_findings = parser(report_path)
            all_findings.extend(parsed_findings)

            print(
                f"[+] Parsed {len(parsed_findings)} finding(s) "
                f"from {report_path}",
                file=sys.stderr,
            )

        except (OSError, ValueError, json.JSONDecodeError) as error:
            message = f"Could not parse {report_path}: {error}"
            print(f"[-] {message}", file=sys.stderr)
            errors.append(message)

    if errors and not all_findings:
        print(
            "[-] No findings produced. Check the input report(s).",
            file=sys.stderr,
        )
        return 1

    try:
        saved_path = output(all_findings, args.output)
    except OSError as error:
        print(
            f"[-] Could not write output file: {error}",
            file=sys.stderr,
        )
        return 1

    print(
        f"[+] Total findings: {len(all_findings)}",
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
