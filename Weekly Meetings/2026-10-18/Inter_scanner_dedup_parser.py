#!/usr/bin/env python3
"""
Merge parsed Nikto and ZAP reports (the JSON files written by the parser) into ONE
deduplicated report.

Findings are merged when they describe the same problem on the same host:
  1. Same issue family (see FAMILIES below), within one scanner or between scanners.
     Example: Nikto's eight "directory listing" tests, or ZAP's and Nikto's "CSP header missing".
  2. Otherwise, the same title wording.
Anything not recognised as the same issue is left alone, so nothing is hidden by over-merging.

A merged finding keeps every URL, method, reference and CVE, and "Merged From" lists the originals.

Usage:
  python merge_reports.py nikto-parsed.json zap-parsed.json -o merged-report.json
"""

import argparse
import json
import math
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

DEFAULT_OUTPUT = "merged-report.json"

# One entry per underlying problem: (title for the merged finding, regex on the lower-case title).
# This is the only place that decides what counts as "the same issue", so add a line to teach it more.
FAMILIES = [
    ("Content Security Policy (CSP) header not set",
     re.compile(r"^content security policy \(csp\) header not set|header missing: content-security-policy")),
    ("X-Content-Type-Options header missing",
     re.compile(r"x-content-type-options header (is )?(missing|not set)|header missing: x-content-type-options")),
    ("Anti-clickjacking header missing",
     re.compile(r"anti-clickjacking header|x-frame-options header (is )?(not present|missing|not set)")),
    ("X-Powered-By header discloses technology", re.compile(r"x-powered-by")),
    ("Directory listing enabled",
     re.compile(r"director(y|ies) (index|listing|browsing)|allows indexing")),
    ("Internal IP address disclosed in Location header",
     re.compile(r"rfc-1918|internal or real ip|private ip")),
]

# Nikto has no severity, so a finding that arrives without a score is rated from its wording (rough).
NIKTO_INFO = re.compile(r"allowed http methods|might be interesting", re.I)
NIKTO_HIGH = re.compile(
    r"sql injection|remote code|command execution|shellshock|remote file inclusion|"
    r"arbitrary (file|code)|backdoor|default (password|credential|account)|"
    r"authentication bypass", re.I)
NIKTO_MEDIUM = re.compile(
    r"cross.site scripting|\bxss\b|directory (indexing|listing)|backup|\.bak\b|"
    r"phpinfo|traversal|admin|password|config|outdated|vulnerable|database|"
    r"\.git\b|\.svn\b|\.env\b", re.I)
BASE_SCORE = {1: 2.5, 2: 5.0, 3: 8.0}
NIKTO_CONFIDENCE = 0.7


# helpers

def split_list(value) -> list:
    return [part.strip() for part in str(value or "").split(",") if part.strip()]


def unique(values) -> list:
    return list(dict.fromkeys(v for v in values if v))


def fingerprint(text: str) -> str:
    """Title reduced to its fixed wording (no URLs, numbers, punctuation)."""
    text = re.sub(r"https?://\S+", "", text.lower())
    return re.sub(r"[^a-z#]+", " ", re.sub(r"\d+", "#", text)).strip()


def host_port(url: str) -> tuple:
    """(host, port) of a URL with or without a scheme; localhost counts as 127.0.0.1."""
    parts = urlsplit(url if "//" in url else "//" + url)
    host = (parts.hostname or "").lower()
    try:
        port = parts.port
    except ValueError:
        port = None
    return ("127.0.0.1" if host == "localhost" else host), port


def family_of(title: str):
    lowered = title.lower()
    return next((name for name, pattern in FAMILIES if pattern.search(lowered)), None)


def severity(score) -> str:
    if score is None:
        return None
    return ("Informational" if score <= 0 else "Low" if score < 4 else "Medium" if score < 7
            else "High" if score < 9 else "Critical")


def nikto_score(title: str, description: str, url_count: int) -> float:
    text = f"{title} {description}"
    if NIKTO_INFO.search(text):
        return 0.0
    risk = 3 if NIKTO_HIGH.search(text) else 2 if NIKTO_MEDIUM.search(text) else 1
    exposure = min(1.0, 0.5 * math.log10(max(url_count, 1)))
    return round(min(10.0, BASE_SCORE[risk] * NIKTO_CONFIDENCE + exposure), 1)


# loading 

def load_members(path: str) -> list:
    """One member per finding in a parsed report (either parser output format works)."""
    with open(Path(path).expanduser(), encoding="utf-8-sig") as handle:
        data = json.load(handle)

    members = []
    for item in data if isinstance(data, list) else [data]:
        if not isinstance(item, dict) or not item.get("Title"):
            continue

        scanners = split_list(item.get("Scanner")) or ["Unknown"]
        if item.get("Instances"):   # the longer format with URL/method pairs
            urls = [i["url"] for i in item["Instances"] if i.get("url")]
            methods = [i["method"] for i in item["Instances"] if i.get("method")]
        else:
            urls, methods = split_list(item.get("Site URL")), split_list(item.get("Method"))

        title, description = str(item["Title"]), str(item.get("Description") or "")
        score = item.get("Score", item.get("Priority Score"))
        source = "parsed report"
        if score is None and "Nikto" in scanners:
            score, source = nikto_score(title, description, len(set(urls))), "Nikto heuristic"

        members.append({
            "scanners": scanners, "title": title, "urls": urls, "methods": methods,
            "description": description, "references": str(item.get("References") or "").split(),
            "cves": split_list(item.get("CVE")), "solution": item.get("Solution"),
            "score": score, "score_source": source, "family": family_of(title),
        })
    if not members:
        raise ValueError("no findings found")
    return members


#  merging 

def merge_group(members: list) -> dict:
    # Best member first: highest score, then the fullest description
    members = sorted(members, key=lambda m: (-(m["score"] if m["score"] is not None else -1), -len(m["description"])))
    best = members[0]
    merged = len(members) > 1
    scores = [m["score"] for m in members if m["score"] is not None]
    score = max(scores) if scores else None

    return {
        "Scanner": ", ".join(sorted(unique(s for m in members for s in m["scanners"]))),
        "Title": best["family"] if merged and best["family"] else best["title"],
        "Site URL": ", ".join(unique(u for m in members for u in m["urls"])) or None,
        "Method": ", ".join(unique(x for m in members for x in m["methods"])) or None,
        "Description": best["description"] or None,
        "References": "\n".join(unique(r for m in members for r in m["references"])) or None,
        "CVE": ", ".join(unique(c for m in members for c in m["cves"])) or None,
        "Solution": next((m["solution"] for m in members if m["solution"]), None),
        "Score": score,
        "Severity": severity(score),
        "Score Source": next((m["score_source"] for m in members if m["score"] == score), None),
        "Merged From": [f"{'/'.join(m['scanners'])}: {m['title']}" for m in members] if merged else [],
    }


def merge(members: list, match_port: bool) -> list:
    groups: dict = {}
    for member in members:
        host, port = host_port(member["urls"][0]) if member["urls"] else ("", None)
        name = member["family"] or "title: " + fingerprint(member["title"])
        groups.setdefault((name, host, port if match_port else None), []).append(member)

    findings = []
    for (name, host, _), group in groups.items():
        finding = merge_group(group)
        if len(group) > 1:
            scanners = " + ".join(sorted(unique(s for m in group for s in m["scanners"])))
            print(f"[+] merged {len(group)} finding(s) ({scanners}) -> {finding['Title']!r}", file=sys.stderr)
            ports = {host_port(u)[1] for m in group for u in m["urls"]}
            if len(ports) > 1:
                print(f"[!]   that spans ports {sorted(p for p in ports if p)}: are these the same server?",
                      file=sys.stderr)
        findings.append(finding)

    findings.sort(key=lambda f: (-(f["Score"] if f["Score"] is not None else -1), f["Title"]))
    return findings


#  main 

def main() -> int:
    cli = argparse.ArgumentParser(description="Merge parsed Nikto / ZAP reports into one deduplicated report.")
    cli.add_argument("reports", nargs="+", metavar="REPORT", help="parsed Nikto and/or ZAP JSON report(s)")
    cli.add_argument("-o", "--output", default=DEFAULT_OUTPUT, help=f"output file (default: {DEFAULT_OUTPUT})")
    cli.add_argument("--match-port", action="store_true",
                     help="only merge findings from the same host AND port (default: same host)")
    cli.add_argument("--skip-info", action="store_true", help="leave out informational findings (score 0)")
    args = cli.parse_args()

    members = []
    for path in args.reports:
        try:
            found = load_members(path)
            members.extend(found)
            print(f"[+] {path}: {len(found)} finding(s)", file=sys.stderr)
        except (OSError, ValueError) as err:   # JSONDecodeError is a ValueError
            print(f"[-] {path}: {err}", file=sys.stderr)
    if not members:
        print("[-] Nothing to merge.", file=sys.stderr)
        return 1

    findings = merge(members, args.match_port)
    if args.skip_info:
        findings = [f for f in findings if f["Severity"] != "Informational"]

    cross = sum(len(f["Scanner"].split(", ")) > 1 for f in findings)
    print(f"[+] {len(members)} finding(s) -> {len(findings)} after merging ({cross} found by more than one scanner)",
          file=sys.stderr)

    out = Path(args.output).expanduser().resolve()
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(findings, indent=3, ensure_ascii=False), encoding="utf-8")
    except OSError as err:
        print(f"[-] Could not write report: {err}", file=sys.stderr)
        return 1
    print(f"[+] Report written to {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())