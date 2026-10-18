#!/usr/bin/env python3
"""
Parse Nikto and/or OWASP ZAP JSON reports into one deduplicated JSON report.
Every finding has the same fields, including ONE Score (0-10) and Severity.

Score: CVSS (+ EPSS + exposure) if a CVE has a CVSS score (--scores),
       otherwise (risk + CWE boost) x confidence + exposure.
"""

import argparse
import html
import json
import math
import os
import re
import sys
import time
import urllib.request
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit

DEFAULT_OUTPUT = "default-parsed-report.json"

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
BREAK_RE = re.compile(r"</p\s*>|<br\s*/?>", re.I)
TAG_RE = re.compile(r"<[^>]+>")
SENTENCE_RE = re.compile(r"(?<=[.!?])\s+")
NIKTO_PATH_RE = re.compile(r"^\s*/[^\s:]*:\s+")

# Nikto has no severity, so guess it from the message. Treat as rough.
NIKTO_HIGH = re.compile(
    r"sql injection|remote code|command execution|shellshock|remote file inclusion|"
    r"arbitrary (file|code)|backdoor|default (password|credential|account)|"
    r"authentication bypass", re.I)
NIKTO_MEDIUM = re.compile(
    r"cross.site scripting|\bxss\b|directory (indexing|listing)|backup|\.bak\b|"
    r"phpinfo|traversal|admin|password|config|outdated|vulnerable|database|"
    r"\.git\b|\.svn\b|\.env\b", re.I)

BASE_SCORE = {0: 0.0, 1: 2.5, 2: 5.0, 3: 8.0}
CONFIDENCE = {0: 0.0, 1: 0.6, 2: 0.8, 3: 1.0, 4: 1.0}
NIKTO_CONFIDENCE = 0.7
CWE_HIGH = {"20", "22", "77", "78", "79", "89", "94", "98", "113", "287", "306",
            "352", "434", "502", "611", "798", "862", "863", "918"}
CWE_MEDIUM = {"200", "256", "259", "311", "312", "319", "326", "327", "523",
              "614", "1004", "1275"}


# ---------- helpers ----------

def clean_html(value) -> str:
    return html.unescape(TAG_RE.sub("", BREAK_RE.sub("\n", str(value or "")))).strip()


def find_cves(*texts) -> list:
    return list(dict.fromkeys(c.upper() for t in texts for c in CVE_RE.findall(str(t or ""))))


def fingerprint(text: str) -> str:
    """Title reduced to its fixed wording (no URLs, numbers, punctuation)."""
    text = re.sub(r"https?://\S+", "", text.lower())
    return re.sub(r"[^a-z#]+", " ", re.sub(r"0x[0-9a-f]+|\d+", "#", text)).strip()


def normalise_url(url: str) -> str:
    """Lowercase host, localhost -> 127.0.0.1, drop default port and trailing slash."""
    p = urlsplit(url.strip())
    scheme, host = p.scheme.lower(), (p.hostname or "").lower()
    host = "127.0.0.1" if host == "localhost" else host
    port = f":{p.port}" if p.port and p.port != {"http": 80, "https": 443}.get(scheme) else ""
    query = urlencode(sorted(parse_qsl(p.query, keep_blank_values=True)))
    return f"{scheme}://{host}{port}{p.path.rstrip('/') or '/'}" + (f"?{query}" if query else "")


def netloc(url: str) -> str:
    return urlsplit(normalise_url(url)).netloc if url else ""


# ---------- parsing: one record per instance ----------

def record(scanner, title, url, method, desc, refs, solution, risk, confidence, cwe, key):
    return {"scanner": scanner, "title": title, "url": url, "method": (method or "").upper(),
            "description": desc, "references": refs, "solution": solution,
            "cves": find_cves(desc, refs), "risk": risk, "confidence": confidence,
            "cwe": str(cwe or ""), "key": key}


def parse_nikto(report: dict):
    host = report.get("host") or report.get("ip") or ""
    port = str(report.get("port") or "")
    secure = report.get("ssl") in (True, "true", "True", "1", 1) or port == "443"
    base = f"{'https' if secure else 'http'}://{host}" + (f":{port}" if port else "")

    for vuln in report.get("vulnerabilities") or []:
        msg = str(vuln.get("msg") or "").strip()
        path = str(vuln.get("url") or "")
        path = path if not path or path.startswith("/") else "/" + path
        refs = vuln.get("references") or ""
        refs = "\n".join(map(str, refs)) if isinstance(refs, list) else refs
        title = SENTENCE_RE.split(NIKTO_PATH_RE.sub("", msg), maxsplit=1)[0] or msg or "Untitled"
        risk = 3 if NIKTO_HIGH.search(msg) else 2 if NIKTO_MEDIUM.search(msg) else 1
        url = base + path
        yield record("Nikto", title, url, vuln.get("method"), msg, refs, "", risk, None, "",
                     ("Nikto", str(vuln.get("id") or ""), fingerprint(title.split(",")[0]),
                      netloc(url)))


def parse_zap(report: dict):
    sites = report.get("site") or []
    for site in [sites] if isinstance(sites, dict) else sites:
        name = site.get("@name") or ""
        for alert in site.get("alerts") or []:
            desc, refs = clean_html(alert.get("desc")), clean_html(alert.get("reference"))
            title = alert.get("alert") or alert.get("name") or "Untitled"
            alert_key = alert.get("alertRef") or alert.get("pluginid") or fingerprint(title)
            for inst in alert.get("instances") or [{}]:
                uri = inst.get("uri") or ""
                url = uri if urlsplit(uri).scheme in ("http", "https") or not name \
                    else urljoin(name.rstrip("/") + "/", uri.lstrip("/"))
                yield record("ZAP", title, url, inst.get("method"), desc, refs,
                             clean_html(alert.get("solution")),
                             int(alert.get("riskcode") or 0), int(alert.get("confidence") or 0),
                             alert.get("cweid"), ("ZAP", str(alert_key), netloc(url or name)))


def parse_file(path: str) -> list:
    with open(Path(path).expanduser(), encoding="utf-8-sig") as handle:
        data = json.load(handle)
    records = []
    for report in data if isinstance(data, list) else [data]:
        if not isinstance(report, dict):
            continue
        if "vulnerabilities" in report:
            records.extend(parse_nikto(report))
        elif report.get("@programName") == "ZAP" and "site" in report:
            records.extend(parse_zap(report))
    if not records:
        raise ValueError("no Nikto or ZAP findings recognised")
    return records


# ---------- deduplication ----------

def group(records: list) -> list:
    """Merge records with the same key into one group, keeping the worst instance."""
    groups = {}
    for rec in records:
        grp = groups.setdefault(rec["key"], {"best": rec, "urls": {}, "methods": [], "cves": []})
        if rec["url"]:
            grp["urls"].setdefault(normalise_url(rec["url"]), rec["url"])
        for value, bucket in ((rec["method"], "methods"), *((c, "cves") for c in rec["cves"])):
            if value and value not in grp[bucket]:
                grp[bucket].append(value)
        if (rec["risk"], rec["confidence"] or 0) > (grp["best"]["risk"], grp["best"]["confidence"] or 0):
            grp["best"] = rec
    return list(groups.values())


# ---------- CVSS / EPSS (optional) ----------

def get_json(url: str, headers: dict = None):
    request = urllib.request.Request(url, headers={"User-Agent": "ScanParser", **(headers or {})})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode())


def lookup_cve(cve: str, api_key: str = None) -> tuple:
    """Return (cvss base score, epss percentile); None where unavailable."""
    cvss = epss = None
    try:
        rows = get_json(f"https://api.first.org/data/v1/epss?cve={cve}").get("data") or []
        epss = float(rows[0]["percentile"]) if rows else None
    except Exception as err:
        print(f"[!] EPSS lookup failed for {cve}: {err}", file=sys.stderr)
    try:
        data = get_json(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}",
                        {"apiKey": api_key} if api_key else {})
        metrics = (data.get("vulnerabilities") or [{}])[0].get("cve", {}).get("metrics", {})
        for name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(name):
                cvss = metrics[name][0]["cvssData"]["baseScore"]
                break
    except Exception as err:
        print(f"[!] NVD lookup failed for {cve}: {err}", file=sys.stderr)
    return cvss, epss


def lookup_all(cves, api_key: str = None) -> dict:
    results = {}
    for index, cve in enumerate(sorted(cves)):
        if index:
            time.sleep(0.7 if api_key else 6.1)   # NVD rate limits
        results[cve] = lookup_cve(cve, api_key)
    return results


# ---------- scoring ----------

def score(grp: dict, cve_data: dict) -> float:
    best = grp["best"]
    exposure = min(1.0, 0.5 * math.log10(max(len(grp["urls"]), 1)))   # more pages = higher

    known = [cve_data[c] for c in grp["cves"] if cve_data.get(c, (None, None))[0] is not None]
    if known:
        cvss = max(k[0] for k in known)
        percentile = max(k[1] or 0.0 for k in known)
        return round(min(10.0, cvss + 1.5 * percentile + exposure), 1)

    if best["risk"] == 0:
        return 0.0
    boost = 1.5 if best["cwe"] in CWE_HIGH else 0.5 if best["cwe"] in CWE_MEDIUM else 0.0
    multiplier = NIKTO_CONFIDENCE if best["confidence"] is None else CONFIDENCE.get(best["confidence"], 1.0)
    return round(min(10.0, (BASE_SCORE[min(best["risk"], 3)] + boost) * multiplier + exposure), 1)


def severity(value: float) -> str:
    """CVSS v3 qualitative bands."""
    return ("None" if value <= 0 else "Low" if value < 4 else "Medium" if value < 7
            else "High" if value < 9 else "Critical")


def build_findings(groups: list, cve_data: dict) -> list:
    findings = []
    for grp in groups:
        best, value = grp["best"], score(grp, cve_data)
        findings.append({
            "Scanner": best["scanner"],
            "Title": best["title"],
            "Site URL": ", ".join(sorted(grp["urls"].values())) or None,
            "Method": ", ".join(grp["methods"]) or None,
            "Description": best["description"] or None,
            "References": best["references"] or None,
            "CVE": ", ".join(grp["cves"]) or None,
            "Solution": best["solution"] or None,
            "Score": value,
            "Severity": severity(value),
        })
    return sorted(findings, key=lambda f: f["Score"], reverse=True)


# ---------- main ----------

def main() -> int:
    cli = argparse.ArgumentParser(description="Parse Nikto / OWASP ZAP JSON reports into one "
                                              "deduplicated, scored JSON report.")
    cli.add_argument("reports", nargs="+", metavar="REPORT", help="Nikto and/or ZAP JSON report(s)")
    cli.add_argument("-o", "--output", default=DEFAULT_OUTPUT, help=f"output file (default: {DEFAULT_OUTPUT})")
    cli.add_argument("--scores", action="store_true", help="look up CVSS (NVD) and EPSS (FIRST) for CVEs")
    cli.add_argument("--nvd-api-key", default=os.environ.get("NVD_API_KEY"),
                     help="NVD API key (or set NVD_API_KEY); much faster lookups")
    args = cli.parse_args()

    records = []
    for path in args.reports:
        try:
            found = parse_file(path)
            records.extend(found)
            print(f"[+] {path}: {len(found)} instance(s)", file=sys.stderr)
        except (OSError, ValueError) as err:   # JSONDecodeError is a ValueError
            print(f"[-] {path}: {err}", file=sys.stderr)
    if not records:
        print("[-] No findings produced.", file=sys.stderr)
        return 1

    groups = group(records)
    print(f"[+] {len(records)} instance(s) -> {len(groups)} finding(s)", file=sys.stderr)

    cve_data = {}
    if args.scores:
        cves = {c for g in groups for c in g["cves"]}
        if cves:
            print(f"[*] Looking up {len(cves)} CVE(s)...", file=sys.stderr)
            cve_data = lookup_all(cves, args.nvd_api_key)

    out = Path(args.output).expanduser().resolve()
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(build_findings(groups, cve_data), indent=3, ensure_ascii=False),
                       encoding="utf-8")
    except OSError as err:
        print(f"[-] Could not write report: {err}", file=sys.stderr)
        return 1
    print(f"[+] Report written to {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())