#!/usr/bin/env python3
"""
Parse Nikto and/or OWASP ZAP JSON reports into one JSON report with NO repeated
vulnerabilities and ONE score per finding.

Scoring: "Score" (0-10), "Severity" and "Score Source" on every finding
  CVE with a CVSS score (--scores):  CVSS + EPSS bonus + exposure bonus
  otherwise (heuristic):             (risk + CWE boost) x confidence + exposure
  Real CVSS/EPSS exist per CVE only. ZAP alerts usually carry a CWE, not a CVE,
  so they get the heuristic score; "Score Source" always says which was used.
"""

import argparse
import html
import json
import math
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit

DEFAULT_OUTPUT = "default-parsed-report.json"

CVE_EXTRACT = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
SENTENCE_END = re.compile(r"(?<=[.!?])\s+")
HTML_BREAKS = re.compile(r"</p\s*>|<br\s*/?>", re.IGNORECASE)
HTML_TAGS = re.compile(r"<[^>]+>")
NIKTO_PATH_PREFIX = re.compile(r"^\s*/[^\s:]*:\s+")


#  helpers

def output(findings: list, output_filename: str = DEFAULT_OUTPUT) -> Path:
    output_path = Path(output_filename).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as output_file:
        json.dump(findings, output_file, indent=3, ensure_ascii=False)
    return output_path


def clean_html(value) -> str:
    text = HTML_BREAKS.sub("\n", str(value or ""))
    return html.unescape(HTML_TAGS.sub("", text)).strip()


def first_sentence(value: str) -> str:
    return SENTENCE_END.split((value or "").strip(), maxsplit=1)[0]


def extract_cves(*texts) -> list:
    found = []
    for text in texts:
        for cve in CVE_EXTRACT.findall(str(text or "")):
            if cve.upper() not in found:
                found.append(cve.upper())
    return found


def to_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def normalise_url(url: str) -> str:
    """Lowercase host, localhost -> 127.0.0.1, drop default ports, trailing
    slash and fragment; sort query parameters."""
    if not url:
        return ""
    parts = urlsplit(str(url).strip())
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if host == "localhost":
        host = "127.0.0.1"
    if ":" in host:
        host = f"[{host}]"
    if parts.port and (scheme, parts.port) not in (("http", 80), ("https", 443)):
        host = f"{host}:{parts.port}"
    path = parts.path.rstrip("/") or "/"
    pairs = sorted(parse_qsl(parts.query, keep_blank_values=True))
    return f"{scheme}://{host}{path}" + (f"?{urlencode(pairs)}" if pairs else "")


def netloc_of(url: str) -> str:
    normalised = normalise_url(url)
    return urlsplit(normalised).netloc if normalised else ""


def fingerprint(text: str) -> str:
    """Title reduced to its fixed wording (no URLs, numbers, punctuation)."""
    text = re.sub(r"https?://\S+", "", (text or "").lower())
    text = re.sub(r"0x[0-9a-f]+|\d+", "#", text)
    return re.sub(r"[^a-z#]+", " ", text).strip()


def add_unique(values: list, value) -> None:
    if value not in (None, "") and value not in values:
        values.append(value)


#  parsing
# Parsers return RAW records, one per instance. Grouping happens afterwards,
# across all files, so repeats are removed even between reports.

def raw_record(scanner, title, url, method, description, references, key,
               **extra) -> dict:
    record = {"scanner": scanner, "title": title, "url": url or "",
              "method": (method or "").upper(), "description": description,
              "references": references, "key": key}
    record.update(extra)
    return record


# Nikto has no severity, so risk is guessed from the message (High, then Medium,
# else Low). Treat Nikto-only scores as rough.
NIKTO_RISK = [
    (3, re.compile(r"sql injection|remote code|command execution|shellshock|"
                   r"remote file inclusion|arbitrary (file|code)|backdoor|"
                   r"default (password|credential|account)|authentication bypass",
                   re.IGNORECASE)),
    (2, re.compile(r"cross.site scripting|\bxss\b|directory (indexing|listing)|"
                   r"backup|\.bak\b|phpinfo|traversal|admin|password|config|"
                   r"outdated|vulnerable|database|\.git\b|\.svn\b|\.env\b",
                   re.IGNORECASE)),
]
RISK_NAMES = {0: "Informational", 1: "Low", 2: "Medium", 3: "High"}


def parse_nikto(reports: list, source: str) -> list:
    records = []
    for report in reports:
        host = report.get("host") or report.get("ip") or ""
        port = str(report.get("port") or "")
        secure = report.get("ssl") in (True, "true", "True", "1", 1) or port == "443"
        base = f"{'https' if secure else 'http'}://{host}{':' + port if port else ''}"

        for vuln in report.get("vulnerabilities") or []:
            msg = str(vuln.get("msg") or "").strip()
            path = str(vuln.get("url") or "")
            path = path if path.startswith("/") or not path else "/" + path
            refs = vuln.get("references") or ""
            if isinstance(refs, list):
                refs = "\n".join(str(r) for r in refs)

            # Title without the leading "/path:"; per-file detail after a comma
            # (inode numbers etc.) is ignored when comparing.
            title = first_sentence(NIKTO_PATH_PREFIX.sub("", msg)) or msg or "Untitled"
            risk = next((r for r, rx in NIKTO_RISK if rx.search(msg)), 1)
            url = f"{base}{path}" if host else path

            records.append(raw_record(
                "Nikto", title, url, vuln.get("method"), msg, refs,
                key=("Nikto", str(vuln.get("id") or ""),
                     fingerprint(title.split(",")[0]), netloc_of(url)),
                alert_id=str(vuln.get("id") or ""), risk_code=risk,
                risk=f"{RISK_NAMES[risk]} (heuristic)", confidence=None,
                cwe=None, cves=extract_cves(msg, refs), source=source,
                param="", evidence="", attack="", other_info=msg, solution=""))
    return records


def parse_zap(reports: list, source: str) -> list:
    records = []
    for report in reports:
        sites = report.get("site") or []
        sites = [sites] if isinstance(sites, dict) else sites

        for site in sites:
            site_name = site.get("@name") or ""

            for alert in site.get("alerts") or []:
                desc = clean_html(alert.get("desc"))
                refs = clean_html(alert.get("reference"))
                title = alert.get("alert") or alert.get("name") or "Untitled"
                alert_key = (alert.get("alertRef") or alert.get("pluginid")
                             or fingerprint(title))

                for inst in alert.get("instances") or [{}]:
                    uri = inst.get("uri") or ""
                    if urlsplit(uri).scheme in ("http", "https"):
                        url = uri
                    else:
                        url = urljoin(site_name.rstrip("/") + "/", uri.lstrip("/")) \
                            if site_name else uri

                    records.append(raw_record(
                        report.get("@programName") or "ZAP", title, url,
                        inst.get("method"), desc, refs,
                        key=("ZAP", str(alert_key), netloc_of(url or site_name)),
                        alert_id=alert.get("pluginid"),
                        risk_code=to_int(alert.get("riskcode"), 0),
                        risk=alert.get("riskdesc"),
                        confidence=to_int(alert.get("confidence"), 0),
                        cwe=alert.get("cweid"),
                        cves=extract_cves(desc, refs, clean_html(alert.get("otherinfo")),
                                          inst.get("otherinfo")),
                        source=source, param=inst.get("param"),
                        evidence=inst.get("evidence"), attack=inst.get("attack"),
                        other_info=inst.get("otherinfo"),
                        solution=clean_html(alert.get("solution"))))
    return records


PARSERS = [
    ("Nikto", lambda reports: any("vulnerabilities" in r for r in reports), parse_nikto),
    ("OWASP ZAP", lambda reports: any(r.get("@programName") == "ZAP" and "site" in r
                                      for r in reports), parse_zap),
]


def load_reports(path: str) -> list:
    with open(Path(path).expanduser(), "r", encoding="utf-8-sig") as handle:
        data = json.load(handle)
    return [item for item in (data if isinstance(data, list) else [data])
            if isinstance(item, dict)]


def parser(path: str) -> list:
    reports = load_reports(path)
    if not reports:
        raise ValueError(f"No JSON objects found in {path}")

    for name, detect, parse in PARSERS:
        if detect(reports):
            print(f"[+] Detected report type: {name} ({path})", file=sys.stderr)
            try:
                return parse(reports, Path(path).name)
            except (AttributeError, TypeError, KeyError) as err:
                raise ValueError(f"{name} report is not in the expected format: {err}") from err

    raise ValueError(f"Unrecognised report format in {path}. "
                     f"Supported types: {', '.join(n for n, _, _ in PARSERS)}.")


#  deduplication

def group_records(records: list, dedup: bool = True) -> list:
    """Collapse all records with the same key into ONE finding."""
    groups = {}

    for index, rec in enumerate(records):
        key = rec["key"] if dedup else (rec["key"], index)
        group = groups.get(key)

        if group is None:
            group = groups[key] = {
                "first": rec, "urls": {}, "methods": [], "params": [],
                "evidence": [], "attacks": [], "other": [], "sources": [],
                "cves": [], "count": 0,
                "best": (rec["risk_code"], rec["confidence"] or 0), "rec": rec,
            }

        group["count"] += 1
        if rec["url"]:
            group["urls"].setdefault(normalise_url(rec["url"]), rec["url"])
        add_unique(group["methods"], rec["method"])
        add_unique(group["params"], rec["param"])
        add_unique(group["evidence"], rec["evidence"])
        add_unique(group["attacks"], rec["attack"])
        add_unique(group["other"], rec["other_info"])
        add_unique(group["sources"], rec["source"])
        for cve in rec["cves"]:
            add_unique(group["cves"], cve)

        # Keep the most severe (then most confident) version of the alert.
        score_key = (rec["risk_code"], rec["confidence"] or 0)
        if score_key > group["best"]:
            group["best"], group["rec"] = score_key, rec

    findings = []
    for group in groups.values():
        first, best = group["first"], group["rec"]
        urls = sorted(group["urls"].values())
        findings.append({
            "Scanner": first["scanner"],
            "Title": first["title"],
            "Site URL": ", ".join(urls) or None,
            "Method": ", ".join(group["methods"]) or None,
            "Description": first["description"] or None,
            "References": first["references"] or None,
            "Alert ID": first["alert_id"] or None,
            "Risk": best["risk"],
            "Risk Code": best["risk_code"],
            "Confidence": best["confidence"],
            "CWE": first["cwe"],
            "CVE": ", ".join(group["cves"]) or None,
            "Solution": first["solution"] or None,
            "Parameters": group["params"],
            "Evidence": group["evidence"],
            "Attacks": group["attacks"],
            "Other Info": group["other"],
            "Affected Count": len(urls),
            "Duplicates Merged": group["count"],
            "Sources": group["sources"],
        })
    return findings


# ------------------------------------------------------------ CVSS / EPSS

EPSS_BATCH = 80
NVD_METRICS = (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"),
               ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0"))


def http_json(url: str, headers: dict = None, timeout: int = 20, retries: int = 2):
    request_headers = {"User-Agent": "MultiScannerParser"}
    request_headers.update(headers or {})
    for attempt in range(retries + 1):
        try:
            request = urllib.request.Request(url, headers=request_headers)
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as err:
            if err.code in (403, 429, 503) and attempt < retries:
                time.sleep(10 * (attempt + 1))
                continue
            raise


def fetch_cve_scores(cves, cache_file: str = None, api_key: str = None) -> dict:
    """CVSS from NVD, EPSS from FIRST. Successful lookups are cached."""
    cves = sorted(set(cves))
    cache = {}
    if cache_file and Path(cache_file).expanduser().exists():
        try:
            cache = json.loads(Path(cache_file).expanduser().read_text("utf-8"))
        except (OSError, ValueError):
            cache = {}

    blank = {"cvss": None, "cvss_version": None, "epss": None,
             "epss_percentile": None, "nvd_ok": False, "epss_ok": False}
    scores = {cve: {**blank, **cache.get(cve, {})} for cve in cves}

    need = [c for c in cves if not scores[c]["epss_ok"]]
    if need:
        print(f"[*] Fetching EPSS for {len(need)} CVE(s)...", file=sys.stderr)
    for start in range(0, len(need), EPSS_BATCH):
        batch = need[start:start + EPSS_BATCH]
        try:
            data = http_json("https://api.first.org/data/v1/epss?cve=" + ",".join(batch))
            for row in data.get("data", []):
                if row.get("cve") in scores:
                    scores[row["cve"]]["epss"] = float(row.get("epss", 0))
                    scores[row["cve"]]["epss_percentile"] = float(row.get("percentile", 0))
            for cve in batch:
                scores[cve]["epss_ok"] = True
        except Exception as err:
            print(f"[!] EPSS API error: {err}", file=sys.stderr)

    need = [c for c in cves if not scores[c]["nvd_ok"]]
    if need:
        print(f"[*] Fetching CVSS for {len(need)} CVE(s) from NVD...", file=sys.stderr)
    delay = 0.7 if api_key else 6.1   # NVD limits: 50/30s with key, 5/30s without
    for index, cve in enumerate(need):
        if index:
            time.sleep(delay)
        try:
            data = http_json(
                f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}",
                headers={"apiKey": api_key} if api_key else {}, timeout=30)
            vulns = data.get("vulnerabilities") or []
            metrics = vulns[0].get("cve", {}).get("metrics", {}) if vulns else {}
            for metric_key, version in NVD_METRICS:
                entries = metrics.get(metric_key) or []
                if entries:
                    primary = next((e for e in entries if e.get("type") == "Primary"),
                                   entries[0])
                    scores[cve]["cvss"] = primary["cvssData"]["baseScore"]
                    scores[cve]["cvss_version"] = version
                    break
            scores[cve]["nvd_ok"] = True
        except Exception as err:
            print(f"[!] NVD API error for {cve}: {err}", file=sys.stderr)

    if cache_file:
        try:
            Path(cache_file).expanduser().write_text(json.dumps(scores, indent=2), "utf-8")
        except OSError as err:
            print(f"[!] Could not write cache: {err}", file=sys.stderr)
    return scores


def apply_cve_scores(findings: list, scores: dict) -> None:
    for item in findings:
        cvss = epss = None
        for cve in (item.get("CVE") or "").split(", "):
            data = scores.get(cve) or {}
            if data.get("cvss") is not None and (cvss is None or data["cvss"] > cvss["cvss"]):
                cvss = data
            if data.get("epss") is not None and (epss is None or data["epss"] > epss["epss"]):
                epss = data
        item["CVSS"] = cvss["cvss"] if cvss else None
        item["CVSS Version"] = cvss["cvss_version"] if cvss else None
        item["EPSS"] = epss["epss"] if epss else None
        item["EPSS Percentile"] = epss["epss_percentile"] if epss else None


#  scoring

BASE_SCORE = {0: 0.0, 1: 2.5, 2: 5.0, 3: 8.0}               # ZAP risk -> base
CONFIDENCE_MULT = {0: 0.0, 1: 0.6, 2: 0.8, 3: 1.0, 4: 1.0}  # ZAP confidence
NIKTO_CONFIDENCE = 0.7                                       # noisy signatures
CWE_BOOST_HIGH = {"20", "22", "77", "78", "79", "89", "94", "98", "113", "287",
                  "306", "352", "434", "502", "611", "798", "862", "863", "918"}
CWE_BOOST_MEDIUM = {"200", "256", "259", "311", "312", "319", "326", "327",
                    "523", "614", "1004", "1275"}


def severity_label(score: float) -> str:
    """CVSS v3 qualitative bands."""
    if score <= 0:
        return "None"
    return ("Low" if score < 4 else "Medium" if score < 7
            else "High" if score < 9 else "Critical")


def calculate_score(item: dict) -> tuple:
    """Return (score 0-10, source label)."""
    affected = max(to_int(item.get("Affected Count"), 1), 1)
    exposure = min(1.0, 0.5 * math.log10(affected))   # more pages = higher
    cvss = item.get("CVSS")

    if cvss is not None:
        epss_bonus = 1.5 * (item.get("EPSS Percentile") or 0.0)
        source = "CVSS+EPSS" if item.get("EPSS") is not None else "CVSS"
        return round(min(10.0, float(cvss) + epss_bonus + exposure), 1), source

    risk = min(max(to_int(item.get("Risk Code")), 0), 3)
    if risk == 0:
        return 0.0, "heuristic"

    cwe = str(item.get("CWE") or "")
    boost = 1.5 if cwe in CWE_BOOST_HIGH else 0.5 if cwe in CWE_BOOST_MEDIUM else 0.0
    if item.get("Confidence") is None:               # Nikto
        multiplier, source = NIKTO_CONFIDENCE, "Nikto heuristic"
    else:
        multiplier = CONFIDENCE_MULT[min(max(to_int(item["Confidence"]), 0), 4)]
        source = "ZAP heuristic"

    return round(min(10.0, (BASE_SCORE[risk] + boost) * multiplier + exposure), 1), source


def score_findings(findings: list) -> list:
    for item in findings:
        item["Score"], item["Score Source"] = calculate_score(item)
        item["Severity"] = severity_label(item["Score"])
    return findings


#  main

def main() -> int:
    cli = argparse.ArgumentParser(
        description="Parse Nikto / OWASP ZAP JSON reports into one deduplicated, "
                    "scored JSON report.")
    cli.add_argument("reports", nargs="+", metavar="REPORT",
                     help="path(s) of the Nikto and/or OWASP ZAP JSON report(s)")
    cli.add_argument("-o", "--output", default=DEFAULT_OUTPUT, metavar="FILENAME",
                     help=f"output filename or full path (default: {DEFAULT_OUTPUT})")
    cli.add_argument("--scores", action="store_true",
                     help="look up CVSS (NVD) and EPSS (FIRST) for any CVEs (slower)")
    cli.add_argument("--nvd-api-key", default=os.environ.get("NVD_API_KEY"),
                     metavar="KEY", help="NVD API key (or set NVD_API_KEY); ~9x faster")
    cli.add_argument("--cache", metavar="FILE", help="cache CVE lookups between runs")
    cli.add_argument("--no-dedup", action="store_true",
                     help="skip deduplication and output every instance")
    cli.add_argument("--raw-output", metavar="FILENAME",
                     help="also save every instance before deduplication")
    args = cli.parse_args()

    start = time.perf_counter()
    print(f"\n[+] Started at {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}", file=sys.stderr)

    records, errors = [], []
    for path in args.reports:
        try:
            parsed = parser(path)
            records.extend(parsed)
            print(f"[+] Parsed {len(parsed)} instance(s) from {path}", file=sys.stderr)
        except (OSError, ValueError) as err:     # JSONDecodeError is a ValueError
            errors.append(f"Could not parse {path}: {err}")
            print(f"[-] {errors[-1]}", file=sys.stderr)

    if not records and errors:
        print("\n[-] No findings produced. Exiting.", file=sys.stderr)
        return 1

    findings = group_records(records, dedup=not args.no_dedup)
    print(f"[+] Deduplication: {len(records)} instance(s) -> {len(findings)} "
          f"finding(s) ({len(records) - len(findings)} duplicate(s) merged)",
          file=sys.stderr)

    if args.scores:
        cves = {c for f in findings for c in (f["CVE"] or "").split(", ") if c}
        if cves:
            apply_cve_scores(findings, fetch_cve_scores(cves, args.cache, args.nvd_api_key))
        else:
            print("[*] No CVEs found; using heuristic scores.", file=sys.stderr)

    findings = score_findings(findings)

    try:
        if args.raw_output:
            output([{k: v for k, v in r.items() if k != "key"} for r in records],
                   args.raw_output)
        saved = output(findings, args.output)
    except OSError as err:
        print(f"\n[-] Could not write report: {err}", file=sys.stderr)
        return 1

    print(f"\n[+] Total: {len(findings)} finding(s). Report written to: {saved}",
          file=sys.stderr)
    if errors:
        print(f"[!] {len(errors)} file(s) had errors (see messages above).", file=sys.stderr)
    print(f"[+] Elapsed: {time.perf_counter() - start:.2f} seconds", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())