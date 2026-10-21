#!/usr/bin/env python3
"""
Merge parsed Nikto and ZAP reports (the JSON files written by the parser) into ONE
deduplicated, prioritised report.

Merging: findings are merged when they describe the same problem on the same host:
  1. Same issue family (see FAMILIES), within one scanner or between scanners.
  2. Otherwise, the same title wording.
A merged finding keeps every URL, method, reference, CVE and CWE, and "Merged From" lists the originals.

Prioritising: every finding is put on the SAME scale, whichever scanner found it.
  Impact (0-10)    how bad it is if real. First available of:
                     1. CVSS of a CVE named in the finding           (--enrich, NVD)
                     2. the scanner's own rating (ZAP risk code / severity label)
                     3. average CVSS of the CVEs NVD lists for its CWE (--enrich, NVD)
                     4. a keyword heuristic on the wording
  Likelihood       scanner confidence, scaled by the EPSS percentile of the CVE when known (--enrich, FIRST).
  Priority Score = Impact x Likelihood + breadth bonus (many URLs) + corroboration bonus (several scanners), max 10.
  Severity is taken from Impact alone, so a Nikto "high" finding is still labelled High.

Usage:
  python merge_reports.py nikto-parsed.json zap-parsed.json -o merged-report.json
  python merge_reports.py nikto-parsed.json zap-parsed.json --enrich        # adds CVSS/EPSS lookups (internet)
Set NVD_API_KEY to speed up NVD lookups.
"""
 
import argparse
import json
import math
import os
import re
import sys
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

DEFAULT_OUTPUT = "merged-report.json"
DEFAULT_CACHE = "score-cache.json"

# One entry per underlying problem: (title for the merged finding, regex on the lower-case title).
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

# ---- scoring settings -------------------------------------------------------------------------
# Impact on the 0-10 scale for scanner ratings (chosen to sit in the middle of the CVSS bands)
ZAP_RISK_IMPACT = {0: 0.0, 1: 2.5, 2: 5.5, 3: 8.0}
LABEL_IMPACT = {"informational": 0.0, "info": 0.0, "low": 2.5, "medium": 5.5, "high": 8.0, "critical": 9.5}

# Keyword heuristic for findings with no other rating (mostly Nikto, which has no severity)
KW_INFO = re.compile(r"allowed http methods|might be interesting", re.I)
KW_HIGH = re.compile(
    r"sql injection|remote code|command execution|shellshock|remote file inclusion|"
    r"arbitrary (file|code)|backdoor|default (password|credential|account)|"
    r"authentication bypass", re.I)
KW_MEDIUM = re.compile(
    r"cross.site scripting|\bxss\b|directory (indexing|listing)|backup|\.bak\b|"
    r"phpinfo|traversal|admin|password|config|outdated|vulnerable|database|"
    r"\.git\b|\.svn\b|\.env\b", re.I)

# Likelihood: how far the scanner's finding can be trusted
SCANNER_CONFIDENCE = {"nikto": 0.7, "zap": 0.85}      # matched as a substring of the scanner name
DEFAULT_CONFIDENCE = 0.7
CONFIDENCE_LABEL = {"false positive": 0.0, "low": 0.5, "medium": 0.75, "high": 0.9,
                    "confirmed": 1.0, "user confirmed": 1.0}
EXPLOIT_FLOOR = 0.6      # EPSS percentile 0 -> x0.6, percentile 1 -> x1.0 (raw EPSS is too skewed to multiply)
EXPLOIT_UNKNOWN = 0.8    # no EPSS data: neutral
BREADTH_MAX = 1.0        # most a finding gains for affecting many URLs (log scale)
CORROBORATION_BONUS = 0.5

# ---- lookup settings --------------------------------------------------------------------------
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY")
NVD_DELAY = 1.0 if NVD_API_KEY else 6.1     # seconds between NVD requests (rate limit)
CWE_SAMPLE = 200                            # CVEs sampled from NVD to average one CWE
MAX_BYTES = 30 * 1024 * 1024
CACHE_TTL = 7 * 24 * 3600                   # re-fetch cached scores after a week

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
CWE_RE = re.compile(r"CWE-(\d+)", re.I)


# helpers

def warn(msg: str) -> None:
    print(msg, file=sys.stderr)


def as_list(value, sep=None) -> list:
    """A JSON value (string, list or None) as a clean list of strings, optionally split on a regex."""
    out = []
    for v in value if isinstance(value, list) else [value]:
        if v is not None:
            out += [p.strip() for p in (re.split(sep, str(v)) if sep else [str(v)])]
    return [p for p in out if p]


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


def severity(impact: float) -> str:
    return ("Informational" if impact <= 0 else "Low" if impact < 4 else "Medium" if impact < 7
            else "High" if impact < 9 else "Critical")


def keyword_impact(text: str) -> float:
    if KW_INFO.search(text):
        return 0.0
    return 8.0 if KW_HIGH.search(text) else 5.5 if KW_MEDIUM.search(text) else 2.5


# score lookups (NVD for CVSS, FIRST for EPSS)

def best_cvss(metrics: dict):
    """Base score of the newest CVSS version a CVE has, or None."""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            return metrics[key][0]["cvssData"]["baseScore"]
    return None


class Lookup:
    """CVSS / EPSS lookups with an on-disk cache, so repeat runs make few or no requests.
    A failed lookup is never fatal: that score stays unknown and is retried on the next run."""

    def __init__(self, cache_path):
        self.path = Path(cache_path).expanduser()
        self.data = {"cve": {}, "cwe": {}}
        self.last_nvd = float("-inf")
        self.tried = set()
        try:
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
            self.data["cve"].update(loaded.get("cve", {}))
            self.data["cwe"].update(loaded.get("cwe", {}))
        except (OSError, ValueError, AttributeError):
            pass

    def _fresh(self, kind: str, key: str) -> bool:
        entry = self.data[kind].get(key)
        return bool(entry) and time.time() - entry.get("ts", 0) < CACHE_TTL

    def _get(self, url: str, nvd: bool = False, timeout: int = 20) -> dict:
        headers = {"User-Agent": "merge_reports"}
        if nvd:
            wait = NVD_DELAY - (time.monotonic() - self.last_nvd)
            if wait > 0:
                time.sleep(wait)
            self.last_nvd = time.monotonic()
            if NVD_API_KEY:
                headers["apiKey"] = NVD_API_KEY      # only ever sent to NVD
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=timeout) as resp:
            body = resp.read(MAX_BYTES + 1)
        if len(body) > MAX_BYTES:
            raise ValueError("response too large")
        return json.loads(body.decode("utf-8"))

    def _epss_percentiles(self, cves: list) -> dict:
        found = {}
        for i in range(0, len(cves), 100):
            try:
                data = self._get(f"{EPSS_URL}?cve={','.join(cves[i:i + 100])}")
                found.update({r["cve"]: float(r["percentile"]) for r in data.get("data") or []})
            except (OSError, ValueError, KeyError, TypeError) as err:
                warn(f"[!] EPSS lookup failed: {err}")
        return found

    def cves(self, wanted: set) -> dict:
        """{CVE: {cvss, epss_pct}} for the CVEs that could be looked up."""
        todo = sorted(c for c in wanted if not self._fresh("cve", c))
        if todo:
            warn(f"[*] Looking up {len(todo)} CVE(s); NVD is rate limited, about {round(NVD_DELAY * len(todo))}s...")
            pct = self._epss_percentiles(todo)
            for cve in todo:
                entry, ok = {"cvss": None, "epss_pct": pct.get(cve)}, True
                try:
                    vulns = self._get(f"{NVD_URL}?cveId={cve}", nvd=True).get("vulnerabilities") or []
                    entry["cvss"] = best_cvss(vulns[0]["cve"].get("metrics", {})) if vulns else None
                except (OSError, ValueError, KeyError, IndexError, TypeError) as err:
                    ok = False
                    warn(f"[!] NVD lookup failed for {cve}: {err}")
                entry["ts"] = time.time() if ok else 0     # ts 0 = stale, so it is retried next run
                self.data["cve"][cve] = entry
            self.save()
        return {c: self.data["cve"][c] for c in wanted if c in self.data["cve"]}

    def cwe_cvss(self, cwe: str):
        """Average CVSS of a sample of the CVEs NVD lists for this CWE, or None."""
        if cwe not in self.tried and not self._fresh("cwe", cwe):
            self.tried.add(cwe)
            warn(f"[*] Sampling CVEs for {cwe}...")
            scores, ok = [], True
            try:
                data = self._get(f"{NVD_URL}?cweId={cwe}&resultsPerPage={CWE_SAMPLE}", nvd=True, timeout=60)
                scores = [s for v in data.get("vulnerabilities") or []
                          if (s := best_cvss(v["cve"].get("metrics", {}))) is not None]
            except (OSError, ValueError, KeyError, IndexError, TypeError) as err:
                ok = False
                warn(f"[!] NVD lookup failed for {cwe}: {err}")
            self.data["cwe"][cwe] = {"cvss": round(sum(scores) / len(scores), 1) if scores else None,
                                     "ts": time.time() if ok else 0}
            self.save()
        return self.data["cwe"].get(cwe, {}).get("cvss")

    def save(self) -> None:
        try:
            self.path.write_text(json.dumps(self.data), encoding="utf-8")
        except OSError as err:
            warn(f"[!] Could not write cache: {err}")


# loading

def declared_impact(item: dict):
    """The scanner's own rating of a finding on the 0-10 scale, or None if the report has none."""
    for key in ("ZAP Risk", "Risk Code", "riskcode"):
        value = str(item.get(key, "")).strip()
        if value.isdecimal() and int(value) in ZAP_RISK_IMPACT:
            return ZAP_RISK_IMPACT[int(value)]
    for key in ("Severity", "Risk", "Risk Level"):
        words = str(item.get(key) or "").lower().split()
        if words and words[0] in LABEL_IMPACT:
            return LABEL_IMPACT[words[0]]
    score = item.get("Score")
    if isinstance(score, (int, float)) and not isinstance(score, bool):
        return max(0.0, min(10.0, float(score)))
    return None


def confidence_of(item: dict, scanners: list) -> float:
    label = str(item.get("Confidence") or "").strip().lower()
    if label in CONFIDENCE_LABEL:
        return CONFIDENCE_LABEL[label]
    known = [c for s in scanners for name, c in SCANNER_CONFIDENCE.items() if name in s.lower()]
    return max(known) if known else DEFAULT_CONFIDENCE


def load_members(path: str) -> list:
    """One member per finding in a parsed report. Text fields may be strings or lists."""
    with open(Path(path).expanduser(), encoding="utf-8-sig") as handle:
        data = json.load(handle)

    members = []
    for item in data if isinstance(data, list) else [data]:
        titles = as_list(item.get("Title")) if isinstance(item, dict) else []
        if not titles:
            continue

        scanners = as_list(item.get("Scanner"), ",") or ["Unknown"]
        if item.get("Instances"):   # the longer format with URL/method pairs
            urls = [i["url"] for i in item["Instances"] if i.get("url")]
            methods = [i["method"] for i in item["Instances"] if i.get("method")]
        else:
            urls, methods = as_list(item.get("Site URL"), ","), as_list(item.get("Method"), ",")

        description = "\n\n".join(unique(as_list(item.get("Description"))))
        references = [r for part in as_list(item.get("References")) for r in part.split()]
        blob = " ".join([*titles, description, *references])

        cwes = [f"CWE-{n}" for n in CWE_RE.findall(blob)]
        for key in ("CWE", "CWE ID", "cweid"):
            digits = [re.sub(r"\D", "", v) for v in as_list(item.get(key), ",")]
            cwes += [f"CWE-{int(d)}" for d in digits if d and int(d) > 0]

        members.append({
            "scanners": scanners, "title": titles[0], "urls": urls, "methods": methods,
            "description": description, "references": references,
            "cves": unique(c.upper() for c in as_list(item.get("CVE"), ",") + CVE_RE.findall(blob)),
            "cwes": unique(cwes), "solution": next(iter(as_list(item.get("Solution"))), None),
            "declared": declared_impact(item), "confidence": confidence_of(item, scanners),
            "family": family_of(titles[0]),
        })
    if not members:
        raise ValueError("no findings found")
    return members


# prioritising

def assess(members: list, lookup) -> None:
    """Give every member an impact (0-10), where it came from, and an EPSS percentile if known."""
    info = lookup.cves({c for m in members for c in m["cves"]}) if lookup else {}

    for m in members:
        known = [info[c] for c in m["cves"] if c in info]
        cvss = [k["cvss"] for k in known if k["cvss"] is not None]
        pct = [k["epss_pct"] for k in known if k["epss_pct"] is not None]
        m["exploit"] = max(pct) if pct else None

        if cvss:
            m["impact"], m["impact_source"] = max(cvss), "CVSS (CVE)"
        elif m["declared"] is not None:
            m["impact"], m["impact_source"] = m["declared"], "scanner rating"
        else:
            averages = [a for a in (lookup.cwe_cvss(c) for c in m["cwes"]) if a is not None] if lookup else []
            if averages:
                m["impact"], m["impact_source"] = max(averages), "CVSS average (CWE)"
            else:
                m["impact"] = keyword_impact(f"{m['title']} {m['description']}")
                m["impact_source"] = "keyword heuristic"


def merge_group(members: list) -> dict:
    # Best member first: highest impact, then the fullest description
    members = sorted(members, key=lambda m: (-m["impact"], -len(m["description"])))
    best = members[0]
    merged = len(members) > 1

    scanners = sorted(unique(s for m in members for s in m["scanners"]))
    urls = unique(u for m in members for u in m["urls"])
    pcts = [m["exploit"] for m in members if m["exploit"] is not None]
    confidence = max(m["confidence"] for m in members)
    exploit = EXPLOIT_FLOOR + (1 - EXPLOIT_FLOOR) * max(pcts) if pcts else EXPLOIT_UNKNOWN
    breadth = min(BREADTH_MAX, 0.5 * math.log10(max(len(urls), 1)))
    corroboration = CORROBORATION_BONUS if len(scanners) > 1 else 0.0

    # Informational findings and false positives stay at 0 so they never outrank real ones
    if best["impact"] <= 0 or confidence <= 0:
        priority = 0.0
    else:
        priority = min(10.0, best["impact"] * confidence * exploit + breadth + corroboration)

    return {
        "Scanner": ", ".join(scanners),
        "Title": best["family"] if merged and best["family"] else best["title"],
        "Site URL": ", ".join(urls) or None,
        "Method": ", ".join(unique(x for m in members for x in m["methods"])) or None,
        "Description": best["description"] or None,
        "References": "\n".join(unique(r for m in members for r in m["references"])) or None,
        "CVE": ", ".join(unique(c for m in members for c in m["cves"])) or None,
        "CWE": ", ".join(unique(c for m in members for c in m["cwes"])) or None,
        "Solution": next((m["solution"] for m in members if m["solution"]), None),
        "Priority Score": round(priority, 2),
        "Severity": severity(best["impact"]),
        "Priority Detail": {
            "impact": round(best["impact"], 1), "impact_source": best["impact_source"],
            "confidence": confidence, "epss_percentile": max(pcts) if pcts else None,
            "affected_urls": len(urls), "breadth_bonus": round(breadth, 2),
            "corroboration_bonus": corroboration,
        },
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
            warn(f"[+] merged {len(group)} finding(s) ({scanners}) -> {finding['Title']!r}")
            ports = {host_port(u)[1] for m in group for u in m["urls"]} - {None}
            if len(ports) > 1:
                warn(f"[!]   that spans ports {sorted(ports)}: are these the same server?")
        findings.append(finding)

    findings.sort(key=lambda f: (-f["Priority Score"], -f["Priority Detail"]["affected_urls"], f["Title"]))
    return findings


# main

def main() -> int:
    cli = argparse.ArgumentParser(description="Merge parsed Nikto / ZAP reports into one prioritised report.")
    cli.add_argument("reports", nargs="+", metavar="REPORT", help="parsed Nikto and/or ZAP JSON report(s)")
    cli.add_argument("-o", "--output", default=DEFAULT_OUTPUT, help=f"output file (default: {DEFAULT_OUTPUT})")
    cli.add_argument("--match-port", action="store_true",
                     help="only merge findings from the same host AND port (default: same host)")
    cli.add_argument("--skip-info", action="store_true", help="leave out informational findings")
    cli.add_argument("--enrich", action="store_true",
                     help="look up CVSS (NVD) and EPSS (FIRST) for CVEs/CWEs; needs internet and is slow without NVD_API_KEY")
    cli.add_argument("--cache", default=DEFAULT_CACHE, metavar="FILE",
                     help=f"score cache used with --enrich (default: {DEFAULT_CACHE})")
    args = cli.parse_args()

    members = []
    for path in args.reports:
        try:
            found = load_members(path)
            members.extend(found)
            warn(f"[+] {path}: {len(found)} finding(s)")
        except (OSError, ValueError, AttributeError, TypeError, KeyError) as err:
            warn(f"[-] {path}: {err}")
    if not members:
        warn("[-] Nothing to merge.")
        return 1

    assess(members, Lookup(args.cache) if args.enrich else None)
    findings = merge(members, args.match_port)
    if args.skip_info:
        findings = [f for f in findings if f["Severity"] != "Informational"]

    cross = sum(len(f["Scanner"].split(", ")) > 1 for f in findings)
    warn(f"[+] {len(members)} finding(s) -> {len(findings)} after merging ({cross} found by more than one scanner)")

    out = Path(args.output).expanduser().resolve()
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(findings, indent=3, ensure_ascii=False), encoding="utf-8")
    except OSError as err:
        warn(f"[-] Could not write report: {err}")
        return 1
    warn(f"[+] Report written to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())