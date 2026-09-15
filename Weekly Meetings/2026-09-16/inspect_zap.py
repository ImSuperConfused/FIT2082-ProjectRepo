import json
from pathlib import Path

report_path = Path(__file__).with_name("zap_report.json")

with open(report_path, "r", encoding="utf-8") as file:
    report = json.load(file)

print("Top-level type:", type(report).__name__)
print("Top-level keys:", list(report.keys()))

# Final JSON report template
final_report = {
    "report_metadata": {
        "scanners": ["OWASP ZAP"]
    },
    "findings": []
}

for site in report.get("site", []):
    site_name = site.get("@name")
    alerts = site.get("alerts", [])

    print("Site:", site_name)
    print("Number of alerts:", len(alerts))

    for alert in alerts:
        finding = {
            "scanner": "OWASP ZAP",
            "site": site_name,
            "title": alert.get("alert"),
            "risk": alert.get("riskdesc"),
            "confidence": alert.get("confidence"),
            "cwe": alert.get("cweid")
        }

        final_report["findings"].append(finding)

        print("Title:", alert.get("alert"))
        print("Risk:", alert.get("riskdesc"))
        print("Confidence:", alert.get("confidence"))
        print("CWE:", alert.get("cweid"))
        print("---")

# Save the final JSON report
output_path = Path(__file__).with_name("final_report.json")

with open(output_path, "w", encoding="utf-8") as file:
    json.dump(final_report, file, indent=4)

print(f"Final JSON report saved to: {output_path}")