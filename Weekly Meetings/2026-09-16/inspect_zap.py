import json

with open("zap_report.json", "r", encoding="utf-8") as file:
    report = json.load(file)

print("Top-level type:", type(report).__name__)

if isinstance(report, dict):
    print("Top-level keys:", list(report.keys()))

    sites = report.get("site", [])

    for site in sites:
        print("Site:", site.get("@name"))

        alerts = site.get("alerts", [])

        print("Number of alerts:", len(alerts))

        for alert in alerts:
            print("Title:", alert.get("alert"))
            print("Risk:", alert.get("riskdesc"))
            print("Confidence:", alert.get("confidence"))
            print("CWE:", alert.get("cweid"))
            print("---")
