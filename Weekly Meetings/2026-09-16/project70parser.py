import json
import re
import sys
import time
from datetime import datetime
from pathlib import Path

def output(findings: list, output_filename: str = "default-parsed-report.json") -> Path:
    output_path: Path = Path.cwd() / output_filename

    with open(output_path, "w", encoding="utf-8") as output_file:
        json.dump(findings, output_file, indent=3)

    return output_path

def extract_vulnerability_type(ref: str) -> str:
    """
    Input: The 'reference' string from a single Nikto finding.
    Output: The matched CWE/CVE identifier | Unknown if reference field is empty | (URL) for URL matches [will implement later]
    """
    # If references string is empty then return Unknown for reference
    if not ref:
        return "Unknown"
    
    # Using standard AWK Regular Expression where [0-9]+ = [0-9][0-9]* / Strict Matching
    match = re.search(r"^[ ]*C(W|V)E[ ]*-[ ]*[0-9]+(-[0-9]+)*[ ]*$", ref)

    # Find a match then return full matched string removing any spaces within the matched string and cleans the string
    if match:
        return match.group(0).replace(" ", "")
    return "(URL)"

def parser(path: str) -> list:
    """
    Input: Full file path of the Nikto JSON report
    Output: A clean list of parsed findings in a dictionary.
    """
    # Open file in binary mode to control decoding
    with open(path, "rb") as fstr:
        data: list = json.loads(fstr.read().decode("utf-8"))

    # Enforce data into a list
    docs = data if isinstance(data, list) else [data]

    results: list = []
    for doc in docs:
        # Target IP for the host
        ip: str = doc.get("ip")

        # Check each individual vulnerability finding in the JSON
        for finding in doc.get("vulnerabilities", []):
            msg: str = finding.get("msg", "")
            references: str = finding.get("references", "")
            url: str = finding.get("url", "")

            # Build a cleaned list format {Scanner, Site, Type, Message, References}
            results.append({
                "Scanner": "Nikto",
                "Site": f"{ip}{url}",
                "Type": extract_vulnerability_type(references),
                "Message": msg,
                "References": references
            })

    return results


if __name__ == "__main__":
    # Expand to allow "-o {filename} where {filename} contains an entire path ~\{filename} or default to user's working directory"

    # Checks if the arguements given to the terminal is < 2 or > 2 and exits if true with error printed
    if len(sys.argv) != 2:
        print("Usage: python3 filename.py <nikto-report.json>", file=sys.stderr)
        sys.exit(1)

    start_timer = time.perf_counter()

    print(f"\n[+] Started at {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}", file=sys.stderr)

    # Otherwise run the parsers on the given nikto report json
    findings = parser(sys.argv[1])
    # Print the parsed report into json cleaned format
    saved_path = output(findings)
    print(f"\n[+] Parsed report written to: {saved_path}", file=sys.stderr)

    print(f"\n[+] Finished at {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}. Elapsed: {time.perf_counter() - start_timer:.2f} seconds", file=sys.stderr)