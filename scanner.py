import argparse
import json
import os
from datetime import datetime

import requests


OSV_URL = "https://api.osv.dev/v1/query"
REQUEST_TIMEOUT = 15


def truncate(text: str, length: int = 100) -> str:
    if not text:
        return "No summary available"
    text = " ".join(text.split())
    return text if len(text) <= length else text[: length - 3] + "..."


def extract_severity(vuln: dict) -> str:
    # OSV often returns severity as a list like:
    # "severity": [{"type": "CVSS_V3", "score": "7.5"}]
    severity_list = vuln.get("severity", [])
    if severity_list:
        first = severity_list[0]
        score = first.get("score")
        sev_type = first.get("type")
        if score and sev_type:
            return f"{sev_type}:{score}"
        if score:
            return str(score)

    # Fallbacks sometimes seen in vulnerability data
    database_specific = vuln.get("database_specific", {})
    if database_specific.get("severity"):
        return str(database_specific["severity"])

    ecosystem_specific = vuln.get("ecosystem_specific", {})
    if ecosystem_specific.get("severity"):
        return str(ecosystem_specific["severity"])

    return "UNKNOWN"


def format_publish_date(vuln: dict) -> str:
    published = vuln.get("published")
    if not published:
        return "UNKNOWN"

    # Example: 2023-08-10T18:15:00Z -> 2023-08-10
    return published[:10]


def check_package(package_name: str) -> dict:
    payload = {
        "package": {
            "name": package_name,
            "ecosystem": "PyPI",
        }
    }

    try:
        response = requests.post(OSV_URL, json=payload, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
    except requests.RequestException as exc:
        return {
            "package": package_name,
            "status": "error",
            "error": str(exc),
            "vulns": [],
        }

    data = response.json()
    return {
        "package": package_name,
        "status": "ok",
        "vulns": data.get("vulns", []),
    }


def parse_requirements(file_path: str) -> list[str]:
    packages = []

    with open(file_path, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()

            if not line or line.startswith("#"):
                continue

            if "#" in line:
                line = line.split("#", 1)[0].strip()

            for separator in ["==", ">=", "<=", "~=", "!=", ">", "<"]:
                if separator in line:
                    line = line.split(separator, 1)[0].strip()
                    break

            if line:
                packages.append(line)

    return packages


def print_package_result(result: dict) -> None:
    package_name = result["package"]

    if result["status"] == "error":
        print(f"[ERROR] {package_name}")
        print(f"  {result['error']}")
        print()
        return

    vulns = result["vulns"]

    if not vulns:
        print(f"[OK] {package_name} has no known vulnerabilities")
        print()
        return

    print(f"[!] Vulnerabilities found for {package_name}: {len(vulns)}")
    print("    ID               | Severity        | Publish Date")
    print("    -----------------|-----------------|------------")

    for vuln in vulns:
        vuln_id = vuln.get("id", "UNKNOWN")
        severity = extract_severity(vuln)
        publish_date = format_publish_date(vuln)
        print(f"    {vuln_id:<16} | {severity:<15} | {publish_date}")

    print()


def save_json_report(results: list[dict], output_file: str) -> None:
    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "results": results,
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"[+] JSON report saved to {output_file}")


def scan_requirements(file_path: str, json_output: str | None = None) -> int:
    if not os.path.exists(file_path):
        print(f"[ERROR] File not found: {file_path}")
        return 2

    packages = parse_requirements(file_path)

    if not packages:
        print("[ERROR] No packages found in requirements file")
        return 2

    print(f"[*] Scanning {len(packages)} package(s) from {file_path}")
    print()

    results = []
    vulnerable_packages = 0
    total_vulns = 0
    error_packages = 0

    for package in packages:
        result = check_package(package)
        results.append(result)
        print_package_result(result)

        if result["status"] == "error":
            error_packages += 1
        elif result["vulns"]:
            vulnerable_packages += 1
            total_vulns += len(result["vulns"])

    print("==== Scan Summary ====")
    print(f"Packages scanned      : {len(packages)}")
    print(f"Vulnerable packages   : {vulnerable_packages}")
    print(f"Total vulnerabilities : {total_vulns}")
    print(f"Errors                : {error_packages}")

    if json_output:
        save_json_report(results, json_output)

    # Non-zero exit code if vulns found or errors occurred
    if error_packages > 0:
        return 2
    if total_vulns > 0:
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan Python dependencies with OSV.dev")
    parser.add_argument(
        "-f",
        "--file",
        default="requirements.txt",
        help="Path to requirements file",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Optional JSON output file",
    )

    args = parser.parse_args()
    return scan_requirements(args.file, args.output)


if __name__ == "__main__":
    raise SystemExit(main())