import argparse
import json
import os
from datetime import datetime
from typing import Any

import requests


OSV_URL = "https://api.osv.dev/v1/query"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"

# This is the commonly used official CISA KEV JSON feed URL.
# If CISA ever changes it, override with KEV_URL env var.
KEV_URL = os.getenv(
    "KEV_URL",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
)

REQUEST_TIMEOUT = 20
NVD_API_KEY = os.getenv("NVD_API_KEY")


def truncate(text: str, length: int = 100) -> str:
    if not text:
        return ""
    text = " ".join(text.split())
    return text if len(text) <= length else text[: length - 3] + "..."


def safe_get(url: str, **kwargs) -> requests.Response:
    response = requests.get(url, timeout=REQUEST_TIMEOUT, **kwargs)
    response.raise_for_status()
    return response


def safe_post(url: str, **kwargs) -> requests.Response:
    response = requests.post(url, timeout=REQUEST_TIMEOUT, **kwargs)
    response.raise_for_status()
    return response


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


def check_package(package_name: str) -> dict[str, Any]:
    payload = {
        "package": {
            "name": package_name,
            "ecosystem": "PyPI",
        }
    }

    try:
        response = safe_post(OSV_URL, json=payload)
        data = response.json()
    except requests.RequestException as exc:
        return {
            "package": package_name,
            "status": "error",
            "error": f"OSV request failed: {exc}",
            "vulns": [],
        }
    except ValueError as exc:
        return {
            "package": package_name,
            "status": "error",
            "error": f"OSV returned invalid JSON: {exc}",
            "vulns": [],
        }

    return {
        "package": package_name,
        "status": "ok",
        "vulns": data.get("vulns", []),
    }


def extract_cve_id(vuln: dict[str, Any]) -> str | None:
    vuln_id = vuln.get("id", "")
    if isinstance(vuln_id, str) and vuln_id.startswith("CVE-"):
        return vuln_id

    for alias in vuln.get("aliases", []):
        if isinstance(alias, str) and alias.startswith("CVE-"):
            return alias

    return None


def format_date(value: str | None) -> str:
    if not value:
        return "UNKNOWN"

    # Handles common ISO timestamps like 2024-11-14T12:34:56Z
    if len(value) >= 10:
        return value[:10]

    return value


def parse_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def osv_fallback_severity_and_score(vuln: dict[str, Any]) -> tuple[str, str]:
    severity_list = vuln.get("severity", [])
    if not severity_list:
        return "UNKNOWN", "N/A"

    first = severity_list[0]
    score = first.get("score")
    sev_type = first.get("type", "")

    # OSV often exposes score strings like CVSS vectors or numeric text.
    if score:
        score_text = str(score)

        # If it looks numeric, return it as score.
        numeric_score = parse_float(score_text)
        if numeric_score is not None:
            return "UNKNOWN", f"{numeric_score:.1f}"

        # Otherwise keep it as opaque score text.
        return sev_type or "UNKNOWN", score_text

    return sev_type or "UNKNOWN", "N/A"


def fetch_kev_set() -> tuple[set[str], str | None]:
    try:
        response = safe_get(KEV_URL)
        data = response.json()
    except requests.RequestException as exc:
        return set(), f"CISA KEV request failed: {exc}"
    except ValueError as exc:
        return set(), f"CISA KEV returned invalid JSON: {exc}"

    vulnerabilities = data.get("vulnerabilities", [])
    kev_set = {
        item.get("cveID")
        for item in vulnerabilities
        if isinstance(item, dict) and item.get("cveID")
    }
    return kev_set, None


def fetch_nvd_cve(cve_id: str) -> tuple[dict[str, Any] | None, str | None]:
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    params = {"cveId": cve_id}

    try:
        response = safe_get(NVD_URL, params=params, headers=headers or None)
        data = response.json()
    except requests.RequestException as exc:
        return None, f"NVD request failed for {cve_id}: {exc}"
    except ValueError as exc:
        return None, f"NVD returned invalid JSON for {cve_id}: {exc}"

    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        return None, None

    cve = vulnerabilities[0].get("cve", {})
    return cve, None


def extract_nvd_severity_and_cvss(cve: dict[str, Any]) -> tuple[str, str]:
    metrics = cve.get("metrics", {})

    # Prefer newer versions first
    candidates = [
        ("cvssMetricV40", "cvssV4_0"),
        ("cvssMetricV31", "cvssV3_1"),
        ("cvssMetricV30", "cvssV3_0"),
        ("cvssMetricV2", "cvssV2"),
    ]

    for metric_key, _label in candidates:
        metric_list = metrics.get(metric_key, [])
        if not metric_list:
            continue

        metric = metric_list[0]
        cvss_data = metric.get("cvssData", {})

        severity = (
            cvss_data.get("baseSeverity")
            or metric.get("baseSeverity")
            or "UNKNOWN"
        )

        score = cvss_data.get("baseScore")
        if score is not None:
            try:
                return str(severity), f"{float(score):.1f}"
            except (TypeError, ValueError):
                return str(severity), str(score)

        return str(severity), "N/A"

    return "UNKNOWN", "N/A"


def fetch_epss_map(cve_ids: list[str]) -> tuple[dict[str, dict[str, str]], str | None]:
    unique_ids = sorted(set(cve_ids))
    if not unique_ids:
        return {}, None

    params = {"cve": ",".join(unique_ids)}

    try:
        response = safe_get(EPSS_URL, params=params)
        data = response.json()
    except requests.RequestException as exc:
        return {}, f"EPSS request failed: {exc}"
    except ValueError as exc:
        return {}, f"EPSS returned invalid JSON: {exc}"

    epss_map: dict[str, dict[str, str]] = {}
    for item in data.get("data", []):
        cve = item.get("cve")
        if not cve:
            continue
        epss_map[cve] = {
            "epss": item.get("epss", ""),
            "percentile": item.get("percentile", ""),
            "date": item.get("date", ""),
        }

    return epss_map, None


def enrich_results(results: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    warnings: list[str] = []

    kev_set, kev_error = fetch_kev_set()
    if kev_error:
        warnings.append(kev_error)

    # Gather CVEs first so we can batch EPSS lookup
    all_cve_ids: list[str] = []
    for result in results:
        if result["status"] != "ok":
            continue
        for vuln in result["vulns"]:
            cve_id = extract_cve_id(vuln)
            if cve_id:
                all_cve_ids.append(cve_id)

    epss_map, epss_error = fetch_epss_map(all_cve_ids)
    if epss_error:
        warnings.append(epss_error)

    nvd_cache: dict[str, dict[str, Any] | None] = {}

    enriched_results: list[dict[str, Any]] = []
    for result in results:
        if result["status"] != "ok":
            enriched_results.append(result)
            continue

        enriched_vulns: list[dict[str, Any]] = []

        for vuln in result["vulns"]:
            cve_id = extract_cve_id(vuln)
            osv_id = vuln.get("id", "UNKNOWN")

            severity = "UNKNOWN"
            cvss = "N/A"
            publish_date = format_date(vuln.get("published"))
            kev = "N/A"
            epss = "N/A"

            if cve_id:
                if cve_id not in nvd_cache:
                    nvd_data, nvd_error = fetch_nvd_cve(cve_id)
                    nvd_cache[cve_id] = nvd_data
                    if nvd_error:
                        warnings.append(nvd_error)

                nvd_cve = nvd_cache.get(cve_id)
                if nvd_cve:
                    severity, cvss = extract_nvd_severity_and_cvss(nvd_cve)
                    publish_date = format_date(nvd_cve.get("published")) or publish_date

                epss_entry = epss_map.get(cve_id)
                if epss_entry:
                    epss_value = parse_float(epss_entry.get("epss"))
                    if epss_value is not None:
                        epss = f"{epss_value:.3f}"
                    else:
                        epss = epss_entry.get("epss", "N/A") or "N/A"

                kev = "YES" if cve_id in kev_set else "NO"

            if severity == "UNKNOWN" and cvss == "N/A":
                fallback_severity, fallback_cvss = osv_fallback_severity_and_score(vuln)
                severity = fallback_severity
                cvss = fallback_cvss

            enriched_vulns.append(
                {
                    "osv_id": osv_id,
                    "cve_id": cve_id or "N/A",
                    "severity": severity,
                    "cvss": cvss,
                    "epss": epss,
                    "kev": kev,
                    "publish_date": publish_date,
                    "summary": vuln.get("summary", ""),
                    "aliases": vuln.get("aliases", []),
                }
            )

        enriched_result = dict(result)
        enriched_result["enriched_vulns"] = enriched_vulns
        enriched_results.append(enriched_result)

    # De-duplicate warnings while preserving order
    unique_warnings = list(dict.fromkeys(warnings))
    return enriched_results, unique_warnings


def print_package_result(result: dict[str, Any]) -> None:
    package_name = result["package"]

    if result["status"] == "error":
        print(f"[ERROR] {package_name}")
        print(f"  {result['error']}")
        print()
        return

    vulns = result.get("enriched_vulns", [])

    if not vulns:
        print(f"[OK] {package_name} has no known vulnerabilities")
        print()
        return

    print(f"[!] Vulnerabilities found for {package_name}: {len(vulns)}")
    print("    Package               | CVE                 | Severity   | CVSS | EPSS  | KEV | Publish Date")
    print("    ----------------------|---------------------|------------|------|-------|-----|------------")

    for vuln in vulns:
        print(
            f"    {package_name:<21} | "
            f"{vuln['cve_id']:<15}     | "
            f"{vuln['severity']:<10} | "
            f"{vuln['cvss']:<4} | "
            f"{vuln['epss']:<5} | "
            f"{vuln['kev']:<3} | "
            f"{vuln['publish_date']}"
        )

    print()


def save_json_report(
    results: list[dict[str, Any]],
    warnings: list[str],
    output_file: str,
) -> None:
    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "warnings": warnings,
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

    raw_results = []
    error_packages = 0

    for package in packages:
        result = check_package(package)
        raw_results.append(result)
        if result["status"] == "error":
            error_packages += 1

    enriched_results, warnings = enrich_results(raw_results)

    vulnerable_packages = 0
    total_vulns = 0

    for result in enriched_results:
        print_package_result(result)

        if result["status"] == "ok" and result.get("enriched_vulns"):
            vulnerable_packages += 1
            total_vulns += len(result["enriched_vulns"])

    print("==== Scan Summary ====")
    print(f"Packages scanned      : {len(packages)}")
    print(f"Vulnerable packages   : {vulnerable_packages}")
    print(f"Total vulnerabilities : {total_vulns}")
    print(f"Errors                : {error_packages}")

    if warnings:
        print()
        print("==== Warnings ====")
        for warning in warnings:
            print(f"- {warning}")

    if json_output:
        save_json_report(enriched_results, warnings, json_output)

    if error_packages > 0:
        return 2
    if total_vulns > 0:
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan Python dependencies with OSV, NVD, EPSS, and CISA KEV"
    )
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
