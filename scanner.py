import requests

def check_package(package_name):
    url = f"https://api.osv.dev/v1/query"
    
    payload = {
        "package": {
            "name": package_name,
            "ecosystem": "PyPI"
        }
    }

    response = requests.post(url, json=payload)

    if response.status_code == 200:
        data = response.json()
        if "vulns" in data:
            print(f"[!] Vulnerabilities found for {package_name}")
            for v in data["vulns"]:
                print("  -", v["id"])
        else:
            print(f"[OK] {package_name} has no known vulnerabilities")

def scan_requirements(file):
    with open(file) as f:
        for line in f:
            pkg = line.strip().split("==")[0]
            check_package(pkg)

scan_requirements("requirements.txt")
