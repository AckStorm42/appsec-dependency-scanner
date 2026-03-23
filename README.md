# AppSec Dependency Scanner

A lightweight Python tool for identifying known vulnerabilities in dependencies using multiple high-quality data sources, including:

* OSV (Open Source Vulnerabilities)
* NVD (National Vulnerability Database)
* EPSS (Exploit Prediction Scoring System)
* CISA KEV (Known Exploited Vulnerabilities)

This project is designed for learning, demos, and lightweight security scanning — not as a full replacement for enterprise SCA tools.

---

## ✨ Features

* Query vulnerabilities for Python packages (PyPI ecosystem)
* Aggregates data from multiple sources:

  * CVE ID
  * Severity
  * CVSS score
  * EPSS score
  * KEV status (exploited in the wild)
  * Publish date
* Clean, readable terminal output
* No API keys required (optional NVD key for better rate limits)

---

## 📦 Installation

Clone the repository:

```bash
git clone https://github.com/AckStorm42/appsec-dependency-scanner.git
cd appsec-dependency-scanner
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## 🚀 Usage

### Scan a single package

```bash
python scanner.py requests
```

### Scan multiple packages

```bash
python scanner.py requests flask django
```

---

## 📊 Example Output

```
Package: requests

CVE            Severity   CVSS   EPSS   KEV   Publish Date
---------------------------------------------------------
CVE-2023-1234  HIGH       7.5    0.42   YES   2023-08-10
CVE-2022-5678  MEDIUM     5.3    0.12   NO    2022-04-21
```

---

## 🔐 Environment Variables (Optional)

You can improve NVD rate limits by setting an API key:

```bash
export NVD_API_KEY=your_api_key_here
```

If not set, the tool will still work using public endpoints with lower rate limits.

---

## 🧠 Data Sources

* OSV.dev
* NVD (nvd.nist.gov)
* FIRST EPSS
* CISA KEV Catalog

---

## ⚠️ Limitations

* Focused on PyPI packages only (for now)
* Not a full dependency tree scanner (does not parse requirements files yet)
* API rate limits may apply without an NVD API key
* Data quality depends on upstream sources

---

## 🛠️ Roadmap Ideas

* Support `requirements.txt` input
* Add JSON / CSV output formats
* Dependency tree resolution
* Docker image support
* CI/CD integration examples

---

## 🤝 Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

---

## 📄 License

This project is licensed under the MIT License.

---

## 👤 Author

AckStorm42
GitHub: https://github.com/AckStorm42

---

## ⭐ If you find this useful

Give it a star — it helps others discover the project!

