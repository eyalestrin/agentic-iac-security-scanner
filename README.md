# Agentic IaC Security Scanner (`agentic-iac-scanner`)

An autonomous, cross-platform security analysis engine designed to evaluate Infrastructure as Code (IaC) against industry standards, cloud architecture pillars, and compliance baselines.

`agentic-iac-scanner` provides semantic reasoning and cross-template data flow analysis across Terraform, AWS CloudFormation, Azure ARM, and Bicep files. It automates chunking for large codebases and generates comprehensive reports across multiple formats.

---

## ⚡ Key Features

* **Multi-Format Auto-Detection**: Automatically detects and parses Terraform (`.tf`, `.tfvars`), AWS CloudFormation (`.json`, `.yaml`), Azure ARM templates (`.json`), and Azure Bicep (`.bicep`).
* **Cross-Platform Support**: Written in pure Python—runs identically on **Windows**, **Linux** (RHEL, Ubuntu, Debian), and **macOS**.
* **400-Line Checkpointing**: Splits large infrastructure templates into **400-line chunks**, saving scan state to `.iac_checkpoint.json` so interrupted runs resume without rescanning completed sections.
* **Framework Mappings**:
  * **OWASP**: IaC Security Principles & DevSecOps Verification Standard (DSVS).
  * **CIS Benchmarks**: Hardening checks across AWS, Azure, and GCP resources.
  * **AWS Well-Architected Framework**: Security Pillar alignment (KMS encryption, S3 access policies, IAM wildcards, GuardDuty).
  * **Azure Well-Architected Framework**: Security Pillar alignment (NSG rules, Key Vault purge protection, Managed Identities).
  * **GCP Well-Architected Framework**: Security Pillar alignment (Private Google Access, CMEK keys, Service Account management).
* **Multi-Format Reporting**: Outputs scan artifacts in **Markdown**, **JSON**, and **HTML**, while automatically generating a compiled **PDF report** on every run.

---

## 📁 Repository Structure

```text
agentic-iac-scanner/
├── SKILL.md                  # Skill definition and agentic instructions
├── README.md                 # Project documentation
├── requirements.txt          # Python dependencies
├── agentic_iac_scanner.py    # Core scanner engine script
└── templates/
    └── report_template.html  # HTML/PDF report layout
```

---

## 🛠️ Installation

### Prerequisites
* Python 3.9+
* `pip` package manager

### Setup

```bash
# Clone the repository
git clone https://github.com/your-username/agentic-iac-scanner.git
cd agentic-iac-scanner

# Install required dependencies
pip install -r requirements.txt
```

### `requirements.txt`
```text
jinja2>=3.1.2
weasyprint>=60.0
argparse
typing
```

---

## 🚀 Quick Start

### 1. Execute Scan
Run the scanner against any directory containing IaC templates:

```bash
python agentic_iac_scanner.py -d ./infrastructure -o ./reports
```

### 2. Resuming Interrupted Scans
If a scan is interrupted, re-run the same command. The engine reads `.iac_checkpoint.json` in the target directory and skips previously completed 400-line blocks:

```bash
python agentic_iac_scanner.py -d ./infrastructure -o ./reports
```

---

## 📊 Output Artifacts

All scan results are compiled in the designated output directory (`./reports` by default):

| Artifact | Description |
| :--- | :--- |
| `iac_security_report.pdf` | **Mandatory PDF report** with executive summary and severity breakdown. |
| `summary.md` | Lightweight Markdown summary for pull request comments or developer reviews. |
| `findings.json` | Structured JSON output for integration into CI/CD pipelines. |
| `report.html` | Interactive HTML report for local browser viewing. |

---

## 🛡️ Target Framework Alignment

| Framework | Target Resources & Checked Controls |
| :--- | :--- |
| **OWASP IaC** | Least privilege access, unencrypted state files, hardcoded credentials, public storage exposure. |
| **CIS Benchmarks** | Default network rules, audit logging status, storage bucket access logging, mandatory tags. |
| **AWS Security Pillar** | S3 bucket key enforcement, CloudTrail multi-region coverage, TLS 1.2+ ingress policies. |
| **Azure Security Pillar** | Subnet NSG associations, Key Vault soft-delete/purge protection, diagnostic settings routing. |
| **GCP Security Pillar** | Uniform bucket-level access, VPC Flow Logs, CMEK integration on BigQuery & GCS. |

