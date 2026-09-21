# Agentic IaC Security Scanner (`agentic-iac-security-scanner`)

An autonomous, multi-platform AI security scanning skill for deep static security analysis, semantic reasoning, and architectural threat modeling across Infrastructure as Code (IaC) templates.

Target Repository: [https://github.com/eyalestrin/agentic-iac-security-scanner](https://github.com/eyalestrin/agentic-iac-security-scanner)

This skill automatically detects IaC formats (Terraform modules, AWS CloudFormation, Azure ARM/Bicep), chunks large repositories into **400-line operational checkpoints**, and evaluates configurations against major security frameworks (**OWASP**, **CIS Benchmarks**, and the **AWS/Azure/GCP Well-Architected Framework: Security Pillars**).

---

## 🚀 Key Features

* **VS Code Skill Integration**: Installs and executes directly within your local workspace under `.vscode/skills/agentic-iac-security-scanner`.
* **Multi-Format Auto-Detection**: Automatically identifies and parses Terraform (`.tf`, `.tfvars`), AWS CloudFormation (`.json`, `.yaml`), Azure ARM templates (`.json`), and Azure Bicep (`.bicep`).
* **Local & Remote Git Scanning**: Scans existing local directories/subfolders or automatically clones and audits remote Git repositories via the `--git` flag.
* **Pre-Scan Cleanup & State Management**: Automatically purges stale checkpoint files and previous scan reports at the start of every run.
* **400-Line Checkpointing System**: Breaks large files into maximum 400-line contextual chunks saved locally in `.iac_checkpoint.json` in the current project root.
* **Debug Mode (`--debug`)**: Retains state and checkpoint artifacts after a successful scan for auditing and inspection; by default, checkpoints are cleaned up post-scan.
* **Framework Alignment**: Evaluates code against OWASP IaC guidelines, CIS Benchmarks, and the AWS/Azure/GCP Well-Architected Security Pillars.
* **Detailed Severity-Sorted Reports**: Generates structured reports with executive summaries, LLM metadata, isolated code snippets, actionable fixes, and public standard references—always generating a PDF report alongside HTML/Markdown/JSON formats.

---

## 💻 Installation & Prerequisites

### Installation Directory
Clone or place this skill inside your VS Code workspace skills folder:

```bash
mkdir -p .vscode/skills
cd .vscode/skills
git clone https://github.com/eyalestrin/agentic-iac-security-scanner.git
```

---

### Operating System Prerequisites

The engine requires Python 3.9+ and native C libraries for PDF report generation (`weasyprint`).

#### 1. Windows Setup
1. Download and install Python 3.9+ from [python.org](https://www.python.org/) (ensure "Add Python to PATH" is checked).
2. Install GTK+ binaries required by WeasyPrint:
   * **Option A (via Chocolatey):**
     ```cmd
     choco install gtk-runtime
     ```
   * **Option B (via MSYS2):**
     ```cmd
     pacman -S mingw-w64-x86_64-gtk3
     ```
3. Install required Python packages:
   ```cmd
   pip install -r .vscode\skills\agentic-iac-security-scanner\requirements.txt
   ```

#### 2. Linux Setup (Ubuntu / Debian)
```bash
sudo apt update
sudo apt install -y python3 python3-pip build-essential python3-dev \
    python3-setuptools python3-wheel python3-cffi \
    libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev shared-mime-info

pip3 install -r .vscode/skills/agentic-iac-security-scanner/requirements.txt
```

#### 3. Linux Setup (RHEL / Fedora / CentOS)
```bash
sudo dnf install -y python3 python3-pip gcc cairo pango gdk-pixbuf2 libffi-devel

pip3 install -r .vscode/skills/agentic-iac-security-scanner/requirements.txt
```

#### 4. macOS Setup
```bash
# Install Homebrew dependencies
brew install python cairo pango gdk-pixbuf libffi

pip3 install -r .vscode/skills/agentic-iac-security-scanner/requirements.txt
```

---

## 🛠️ Usage & OS Command Examples

### Command Line Switches

```text
python agentic_iac_scanner.py [OPTIONS]

Options:
  -d, --directory PATH    Path to local project directory to scan (scans directory and all sub-folders)
  -g, --git URL           Remote Git repository URL to clone and scan
  -f, --format FORMAT     Output format: html, md, json, sarif (Default: html; PDF always created)
  -o, --output PATH       Output directory for generated reports (Default: ./reports)
  --debug                 Enable debug mode to keep .iac_checkpoint.json after scan completion
  --llm-model NAME        Name of LLM model used for scan metadata annotation (e.g., Claude 3.5 Sonnet, GPT-4o)
```

---

### OS-Specific CLI Execution Examples (Output Format: HTML + PDF)

#### Windows (Command Prompt / PowerShell)
* **Scan Existing Local Project (and all sub-folders):**
  ```cmd
  python .vscode\skills\agentic-iac-security-scanner\agentic_iac_scanner.py -d C:\Projects\MyCloudInfra -f html -o .\reports --debug
  ```
* **Scan Remote Git Repository:**
  ```cmd
  python .vscode\skills\agentic-iac-security-scanner\agentic_iac_scanner.py -g https://github.com/eyalestrin/agentic-iac-security-scanner.git -f html -o .\reports
  ```

#### Linux (Ubuntu / RHEL)
* **Scan Existing Local Project (and all sub-folders):**
  ```bash
  python3 .vscode/skills/agentic-iac-security-scanner/agentic_iac_scanner.py -d /home/user/projects/cloud-infra -f html -o ./reports --debug
  ```
* **Scan Remote Git Repository:**
  ```bash
  python3 .vscode/skills/agentic-iac-security-scanner/agentic_iac_scanner.py -g https://github.com/eyalestrin/agentic-iac-security-scanner.git -f html -o ./reports
  ```

#### macOS
* **Scan Existing Local Project (and all sub-folders):**
  ```bash
  python3 .vscode/skills/agentic-iac-security-scanner/agentic_iac_scanner.py -d ~/Developer/aws-cloudformation-templates -f html -o ./reports --debug
  ```
* **Scan Remote Git Repository:**
  ```bash
  python3 .vscode/skills/agentic-iac-security-scanner/agentic_iac_scanner.py -g https://github.com/eyalestrin/agentic-iac-security-scanner.git -f html -o ./reports
  ```

---

## 📊 Report Structure & Output Specifications

At the beginning of every scan, the skill purges all previous report files and checkpoint files. The freshly generated reports strictly adhere to the following layout:

1. **Header Metadata**:
   * **LLM Engine Used**: Displays the exact LLM model used during analysis (e.g., `Claude 3.5 Sonnet`, `GPT-4o`).
   * **Detected IaC Languages**: Lists all auto-detected frameworks (e.g., `Terraform`, `AWS CloudFormation`, `Azure ARM`, `Azure Bicep`).

2. **Executive Summary**:
   * High-level summary table of security findings grouped and sorted strictly by severity in descending order (**Critical ➔ High ➔ Medium ➔ Low**).

3. **Detailed Findings Section** (Sorted Critical ➔ Low):
   * **Title & Severity Badge**
   * **Finding Description**: Detailed explanation of the vulnerability and security implications.
   * **Exact Location**: Full path to the file and exact line numbers (e.g., `/modules/storage/s3.tf: Lines 14-22`).
   * **Vulnerable Code Snippet**: Isolated relevant lines of code containing the defect (excluding non-relevant code blocks).
   * **Remediation / Recommendation to Fix**: Copy-paste ready replacement code block enabling direct remediation.
   * **Reference Reading**: Direct links to public documentation (OWASP, CIS Benchmarks, AWS/Azure/GCP Well-Architected Security Pillars).
