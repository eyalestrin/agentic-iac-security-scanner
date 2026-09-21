# Agentic IaC Security Scanner (`agentic-iac-security-scanner`)

An autonomous, multi-platform AI security scanning skill for deep static security analysis, semantic reasoning, and architectural threat modeling across Infrastructure as Code (IaC) templates.

Target Repository: [https://github.com/eyalestrin/agentic-iac-security-scanner](https://github.com/eyalestrin/agentic-iac-security-scanner)

This skill automatically detects IaC formats (Terraform modules, AWS CloudFormation, Azure ARM/Bicep), chunks large repositories into **400-line operational checkpoints**, and evaluates configurations against major security frameworks (**OWASP**, **CIS Benchmarks**, and the **AWS/Azure/GCP Well-Architected Framework: Security Pillars**).

---

## 🚀 Key Features

* **Current development path**: `~/agentic-iac-security-scanner`.
* **Final VS Code deployment path**: `~/.vscode/skills/agentic-iac-security-scanner`.
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
During development, keep the checkout at `~/agentic-iac-security-scanner`.
For final VS Code deployment, place it at
`~/.vscode/skills/agentic-iac-security-scanner`:

```bash
mkdir -p ~/.vscode/skills
git clone https://github.com/eyalestrin/agentic-iac-security-scanner.git \
  ~/.vscode/skills/agentic-iac-security-scanner
```

---

### Operating System Prerequisites

The engine requires Python 3.9+ and uses only the Python standard library.
PDF generation is built in; no WeasyPrint, GTK, or native C libraries are
required.

#### 1. Windows Setup
1. Install Python 3.9+ from [python.org](https://www.python.org/). Enable
  **Add Python to PATH** during installation.
2. Open PowerShell and verify Python:
  ```powershell
  python --version
  ```
3. Clone or copy the skill into the final VS Code skill directory:
  ```powershell
  $skillPath = Join-Path $HOME ".vscode\skills\agentic-iac-security-scanner"
  New-Item -ItemType Directory -Force -Path (Split-Path $skillPath) | Out-Null
  git clone https://github.com/eyalestrin/agentic-iac-security-scanner.git $skillPath
  ```
4. Run the scanner from the project directory. No virtual environment,
  GTK installation, or additional Python package is required.

#### 2. Linux Setup (Ubuntu / Debian)
```bash
sudo apt update
sudo apt install -y python3
```

No Python package installation is required.

#### 3. Linux Setup (RHEL / Fedora / CentOS)
```bash
sudo dnf install -y python3
```

#### 4. macOS Setup
```bash
# Install Homebrew dependencies
brew install python cairo pango gdk-pixbuf libffi

python3 --version
```

---

## 🛠️ Usage & OS Command Examples

### Command Line Switches

```text
python agentic_iac_scanner.py [OPTIONS]

Options:
  -d, --directory PATH    Path to local project directory to scan (default: current directory)
  -f, --format FORMAT     Requested format: html, md, json, or sarif (default: html)
  --debug                 Optional: keep .iac_checkpoint.json after scan completion
```

---

### OS-Specific CLI Execution Examples (Output Format: HTML + PDF)

#### Windows (Command Prompt / PowerShell)
* **Scan Existing Local Project (and all sub-folders):**
  ```cmd
  python .vscode\skills\agentic-iac-security-scanner\agentic_iac_scanner.py -f html
  ```
* **Scan Remote Git Repository:**
  ```cmd
  python .vscode\skills\agentic-iac-security-scanner\agentic_iac_scanner.py -g https://github.com/eyalestrin/agentic-iac-security-scanner.git -f html
  ```

#### Linux (Ubuntu / RHEL)
* **Scan Existing Local Project (and all sub-folders):**
  ```bash
  python3 ~/agentic-iac-security-scanner/agentic_iac_scanner.py -f html
  ```
* **Scan Remote Git Repository:**
  ```bash
  python3 ~/agentic-iac-security-scanner/agentic_iac_scanner.py -g https://github.com/eyalestrin/agentic-iac-security-scanner.git -f html
  ```

#### macOS
* **Scan Existing Local Project (and all sub-folders):**
  ```bash
  python3 ~/agentic-iac-security-scanner/agentic_iac_scanner.py -f html
  ```
* **Scan Remote Git Repository:**
  ```bash
  python3 ~/agentic-iac-security-scanner/agentic_iac_scanner.py -g https://github.com/eyalestrin/agentic-iac-security-scanner.git -f html
  ```

---

## 📊 Report Structure & Output Specifications

At the beginning of every scan, the skill purges previous reports and
checkpoint files. Reports are written to the current folder; `findings.json`
is retained only with `--debug`.

### Output Formats

Choose one requested format with `-f`. The scanner creates that format in the
current folder and creates `iac-security-scanner.pdf` as the executive summary.
It does not create the other requested formats. `findings.json` is an optional
debug artifact only.

#### HTML (`-f html`)

Creates `iac-security-scanner.html`, a browser-readable report. It is useful
for reviewing findings interactively because severity labels, file locations,
focused code snippets, and remediation text are displayed with wrapped text.

#### Markdown (`-f md`)

Creates `iac-security-scanner.md`, a plain-text report suitable for GitHub,
pull requests, documentation, terminals, and version control. It contains the
executive summary followed by severity-sorted findings and remediation details.

#### JSON (`-f json`)

Creates `iac-security-scanner.json`, a machine-readable report for scripts,
custom dashboards, automation, and downstream processing. It preserves the
structured finding fields such as severity, IaC framework, file path, line
range, vulnerable code, remediation, and standard mapping.

#### SARIF (`-f sarif`)

Creates `iac-security-scanner.sarif` using the SARIF 2.1.0 structure. SARIF is
intended for CI/CD tools, code-scanning platforms, and security dashboards
that can import standardized static-analysis results.

#### PDF executive summary

Creates `iac-security-scanner.pdf` as the executive summary for sharing,
archiving, and reviewing outside the development environment. PDF generation
uses only the Python standard library; no GTK, WeasyPrint, or extra package is
needed.

The scanner does not create a separate output directory and does not write
`findings.json` unless `--debug` is supplied.

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
