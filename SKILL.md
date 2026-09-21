---
name: agentic-iac-security-scanner
description: Autonomous cross-platform security scanner for IaC (Terraform, CloudFormation, ARM, Bicep) mapped against OWASP, CIS Benchmarks, and Cloud Well-Architected Security Pillars.
version: 1.0.0
---

# Agentic IaC Security Scanner Skill

## Purpose & Scope
This skill performs semantic AI static analysis and architectural threat modeling on Infrastructure as Code (IaC) source files. It scans local directories or remote Git repositories, operates in 400-line checkpoints, and generates multi-format reports sorted by severity.

Target Repository: `https://github.com/eyalestrin/agentic-iac-security-scanner`
Current Development Path: `~/agentic-iac-security-scanner`
Final Deployment Path: `~/.vscode/skills/agentic-iac-security-scanner`

---

## Operational Execution Protocol

### Step 1: Initialization & Environment Purge
Before initiating scanning:
1. Delete any existing local `.iac_checkpoint.json` in the project root.
2. Purge existing `iac-security-scanner.*` report files in the current directory.
3. If `--git <URL>` is provided, clone the remote repository into a temporary workspace directory before scanning.

### Step 2: Language Detection & Chunking
1. Recursively discover files and auto-detect IaC languages:
   * **Terraform**: `.tf`, `.tfvars`
   * **AWS CloudFormation**: `.yaml`, `.json` containing `AWSTemplateFormatVersion` or AWS resource types
   * **Azure ARM**: `.json` with `$schema` referencing `deploymentTemplate.json`
   * **Azure Bicep**: `.bicep`
2. Divide target files into **400-line chunks**. Record state in `.iac_checkpoint.json`.

### Step 3: Security Evaluation Rules
Evaluate each chunk against:
* **OWASP IaC & DSVS**: Least privilege, public exposure, hardcoded credentials, unencrypted state.
* **CIS Benchmarks**: Storage bucket encryption, audit logging, strict ingress rules.
* **AWS Well-Architected (Security Pillar)**: KMS keys, S3 bucket keys, GuardDuty/CloudTrail targets, IAM wildcards.
* **Azure Well-Architected (Security Pillar)**: Subnet NSG associations, Key Vault soft-delete/purge protection, Managed Identities.
* **GCP Well-Architected (Security Pillar)**: Uniform bucket-level access, VPC Flow Logs, CMEK key usage.

### Step 4: Report Generation & Cleanup
1. Write findings only to the requested format (`html`, `md`, `json`, or `sarif`) in the current folder.
2. **Always generate `iac-security-scanner.pdf`** using the Python standard library; no WeasyPrint or GTK installation is required.
3. Include metadata at the top of reports:
   * LLM model used for the scan.
   * List of detected IaC frameworks.
4. Format findings sorted by severity (**Critical ➔ High ➔ Medium ➔ Low**) with isolated code snippets, fix replacement code, and reference links.
5. **Cleanup**: Unless `--debug` is specified, delete `.iac_checkpoint.json` upon successful completion. Debug mode is optional; do not ask the user to provide it.

### Default Locations

- If no `--directory`/`-d` is provided, scan the current directory (`.`).
- If no `--output`/`-o` is provided, write all reports to the current directory (`.`).
- The user may add `--debug` to retain `.iac_checkpoint.json`; otherwise it is removed after a successful scan.
- A previous checkpoint is removed at the start of every scan, preventing same-named files in different folders from being treated as the same chunk.
- Reports use the basename `iac-security-scanner`; `findings.json` is written only when `--debug` is enabled.

### Python Environment

On Debian/Ubuntu, install `python3-venv` (and the versioned package such as
`python3.12-venv` when required) before creating a project virtual environment.
Install Python packages inside that virtual environment.
Do not install them into the system interpreter with `pip3 install`; PEP 668
blocks that operation. Use `python3 -m venv .venv`, activate it, and run the
scanner with the environment's Python interpreter.