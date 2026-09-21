---
name: agentic-iac-scanner
description: Autonomous security scanner for Infrastructure as Code (Terraform, CloudFormation, ARM, Bicep) mapped against OWASP, CIS, and Cloud Well-Architected Frameworks.
version: 1.0.0
---

# Agentic IaC Security Scanner Skill

## Goal
Scans Infrastructure as Code (IaC) repositories using semantic AI analysis, checkpointing every 400 lines of code. It maps findings against OWASP IaC guidelines, CIS Benchmarks, and Cloud Well-Architected Security Pillars (AWS, Azure, GCP).

## Workflow Instructions

1. **Environment & Dependency Checks**
   - Ensure Python 3.9+ is installed.
   - Verify requirements: `pip install -r requirements.txt`.

2. **Reconnaissance & Format Identification**
   - Inspect target directory.
   - Categorize files by provider engine:
     - **Terraform**: `*.tf`, `*.tfvars`
     - **AWS CloudFormation**: `*.yaml`, `*.yml`, `*.json` (with `AWSTemplateFormatVersion`)
     - **Azure ARM/Bicep**: `*.json` (with `$schema` containing `deploymentTemplate.json`), `*.bicep`

3. **Checkpoint & Chunking Engine**
   - Partition identified IaC files into logical blocks of **maximum 400 lines of code**.
   - Read `.iac_checkpoint.json` in the target directory. Skip any `file_path::chunk_index` marked as `COMPLETED`.

4. **Security Analysis Baseline**
   For each chunk, evaluate against:
   - **OWASP IaC Principles**: Least privilege, public exposure, hardcoded credentials, state file exposure.
   - **CIS Benchmarks**: Encryption at rest/transit, audit logging, default configurations.
   - **AWS Well-Architected (Security Pillar)**: KMS keys, S3 access logging, GuardDuty/CloudTrail coverage, IAM wildcards.
   - **Azure Well-Architected (Security Pillar)**: NSG default rules, Key Vault purge protection, Managed Identity usage.
   - **GCP Well-Architected (Security Pillar)**: Private Google Access, CMEK usage, Service Account key generation.

5. **Report Generation**
   - Save state to `.iac_checkpoint.json` after processing each 400-line block.
   - Compile all findings into `./reports/`:
     - `summary.md` (Markdown summary)
     - `findings.json` (Structured JSON)
     - `results.sarif` (GitHub Security Integration)
     - `iac_security_report.pdf` (**Mandatory PDF Report**)
