#!/usr/bin/env python3
"""
Agentic IaC Security Scanner Core
Supports Windows, Linux (RHEL/Ubuntu), and macOS.
"""

import os
import sys
import json
import re
import argparse
from html import escape
from pathlib import Path
from typing import List, Dict, Any


CHECKPOINT_FILE = ".iac_checkpoint.json"
CHUNK_SIZE_LINES = 400
REPORT_BASENAME = "iac-security-scanner"
SUPPORTED_FORMATS = {"html", "md", "json", "sarif"}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SCANNER_MODEL = "No LLM model used; deterministic IaC heuristic rules"
REPORT_FILES = {f"{REPORT_BASENAME}.{suffix}" for suffix in (*SUPPORTED_FORMATS, "pdf")}

IAC_RULES = [
    {
        "title": "Unrestricted Network Ingress",
        "severity": "CRITICAL",
        "pattern": r"0\.0\.0\.0/0|::/0",
        "standard": "CIS / Least Privilege",
        "description": "An ingress rule allows traffic from every IPv4 or IPv6 source, exposing the resource to the public internet.",
        "remediation": "Restrict the source range to approved CIDRs instead of the entire internet.",
        "fix_template": "cidr_blocks = [\"10.0.0.0/16\"]",
        "references": ["https://www.cisecurity.org/benchmark/amazon_web_services", "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec-secure-network.html"],
    },
    {
        "title": "Wildcard IAM Permission",
        "severity": "HIGH",
        "pattern": r'"Action"\s*:\s*"\*"|actions\s*=\s*\[?\s*"\*"',
        "standard": "CIS / Least Privilege",
        "description": "An IAM policy grants every available action instead of only the actions required by the workload.",
        "remediation": "Replace wildcard actions with the smallest set of required actions.",
        "fix_template": "actions = [\"service:RequiredAction\"]",
        "references": ["https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html", "https://owasp.org/www-project-application-security-verification-standard/"],
    },
    {
        "title": "Public Cloud Storage Access",
        "severity": "HIGH",
        "pattern": r"public-read|public-read-write|allUsers|\*\s*=\s*\[?\s*\"storage\.objects",
        "standard": "CIS / Data Protection",
        "description": "The storage resource is configured for public access, allowing unauthenticated users to read or write data.",
        "remediation": "Remove public access and grant access only to authenticated principals.",
        "fix_template": "public_access = false",
        "references": ["https://www.cisecurity.org/benchmark/amazon_web_services", "https://learn.microsoft.com/azure/security/fundamentals/data-encryption-best-practices"],
    },
    {
        "title": "Storage Encryption Not Configured",
        "severity": "MEDIUM",
        "pattern": r"encrypt(?:ion)?\s*=\s*(?:false|disabled)|encrypted\s*:\s*false",
        "standard": "CIS / Data Protection",
        "description": "The configuration explicitly disables encryption at rest for a storage or data resource.",
        "remediation": "Enable encryption at rest using the cloud provider's managed or customer-managed key.",
        "fix_template": "encryption = true",
        "references": ["https://www.cisecurity.org/benchmark/amazon_web_services", "https://cloud.google.com/security/encryption-at-rest"],
    },
    {
        "title": "Publicly Exposed Resource",
        "severity": "HIGH",
        "pattern": r"public_network_access\s*=\s*['\"]?Enabled|publicNetworkAccess\s*:\s*['\"]?Enabled",
        "standard": "Cloud Well-Architected Security Pillar",
        "description": "The resource is configured to accept public network access instead of using private connectivity controls.",
        "remediation": "Disable public network access and use private endpoints or approved network controls.",
        "fix_template": "public_network_access = \"Disabled\"",
        "references": ["https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec-infrastructure-protection.html", "https://learn.microsoft.com/azure/well-architected/security/secure-networking"],
    },
]

FRAMEWORK_REFERENCES = {
    "Terraform": [
        "https://owasp.org/www-project-devsecops-guideline/",
    ],
    "AWS Terraform": [
        "https://www.cisecurity.org/benchmark/amazon_web_services",
        "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html",
    ],
    "GCP Terraform": [
        "https://cloud.google.com/security/best-practices",
        "https://cloud.google.com/architecture/framework/security",
    ],
    "Azure Terraform": [
        "https://learn.microsoft.com/azure/well-architected/security/",
        "https://learn.microsoft.com/azure/security/fundamentals/best-practices-and-patterns",
    ],
    "AWS CloudFormation": [
        "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html",
        "https://www.cisecurity.org/benchmark/amazon_web_services",
    ],
    "Azure ARM Template": [
        "https://learn.microsoft.com/azure/well-architected/security/",
        "https://learn.microsoft.com/azure/security/fundamentals/best-practices-and-patterns",
    ],
    "Azure Bicep": [
        "https://learn.microsoft.com/azure/well-architected/security/",
        "https://learn.microsoft.com/azure/security/fundamentals/best-practices-and-patterns",
    ],
}


class IaCDetector:
    """Detects IaC frameworks automatically based on file extensions and content analysis."""
    
    @staticmethod
    def identify_type(file_path: Path) -> str:
        ext = file_path.suffix.lower()
        
        if ext in ['.tf', '.tfvars']:
            return "Terraform"
        elif ext == '.bicep':
            return "Azure Bicep"
        elif ext in ['.json', '.yaml', '.yml']:
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                if "AWSTemplateFormatVersion" in content or "Resources" in content and "AWS::" in content:
                    return "AWS CloudFormation"
                elif "$schema" in content and "deploymentTemplate.json" in content:
                    return "Azure ARM Template"
            except Exception:
                pass
        return "Unknown"


class CheckpointManager:
    """Manages scan state across 400-line code checkpoints."""
    
    def __init__(self, target_dir: Path):
        self.checkpoint_path = target_dir / CHECKPOINT_FILE
        self.state = self._load_state()

    def _load_state(self) -> Dict[str, Any]:
        if self.checkpoint_path.exists():
            try:
                return json.loads(self.checkpoint_path.read_text(encoding='utf-8'))
            except Exception:
                return {"completed_chunks": []}
        return {"completed_chunks": []}

    def is_processed(self, chunk_id: str) -> bool:
        return chunk_id in self.state.get("completed_chunks", [])

    def mark_processed(self, chunk_id: str):
        if chunk_id not in self.state["completed_chunks"]:
            self.state["completed_chunks"].append(chunk_id)
            self.checkpoint_path.write_text(json.dumps(self.state, indent=2), encoding='utf-8')


def chunk_file(file_path: Path, max_lines: int = CHUNK_SIZE_LINES) -> List[Dict[str, Any]]:
    """Splits a file into 400-line contextual chunks."""
    chunks = []
    lines = file_path.read_text(encoding='utf-8', errors='ignore').splitlines()
    total_lines = len(lines)
    
    for i in range(0, total_lines, max_lines):
        chunk_lines = lines[i:i + max_lines]
        chunk_id = f"{file_path.resolve()}::chunk_{i // max_lines + 1}"
        chunks.append({
            "chunk_id": chunk_id,
            "start_line": i + 1,
            "end_line": min(i + max_lines, total_lines),
            "content": "\n".join(chunk_lines),
            "file_path": str(file_path)
        })
    return chunks


def analyze_chunk(chunk: Dict[str, Any], iac_type: str) -> List[Dict[str, Any]]:
    """Finds focused IaC security patterns in one chunk."""
    findings = []
    lines = chunk["content"].splitlines()
    framework = detect_framework(chunk, iac_type)
    for offset, line in enumerate(lines):
        for rule in IAC_RULES:
            if re.search(rule["pattern"], line, re.IGNORECASE):
                findings.append({
                    "title": rule["title"],
                    "severity": rule["severity"],
                    "iac_type": framework,
                    "file": str(Path(chunk["file_path"]).resolve()),
                    "line": chunk["start_line"] + offset,
                    "vulnerable_code": line.strip(),
                    "standard": rule["standard"],
                    "description": rule["description"],
                    "remediation": rule["remediation"],
                    "recommended_solution": recommended_solution(rule, framework, line),
                    "references": framework_references(framework),
                })
    return findings


def detect_framework(chunk: Dict[str, Any], iac_type: str) -> str:
    """Refines Terraform detection using path and provider content."""
    if iac_type != "Terraform":
        return iac_type
    source = f"{chunk['file_path']}\n{chunk['content']}".lower()
    if 'google_' in source or '/gcp/' in source:
        return "GCP Terraform"
    if 'azurerm_' in source or '/azure/' in source:
        return "Azure Terraform"
    if 'aws_' in source or '/aws/' in source:
        return "AWS Terraform"
    return iac_type


def framework_references(iac_type: str) -> List[str]:
    """Returns only references relevant to the detected IaC framework."""
    return FRAMEWORK_REFERENCES.get(iac_type, [])


def recommended_solution(rule: Dict[str, Any], framework: str, line: str) -> str:
    """Returns a copy-paste replacement in the detected IaC syntax."""
    title = rule["title"]
    if title == "Unrestricted Network Ingress":
        if framework == "Azure ARM Template":
            return '"sourceAddressPrefix": "10.0.0.0/16"'
        if framework == "Azure Bicep":
            return "sourceAddressPrefix: '10.0.0.0/16'"
        if framework == "GCP Terraform":
            if re.search(r"\bsource_ranges\b", line):
                return 'source_ranges = ["10.0.0.0/16"]'
            return 'value = "10.0.0.0/16"'
    if title == "Publicly Exposed Resource" and framework.startswith("Azure"):
        return 'publicNetworkAccess: "Disabled"'
    if title == "Public Cloud Storage Access" and framework == "GCP Terraform":
        return 'uniform_bucket_level_access = true'
    if title == "Storage Encryption Not Configured" and framework == "GCP Terraform":
        return 'default_kms_key_name = google_kms_crypto_key.storage.id'
    return rule["fix_template"]


def _pdf_escape(value: str) -> str:
    """Escapes text for a PDF literal string using only ASCII-safe output."""
    value = value.encode('ascii', 'replace').decode('ascii')
    return value.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')


def _pdf_content(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Builds styled PDF rows matching the HTML report hierarchy."""
    frameworks = sorted({item["iac_type"] for item in findings})
    counts = {severity: sum(item["severity"] == severity for item in findings) for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    content = [
        {"text": "Agentic IaC Security Scan Report", "style": "title"},
        {"text": f"LLM Module: {SCANNER_MODEL}", "style": "meta"},
        {"text": f"Detected IaC Languages: {', '.join(frameworks) or 'None'}", "style": "meta"},
        {"text": f"Total Findings: {len(findings)}", "style": "meta"},
        {"text": "Executive Summary", "style": "heading"},
        {"text": "Severity                         Identified Findings", "style": "table_header"},
    ]
    content.extend({"text": f"{severity:<30} {counts[severity]}", "style": severity.lower()} for severity in counts)
    content.append({"text": "Detailed Findings (sorted Critical to Low)", "style": "heading"})
    for index, finding in enumerate(findings, 1):
        content.extend([
            {"text": f"{index}. {finding['severity']} - {finding['title']}", "style": finding['severity'].lower()},
            {"text": f"IaC Language: {finding['iac_type']}", "style": "label"},
            {"text": f"Full Path: {finding['file']}:{finding['line']}", "style": "body"},
            {"text": f"Description: {finding['description']}", "style": "body"},
            {"text": f"Standard: {finding['standard']}", "style": "body"},
            {"text": f"Vulnerable Code: {finding['vulnerable_code']}", "style": "code"},
            {"text": f"Recommended solution: {finding['recommended_solution']}", "style": "fix"},
            {"text": "References:", "style": "label"},
        ])
        content.extend({"text": f"- {reference}", "style": "reference"} for reference in finding['references'])
        content.append({"text": "", "style": "body"})
    return content


def _pdf_wrap_rows(content: List[Dict[str, Any]], width: int = 92) -> List[Dict[str, Any]]:
    rows = []
    for item in content:
        text = item["text"]
        if not text:
            rows.append(item)
            continue
        while len(text) > width:
            rows.append({"text": text[:width], "style": item["style"]})
            text = text[width:]
        rows.append({"text": text, "style": item["style"]})
    return rows


def generate_pdf_report(findings: List[Dict[str, Any]], output_path: Path) -> None:
    """Writes a simple valid PDF using only the Python standard library."""
    lines = _pdf_wrap_rows(_pdf_content(findings))
    pages = [lines[index:index + 52] for index in range(0, len(lines), 52)] or [[]]
    objects = []
    objects.append("<< /Type /Catalog /Pages 2 0 R >>")
    page_ids = []
    next_id = 3
    page_data = []
    for page_lines in pages:
        page_id = next_id
        content_id = next_id + 1
        urls = []
        for line_index, item in enumerate(page_lines):
            urls.extend((line_index, match.group(0)) for match in re.finditer(r"https?://\S+", item["text"]))
        annotation_ids = list(range(next_id + 2, next_id + 2 + len(urls)))
        page_data.append((page_id, content_id, page_lines, urls, annotation_ids))
        page_ids.append(page_id)
        next_id += 2 + len(urls)
    font_id = next_id
    for page_id, content_id, page_lines, urls, annotation_ids in page_data:
        stream_lines = []
        y = 750
        for line_index, item in enumerate(page_lines):
            style = item["style"]
            if style == "title":
                size, color = 18, "0.10 0.16 0.24"
            elif style == "heading":
                size, color = 13, "0.10 0.16 0.24"
            elif style == "table_header":
                size, color = 10, "0.10 0.16 0.24"
            elif style == "critical":
                size, color = 10, "0.86 0.15 0.15"
            elif style == "high":
                size, color = 10, "0.92 0.35 0.05"
            elif style == "medium":
                size, color = 10, "0.70 0.38 0.02"
            elif style == "low":
                size, color = 10, "0.10 0.35 0.75"
            elif style == "code":
                size, color = 9, "0.10 0.10 0.10"
            elif style == "fix":
                size, color = 9, "0.05 0.40 0.20"
            else:
                size, color = 9, "0.15 0.18 0.22"
            stream_lines.extend(["BT", f"/F1 {size} Tf", f"{color} rg", f"42 {y} Td", f"({_pdf_escape(item['text'])}) Tj", "ET"])
            y -= 14 if size <= 10 else 20
        stream_lines.append("ET")
        stream = "\n".join(stream_lines).encode('ascii')
        annots = f" /Annots [{' '.join(f'{annotation_id} 0 R' for annotation_id in annotation_ids)}]" if annotation_ids else ""
        objects.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {content_id} 0 R{annots} >>")
        objects.append(f"<< /Length {len(stream)} >>\nstream\n{stream.decode('ascii')}\nendstream")
        for annotation_id, (line_index, url) in zip(annotation_ids, urls):
            top = 762 - line_index * 12
            bottom = top - 10
            objects.append(f"<< /Type /Annot /Subtype /Link /Rect [42 {bottom} 570 {top}] /Border [0 0 0] /A << /S /URI /URI ({_pdf_escape(url)}) >> >>")
    objects.append(f"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    pages_object = f"<< /Type /Pages /Kids [{ ' '.join(f'{page_id} 0 R' for page_id in page_ids) }] /Count {len(page_ids)} >>"
    objects.insert(1, pages_object)

    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for object_id, content in enumerate(objects, 1):
        offsets.append(len(pdf))
        pdf.extend(f"{object_id} 0 obj\n{content}\nendobj\n".encode('ascii'))
    xref = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode('ascii'))
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode('ascii'))
    pdf.extend(f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode('ascii'))
    output_path.write_bytes(pdf)


def cleanup_previous_reports() -> None:
    """Deletes prior standardized reports from the current folder."""
    for report_name in REPORT_FILES:
        report_path = Path.cwd() / report_name
        if report_path.exists():
            report_path.unlink()
            print(f"[+] Removed previous report: {report_path}")


def cleanup_checkpoint(target_dir: Path) -> None:
    """Starts each scan without stale checkpoint state."""
    checkpoint_path = target_dir / CHECKPOINT_FILE
    if checkpoint_path.exists():
        checkpoint_path.unlink()
        print(f"[+] Removed previous checkpoint: {checkpoint_path}")


def generate_reports(findings: List[Dict[str, Any]], output_dir: Path, report_format: str, debug: bool):
    """Generates only the requested report plus the mandatory PDF."""
    output_dir.mkdir(parents=True, exist_ok=True)
    ordered = sorted(findings, key=lambda item: (SEVERITY_ORDER.get(item['severity'], 99), item['file'], item['line']))
    frameworks = sorted({item["iac_type"] for item in ordered})
    report_metadata = {
        "scanner_model": SCANNER_MODEL,
        "detected_iac_languages": frameworks,
        "report_basename": REPORT_BASENAME,
    }

    if debug:
        (output_dir / "findings.json").write_text(json.dumps(ordered, indent=2), encoding='utf-8')

    frameworks = sorted({item["iac_type"] for item in ordered})
    severity_counts = {severity: sum(item["severity"] == severity for item in ordered) for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    md_content = "# Agentic IaC Security Scan Summary\n\n"
    md_content += f"**LLM Module:** {SCANNER_MODEL}\n\n"
    md_content += f"**Detected IaC Languages:** {', '.join(frameworks) or 'None'}\n\n"
    md_content += f"**Total Findings:** {len(ordered)}\n\n"
    md_content += "| Severity | Identified Findings |\n|---|---:|\n"
    md_content += ''.join(f"| {severity} | {severity_counts[severity]} |\n" for severity in severity_counts)
    md_content += "\n| Severity | Finding | Framework | Full File Path | Line |\n|---|---|---|---|---:|\n"
    for f in ordered:
        md_content += f"| {f.get('severity')} | {f.get('title')} | {f.get('iac_type')} | `{f.get('file')}` | {f.get('line')} |\n"
        md_content += f"\n**Description:** {f.get('description')}\n\n**Vulnerable Code:**\n```text\n{f.get('vulnerable_code')}\n```\n\n**Recommended solution:**\n```text\n{f.get('recommended_solution')}\n```\n\n**References:**\n\n" + ''.join(f"- {reference}\n" for reference in f.get('references', [])) + "\n"
    html_content = f"""<!DOCTYPE html>
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; max-width: 100%; overflow-x: hidden; }}
            h1 {{ color: #1a202c; }}
            table {{ width: 100%; table-layout: fixed; border-collapse: collapse; margin-top: 20px; }}
            th, td {{ border: 1px solid #cbd5e1; padding: 10px; text-align: left; overflow-wrap: anywhere; word-break: break-word; vertical-align: top; }}
            th {{ background-color: #f1f5f9; }}
            .CRITICAL {{ color: #dc2626; font-weight: bold; }}
            .HIGH {{ color: #ea580c; font-weight: bold; }}
            .MEDIUM {{ color: #d97706; }}
            .LOW {{ color: #2563eb; }} pre {{ white-space: pre-wrap; overflow-wrap: anywhere; }}
        </style>
    </head>
    <body>
        <h1>Agentic IaC Security Scan Report</h1>
        <p><b>LLM Module:</b> {escape(SCANNER_MODEL)}</p>
        <p><b>Detected IaC Languages:</b> {escape(', '.join(frameworks) or 'None')}</p>
        <hr>
        <h2>Executive Summary</h2>
        <table><tr><th>Severity</th><th>Identified Findings</th></tr>{''.join(f'<tr><td class="{severity}">{severity}</td><td>{severity_counts[severity]}</td></tr>' for severity in severity_counts)}</table>
        <h3>Detailed Findings ({len(ordered)})</h3>
        <table>
            <tr>
                <th>Severity</th>
                <th>Rule / Title</th>
                <th>Target Framework</th>
                <th>Full File Path & Line</th>
                <th>Description / Code / Fix / References</th>
            </tr>
            {"".join([f"<tr><td class='{item['severity']}'>{escape(item['severity'])}</td><td><b>{escape(item['title'])}</b><br>{escape(item['standard'])}</td><td>{escape(item['iac_type'])}</td><td><code>{escape(item['file'])}:{item['line']}</code></td><td><b>Description:</b> {escape(item['description'])}<br><b>Vulnerable Code:</b><pre>{escape(item['vulnerable_code'])}</pre><b>Recommended solution:</b><pre>{escape(item['recommended_solution'])}</pre><b>References:</b><ul>{''.join(f'<li><a href=\"{escape(url, quote=True)}\">{escape(url)}</a></li>' for url in item['references'])}</ul></td></tr>" for item in ordered])}
        </table>
    </body>
    </html>
    """
    if report_format == "md":
        (output_dir / f"{REPORT_BASENAME}.md").write_text(md_content, encoding='utf-8')
    elif report_format == "json":
        (output_dir / f"{REPORT_BASENAME}.json").write_text(json.dumps({"metadata": report_metadata, "findings": ordered}, indent=2), encoding='utf-8')
    elif report_format == "sarif":
        sarif = {"version": "2.1.0", "properties": report_metadata, "runs": [{"tool": {"driver": {"name": "Agentic IaC Scanner"}}, "properties": report_metadata, "results": ordered}]}
        (output_dir / f"{REPORT_BASENAME}.sarif").write_text(json.dumps(sarif, indent=2), encoding='utf-8')
    else:
        (output_dir / f"{REPORT_BASENAME}.html").write_text(html_content, encoding='utf-8')

    pdf_path = output_dir / f"{REPORT_BASENAME}.pdf"
    generate_pdf_report(ordered, pdf_path)
    print(f"[+] PDF Report generated: {pdf_path}")


def main():
    parser = argparse.ArgumentParser(description="Agentic IaC Security Scanner")
    parser.add_argument("-d", "--directory", default=".", help="Target directory containing IaC files (default: current directory)")
    parser.add_argument("-f", "--format", choices=sorted(SUPPORTED_FORMATS), default="html", help="Requested report format (default: html)")
    parser.add_argument("--debug", action="store_true", help="Keep .iac_checkpoint.json after a successful scan")
    args = parser.parse_args()

    cleanup_previous_reports()
    target_dir = Path(args.directory)
    cleanup_checkpoint(target_dir)
    output_dir = Path.cwd()
    
    checkpoint_mgr = CheckpointManager(target_dir)
    findings = []

    print(f"[*] Starting Agentic IaC Security Scan in: {target_dir}")

    for root, _, files in os.walk(target_dir):
        for file in files:
            file_path = Path(root) / file
            iac_type = IaCDetector.identify_type(file_path)
            
            if iac_type == "Unknown":
                continue

            print(f"[+] Found {iac_type} template: {file_path.relative_to(target_dir)}")
            chunks = chunk_file(file_path)

            for chunk in chunks:
                if checkpoint_mgr.is_processed(chunk["chunk_id"]):
                    print(f"  [➜] Skipping already processed chunk: {chunk['chunk_id']}")
                    continue

                print(f"  [⚡] Scanning {chunk['chunk_id']} (Lines {chunk['start_line']}-{chunk['end_line']})...")
                
                findings.extend(analyze_chunk(chunk, iac_type))
                checkpoint_mgr.mark_processed(chunk["chunk_id"])

    # Generate output artifacts
    generate_reports(findings, output_dir, args.format, args.debug)
    if not args.debug and checkpoint_mgr.checkpoint_path.exists():
        checkpoint_mgr.checkpoint_path.unlink()
        print(f"[+] Removed checkpoint: {checkpoint_mgr.checkpoint_path}")
    print(f"[✔] Scan complete. Reports saved to {output_dir.resolve()}")

if __name__ == "__main__":
    main()
