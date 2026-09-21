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
REPORT_FILES = {f"{REPORT_BASENAME}.{suffix}" for suffix in (*SUPPORTED_FORMATS, "pdf")}

IAC_RULES = [
    {
        "title": "Unrestricted Network Ingress",
        "severity": "CRITICAL",
        "pattern": r"0\.0\.0\.0/0|::/0",
        "standard": "CIS / Least Privilege",
        "remediation": "Restrict the source range to approved CIDRs instead of the entire internet.",
    },
    {
        "title": "Wildcard IAM Permission",
        "severity": "HIGH",
        "pattern": r'"Action"\s*:\s*"\*"|actions\s*=\s*\[?\s*"\*"',
        "standard": "CIS / Least Privilege",
        "remediation": "Replace wildcard actions with the smallest set of required actions.",
    },
    {
        "title": "Public Cloud Storage Access",
        "severity": "HIGH",
        "pattern": r"public-read|public-read-write|allUsers|\*\s*=\s*\[?\s*\"storage\.objects",
        "standard": "CIS / Data Protection",
        "remediation": "Remove public access and grant access only to authenticated principals.",
    },
    {
        "title": "Storage Encryption Not Configured",
        "severity": "MEDIUM",
        "pattern": r"encrypt(?:ion)?\s*=\s*(?:false|disabled)|encrypted\s*:\s*false",
        "standard": "CIS / Data Protection",
        "remediation": "Enable encryption at rest using the cloud provider's managed or customer-managed key.",
    },
    {
        "title": "Publicly Exposed Resource",
        "severity": "HIGH",
        "pattern": r"public_network_access\s*=\s*['\"]?Enabled|publicNetworkAccess\s*:\s*['\"]?Enabled",
        "standard": "Cloud Well-Architected Security Pillar",
        "remediation": "Disable public network access and use private endpoints or approved network controls.",
    },
]


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
        chunk_id = f"{file_path.name}::chunk_{i // max_lines + 1}"
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
    for offset, line in enumerate(lines):
        for rule in IAC_RULES:
            if re.search(rule["pattern"], line, re.IGNORECASE):
                findings.append({
                    "title": rule["title"],
                    "severity": rule["severity"],
                    "iac_type": iac_type,
                    "file": str(Path(chunk["file_path"]).resolve()),
                    "line": chunk["start_line"] + offset,
                    "vulnerable_code": line.strip(),
                    "standard": rule["standard"],
                    "remediation": rule["remediation"],
                })
    return findings


def _pdf_escape(value: str) -> str:
    """Escapes text for a PDF literal string using only ASCII-safe output."""
    value = value.encode('ascii', 'replace').decode('ascii')
    return value.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')


def _pdf_lines(findings: List[Dict[str, Any]]) -> List[str]:
    lines = [
        "Agentic IaC Security Scan Report",
        f"Total Findings: {len(findings)}",
        "",
    ]
    for index, finding in enumerate(findings, 1):
        lines.extend([
            f"{index}. {finding['severity']} - {finding['title']}",
            f"Framework: {finding['iac_type']}",
            f"Location: {finding['file']}:{finding['line']}",
            f"Standard: {finding['standard']}",
            f"Code: {finding['vulnerable_code']}",
            f"Fix: {finding['remediation']}",
            "",
        ])
    wrapped = []
    for line in lines:
        while len(line) > 95:
            wrapped.append(line[:95])
            line = line[95:]
        wrapped.append(line)
    return wrapped


def generate_pdf_report(findings: List[Dict[str, Any]], output_path: Path) -> None:
    """Writes a simple valid PDF using only the Python standard library."""
    lines = _pdf_lines(findings)
    pages = [lines[index:index + 52] for index in range(0, len(lines), 52)] or [[]]
    objects = []
    objects.append("<< /Type /Catalog /Pages 2 0 R >>")
    page_ids = []
    next_id = 3
    for page_lines in pages:
        page_id = next_id
        content_id = next_id + 1
        page_ids.append(page_id)
        next_id += 2
        stream_lines = ["BT", "/F1 9 Tf", "42 750 Td", "12 TL"]
        for line in page_lines:
            stream_lines.append(f"({_pdf_escape(line)}) Tj T*" )
        stream_lines.append("ET")
        stream = "\n".join(stream_lines).encode('ascii')
        objects.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 {3 + len(pages) * 2} 0 R >> >> /Contents {content_id} 0 R >>")
        objects.append(f"<< /Length {len(stream)} >>\nstream\n{stream.decode('ascii')}\nendstream")
    font_id = next_id + len(pages) * 2
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


def generate_reports(findings: List[Dict[str, Any]], output_dir: Path, report_format: str, debug: bool):
    """Generates only the requested report plus the mandatory PDF."""
    output_dir.mkdir(parents=True, exist_ok=True)
    ordered = sorted(findings, key=lambda item: (SEVERITY_ORDER.get(item['severity'], 99), item['file'], item['line']))

    if debug:
        (output_dir / "findings.json").write_text(json.dumps(ordered, indent=2), encoding='utf-8')

    md_content = "# Agentic IaC Security Scan Summary\n\n"
    md_content += f"**Total Findings:** {len(ordered)}\n\n"
    md_content += "| Severity | Finding | Framework | File | Line |\n|---|---|---|---|---|\n"
    for f in ordered:
        md_content += f"| {f.get('severity')} | {f.get('title')} | {f.get('framework')} | `{f.get('file')}` | {f.get('line')} |\n"
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
        <p>Generated automatically by Agentic IaC Scanner Skill</p>
        <hr>
        <h3>Detailed Findings ({len(ordered)})</h3>
        <table>
            <tr>
                <th>Severity</th>
                <th>Rule / Title</th>
                <th>Target Framework</th>
                <th>File & Range</th>
                <th>Standard Mapping</th>
            </tr>
            {"".join([f"<tr><td class='{item['severity']}'>{escape(item['severity'])}</td><td>{escape(item['title'])}<br><small>{escape(item['remediation'])}</small></td><td>{escape(item['iac_type'])}</td><td><code>{escape(item['file'])}:{item['line']}</code><br><pre>{escape(item['vulnerable_code'])}</pre></td><td>{escape(item['standard'])}</td></tr>" for item in ordered])}
        </table>
    </body>
    </html>
    """
    if report_format == "md":
        (output_dir / f"{REPORT_BASENAME}.md").write_text(md_content, encoding='utf-8')
    elif report_format == "json":
        (output_dir / f"{REPORT_BASENAME}.json").write_text(json.dumps(ordered, indent=2), encoding='utf-8')
    elif report_format == "sarif":
        sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Agentic IaC Scanner"}}, "results": ordered}]}
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
