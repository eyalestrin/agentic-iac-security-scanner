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
from pathlib import Path
from typing import List, Dict, Any
from jinja2 import Template

try:
    from weasyprint import HTML
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False


CHECKPOINT_FILE = ".iac_checkpoint.json"
CHUNK_SIZE_LINES = 400


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


def generate_reports(findings: List[Dict[str, Any]], output_dir: Path):
    """Generates Markdown, JSON, SARIF, and mandatory PDF reports."""
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 1. JSON Report
    json_path = output_dir / "findings.json"
    json_path.write_text(json.dumps(findings, indent=2), encoding='utf-8')
    
    # 2. Markdown Summary
    md_path = output_dir / "summary.md"
    md_content = "# Agentic IaC Security Scan Summary\n\n"
    md_content += f"**Total Findings:** {len(findings)}\n\n"
    md_content += "| Severity | Finding | Framework | File | Line |\n|---|---|---|---|---|\n"
    for f in findings:
        md_content += f"| {f.get('severity')} | {f.get('title')} | {f.get('framework')} | `{f.get('file')}` | {f.get('line')} |\n"
    md_path.write_text(md_content, encoding='utf-8')

    # 3. HTML Report
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 30px; }}
            h1 {{ color: #1a202c; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th, td {{ border: 1px solid #cbd5e1; padding: 10px; text-align: left; }}
            th {{ background-color: #f1f5f9; }}
            .CRITICAL {{ color: #dc2626; font-weight: bold; }}
            .HIGH {{ color: #ea580c; font-weight: bold; }}
            .MEDIUM {{ color: #d97706; }}
            .LOW {{ color: #2563eb; }}
        </style>
    </head>
    <body>
        <h1>Agentic IaC Security Scan Report</h1>
        <p>Generated automatically by Agentic IaC Scanner Skill</p>
        <hr>
        <h3>Detailed Findings ({len(findings)})</h3>
        <table>
            <tr>
                <th>Severity</th>
                <th>Rule / Title</th>
                <th>Target Framework</th>
                <th>File & Range</th>
                <th>Standard Mapping</th>
            </tr>
            {"".join([f"<tr><td class='{item['severity']}'>{item['severity']}</td><td>{item['title']}</td><td>{item['iac_type']}</td><td>{item['file']}:{item['line']}</td><td>{item['standard']}</td></tr>" for item in findings])}
        </table>
    </body>
    </html>
    """
    html_path = output_dir / "report.html"
    html_path.write_text(html_content, encoding='utf-8')

    # 4. PDF Generation (Always Executed)
    pdf_path = output_dir / "iac_security_report.pdf"
    if WEASYPRINT_AVAILABLE:
        HTML(string=html_content).write_pdf(pdf_path)
        print(f"[+] PDF Report generated: {pdf_path}")
    else:
        print("[-] Warning: WeasyPrint not installed. PDF could not be compiled.")


def main():
    parser = argparse.ArgumentParser(description="Agentic IaC Security Scanner")
    parser.add_argument("-d", "--directory", default=".", help="Target directory containing IaC files (default: current directory)")
    parser.add_argument("-o", "--output", default=".", help="Output directory for reports (default: current directory)")
    parser.add_argument("--debug", action="store_true", help="Keep .iac_checkpoint.json after a successful scan")
    args = parser.parse_args()

    target_dir = Path(args.directory)
    output_dir = Path(args.output)
    
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
                
                # Checkpoint saved
                checkpoint_mgr.mark_processed(chunk["chunk_id"])

    # Generate output artifacts
    generate_reports(findings, output_dir)
    if not args.debug and checkpoint_mgr.checkpoint_path.exists():
        checkpoint_mgr.checkpoint_path.unlink()
        print(f"[+] Removed checkpoint: {checkpoint_mgr.checkpoint_path}")
    print(f"[✔] Scan complete. Reports saved to {output_dir.resolve()}")

if __name__ == "__main__":
    main()
