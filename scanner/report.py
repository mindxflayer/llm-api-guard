import json
from dataclasses import asdict
from scanner.core import Finding

def write_json_report(findings: list[Finding], output_path: str) -> None:
    summary = {
        "total": len(findings),
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
    }
    serialized_findings = []
    for f in findings:
        severity = f.severity.lower()
        summary[severity] = summary.get(severity, 0) + 1
        serialized_findings.append(asdict(f))
        
    report = {
        "summary": summary,
        "findings": serialized_findings
    }
    
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
