import os
import json
from scanner.core import Finding

def load_baseline(path: str) -> set[tuple[str, str]]:
    if not path or not os.path.exists(path):
        return set()
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception:
        return set()
        
    if not isinstance(data, list):
        return set()
        
    baseline = set()
    for item in data:
        if isinstance(item, dict) and "rule" in item and "location" in item:
            baseline.add((item["rule"], item["location"]))
    return baseline

def save_baseline(findings: list[Finding], path: str) -> None:
    data = []
    for f in findings:
        data.append({
            "rule": f.rule,
            "severity": f.severity,
            "message": f.message,
            "location": f.location,
            "suppressed": f.suppressed
        })
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

def filter_new_findings(findings: list[Finding], baseline: set[tuple[str, str]]) -> list[Finding]:
    return [f for f in findings if (f.rule, f.location) not in baseline]

def check_inline_suppression(finding: Finding, target: str) -> bool:
    if not isinstance(target, str) or not os.path.exists(target):
        return False
        
    parts = finding.location.rsplit(':', 1)
    if len(parts) != 2:
        return False
        
    rel_path, line_str = parts
    if not line_str.isdigit():
        return False
        
    line_num = int(line_str)
    
    possible_paths = [rel_path]
    if not os.path.isabs(rel_path):
        possible_paths.append(os.path.join(target, rel_path))
        possible_paths.append(os.path.abspath(os.path.join(target, rel_path)))
        
    filepath = None
    for p in possible_paths:
        if os.path.isfile(p):
            filepath = p
            break
            
    if not filepath:
        return False
        
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception:
        return False
        
    if line_num < 1 or line_num > len(lines):
        return False
        
    lines_to_check = [lines[line_num - 1]]
    if line_num > 1:
        prev_line = lines[line_num - 2].strip()
        if prev_line.startswith("#"):
            lines_to_check.append(lines[line_num - 2])
        
    for line in lines_to_check:
        line_clean = line.strip()
        if "#" in line_clean:
            comment = line_clean.split("#", 1)[1].strip().lower()
            if comment.startswith("scanner: ignore"):
                rule_part = comment[len("scanner: ignore"):].strip()
                if not rule_part or rule_part == finding.rule.lower():
                    return True
                    
    return False
