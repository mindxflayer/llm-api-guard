import os
import json
import tempfile
from scanner.core import Finding
from scanner.report import write_json_report

def test_write_json_report():
    findings = [
        Finding("r1", "critical", "m1", "l1"),
        Finding("r2", "high", "m2", "l2"),
        Finding("r3", "high", "m3", "l3")
    ]
    fd, path = tempfile.mkstemp(suffix=".json")
    try:
        os.close(fd)
        write_json_report(findings, path)
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        assert data["summary"]["total"] == 3
        assert data["summary"]["critical"] == 1
        assert data["summary"]["high"] == 2
        assert data["summary"]["medium"] == 0
        assert data["summary"]["low"] == 0
        
        assert len(data["findings"]) == 3
        assert data["findings"][0]["rule"] == "r1"
        assert data["findings"][1]["severity"] == "high"
    finally:
        os.remove(path)
