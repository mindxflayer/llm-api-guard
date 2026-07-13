import os
import json
import tempfile
from unittest.mock import patch
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

def test_write_html_report():
    findings = [
        Finding("r1", "critical", "m1", "l1", owasp_ref="A1"),
        Finding("r2", "high", "m2", "l2", suppressed=True, owasp_ref="A2")
    ]
    fd, path = tempfile.mkstemp(suffix=".html")
    try:
        os.close(fd)
        from scanner.report import write_html_report
        write_html_report(findings, path, baseline_used=True, baselined_count=1)
        with open(path, "r", encoding="utf-8") as f:
            html = f.read()
            
        assert "Security Scan Report" in html
        assert "r1" in html
        assert "critical" in html
        assert "r2" in html
        assert "suppressed-badge" in html or "finding-row-suppressed" in html
        assert "1 new, 1 baselined" in html
    finally:
        os.remove(path)

def test_cli_format_option():
    findings = [Finding("r1", "medium", "m1", "l1")]
    
    class FakeArgs:
        config = "dummy_config"
        repo = "dummy_repo"
        output = "test_output.json"
        baseline = None
        save_baseline = None
        format = "html"
        fail_on = None
        fail_on_new = False
        
    from cli import run_repo_scan
    
    with patch("cli.load_config", return_value={"checks": {}, "severity_threshold": "low"}), \
         patch("cli.PluginLoader.load_plugins", return_value=[]), \
         patch("cli.Runner.run", return_value=findings), \
         patch("cli.write_html_report") as mock_write_html:
        
        run_repo_scan(FakeArgs())
        mock_write_html.assert_called_once_with(findings, "test_output.html", baseline_used=False, baselined_count=0)
