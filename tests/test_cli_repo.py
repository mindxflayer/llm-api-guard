import os
import json
import tempfile
from cli import run_repo_scan

def test_repo_scan_cli_logic():
    fd, config_path = tempfile.mkstemp(suffix=".yaml")
    try:
        os.write(fd, b"""
target_type: repo
checks:
  hardcoded_keys: true
  unsafe_output_exec: true
live_checks:
  rate_limit_check: true
severity_threshold: low
""")
        os.close(fd)
        
        fd_out, output_path = tempfile.mkstemp(suffix=".json")
        os.close(fd_out)
        
        class Args:
            repo = os.path.join("tests", "samples", "hardcoded_keys")
            config = config_path
            output = output_path
            
        run_repo_scan(Args())
        
        assert os.path.exists(output_path)
        with open(output_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        assert data["summary"]["total"] >= 1
        assert len(data["findings"]) >= 1
        rules = [f["rule"] for f in data["findings"]]
        assert "openai_key" in rules or "aws_key" in rules or "bearer_token" in rules
    finally:
        if os.path.exists(config_path):
            os.remove(config_path)
        if os.path.exists(output_path):
            os.remove(output_path)
