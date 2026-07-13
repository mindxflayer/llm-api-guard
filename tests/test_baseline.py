import os
import json
import pytest
import tempfile
from scanner.core import Finding, Runner, Plugin
from scanner.baseline import (
    load_baseline,
    save_baseline,
    filter_new_findings,
    check_inline_suppression
)

def test_inline_suppression_checking():
    temp_dir = tempfile.mkdtemp()
    filepath = os.path.join(temp_dir, "code.py")
    
    content = """def process():
    key = "sk-12345" # scanner: ignore openai_key
    other = "abc"
    # scanner: ignore bearer_token
    token = "xyz"
    unmarked = "test"
"""
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
        
    rel_path = os.path.relpath(filepath, temp_dir)
    
    f1 = Finding(rule="openai_key", severity="critical", message="leak", location=f"{rel_path}:2")
    f2 = Finding(rule="bearer_token", severity="critical", message="leak", location=f"{rel_path}:5")
    f3 = Finding(rule="bearer_token", severity="critical", message="leak", location=f"{rel_path}:6")
    
    assert check_inline_suppression(f1, temp_dir) is True
    assert check_inline_suppression(f2, temp_dir) is True
    assert check_inline_suppression(f3, temp_dir) is False
    
    os.remove(filepath)
    os.rmdir(temp_dir)

def test_baseline_io_roundtrip():
    findings = [
        Finding(rule="r1", severity="high", message="m1", location="l1"),
        Finding(rule="r2", severity="low", message="m2", location="l2")
    ]
    
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    
    try:
        save_baseline(findings, path)
        
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        assert len(data) == 2
        assert data[0]["rule"] == "r1"
        assert data[0]["location"] == "l1"
        
        loaded = load_baseline(path)
        assert len(loaded) == 2
        assert ("r1", "l1") in loaded
        assert ("r2", "l2") in loaded
    finally:
        os.remove(path)

def test_filter_new_findings():
    findings = [
        Finding(rule="r1", severity="high", message="m1", location="l1"),
        Finding(rule="r2", severity="low", message="m2", location="l2"),
        Finding(rule="r3", severity="medium", message="m3", location="l3")
    ]
    
    baseline = {("r1", "l1"), ("r2", "l2")}
    
    new_findings = filter_new_findings(findings, baseline)
    assert len(new_findings) == 1
    assert new_findings[0].rule == "r3"

def test_runner_integration_with_inline_and_baseline():
    temp_dir = tempfile.mkdtemp()
    filepath = os.path.join(temp_dir, "test_file.py")
    
    content = """secret1 = "sk-1234567890" # scanner: ignore openai_key
secret2 = "sk-9876543210"
"""
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
        
    rel_path = os.path.relpath(filepath, temp_dir)
    
    class FakeStaticPlugin(Plugin):
        name = "fake_static"
        def run(self, target: str) -> list[Finding]:
            return [
                Finding(rule="openai_key", severity="critical", message="openai key", location=f"{rel_path}:1"),
                Finding(rule="openai_key", severity="critical", message="openai key", location=f"{rel_path}:2")
            ]
            
    try:
        runner = Runner([FakeStaticPlugin])
        findings = runner.run(temp_dir)
        
        assert len(findings) == 2
        assert findings[0].suppressed is True
        assert findings[1].suppressed is False
    finally:
        os.remove(filepath)
        os.rmdir(temp_dir)
