import os
import shutil
import tempfile
import pytest
from scanner.core import Finding, Runner, Plugin
from scanner.dedup import deduplicate_findings

def test_dedup_same_location_different_methods():
    f1 = Finding(
        rule="hardcoded_keys",
        severity="medium",
        message="Found AWS API Key prefix",
        location="src/auth.py:10",
        owasp_ref="LLM10",
        detection_method="regex",
        confidence=90
    )
    f2 = Finding(
        rule="hardcoded_keys",
        severity="high",
        message="Entropy score 82",
        location="src/auth.py:10",
        owasp_ref="LLM10",
        detection_method="entropy",
        confidence=55
    )
    merged = deduplicate_findings([f1, f2])
    assert len(merged) == 1
    m = merged[0]
    assert m.severity == "high"
    assert m.confidence == 90
    assert "regex" in m.message
    assert "entropy" in m.message
    assert "Found AWS API Key prefix" in m.message
    assert "Entropy score 82" in m.message

def test_dedup_different_locations_no_merge():
    f1 = Finding(
        rule="hardcoded_keys",
        severity="medium",
        message="Found AWS API Key prefix",
        location="src/auth.py:10",
        owasp_ref="LLM10",
        detection_method="regex",
        confidence=90
    )
    f2 = Finding(
        rule="hardcoded_keys",
        severity="high",
        message="Entropy score 82",
        location="src/auth.py:20",
        owasp_ref="LLM10",
        detection_method="entropy",
        confidence=55
    )
    merged = deduplicate_findings([f1, f2])
    assert len(merged) == 2

def test_dedup_overlapping_ranges():
    f1 = Finding(
        rule="hardcoded_keys",
        severity="low",
        message="m1",
        location="src/auth.py:10-15",
        owasp_ref="LLM10",
        detection_method="regex",
        confidence=30
    )
    f2 = Finding(
        rule="hardcoded_keys",
        severity="high",
        message="m2",
        location="src/auth.py:12-20",
        owasp_ref="LLM10",
        detection_method="entropy",
        confidence=80
    )
    merged = deduplicate_findings([f1, f2])
    assert len(merged) == 1
    assert merged[0].severity == "high"
    assert merged[0].confidence == 80

def test_runner_dedup_end_to_end():
    from scanner.static.hardcoded_keys import HardcodedKeys
    
    class MockEntropyPlugin(Plugin):
        name = "mock_entropy"
        severity = "medium"
        owasp_ref = "LLM06"
        def run(self, target) -> list[Finding]:
            return [Finding(
                rule="entropy_secret",
                severity="high",
                message="Potential secret detected with high entropy",
                location="bad.py:1",
                detection_method="entropy",
                owasp_ref="LLM06"
            )]

    plugin = HardcodedKeys()
    temp_dir = tempfile.mkdtemp()
    try:
        code = 'aws_key = "AKIA1234567890BCDEFY"\n'
        with open(os.path.join(temp_dir, "bad.py"), "w", encoding="utf-8") as f:
            f.write(code)
            
        config = {
            "severity_threshold": "low",
            "checks": {
                "hardcoded_keys": True,
                "mock_entropy": True
            },
            "live_checks": {},
            "secret_detection": {
                "entropy_threshold": 30,
                "min_rules": 10
            },
            "confidence_defaults": {
                "regex": 90,
                "entropy": 55,
                "ruleset": 85,
                "static_heuristic": 60
            }
        }
        
        runner = Runner([plugin, MockEntropyPlugin()], config=config)
        findings = runner.run(temp_dir)
        
        assert len(findings) == 1
        f = findings[0]
        assert "regex" in f.message
        assert "entropy" in f.message
        assert f.confidence == 90
        assert f.severity == "critical"
    finally:
        shutil.rmtree(temp_dir)

