import os
import pytest
import tempfile
import shutil
from scanner.core import Finding, load_config, filter_findings_by_severity, Runner
from scanner.static.unsafe_output_exec import UnsafeOutputExec

def test_load_config_valid():
    content = """
target_type: repo
checks:
  hardcoded_keys: true
  unsafe_output_exec: false
severity_threshold: high
"""
    fd, path = tempfile.mkstemp(suffix=".yaml")
    try:
        os.write(fd, content.encode('utf-8'))
        os.close(fd)
        cfg = load_config(path)
        assert cfg["target_type"] == "repo"
        assert cfg["checks"]["hardcoded_keys"] is True
        assert cfg["checks"]["unsafe_output_exec"] is False
        assert cfg["severity_threshold"] == "high"
    finally:
        os.remove(path)

def test_load_config_invalid():
    fd, path = tempfile.mkstemp(suffix=".yaml")
    try:
        content1 = """
target_type: repo
checks:
  hardcoded_keys: true
"""
        os.write(fd, content1.encode('utf-8'))
        os.close(fd)
        with pytest.raises(ValueError):
            load_config(path)
    finally:
        os.remove(path)

    fd, path = tempfile.mkstemp(suffix=".yaml")
    try:
        content2 = """
target_type: repo
checks:
  hardcoded_keys: true
severity_threshold: extreme
"""
        os.write(fd, content2.encode('utf-8'))
        os.close(fd)
        with pytest.raises(ValueError):
            load_config(path)
    finally:
        os.remove(path)

    fd, path = tempfile.mkstemp(suffix=".yaml")
    try:
        content3 = """
target_type: repo
checks: true
severity_threshold: low
"""
        os.write(fd, content3.encode('utf-8'))
        os.close(fd)
        with pytest.raises(ValueError):
            load_config(path)
    finally:
        os.remove(path)

def test_filter_findings_by_severity():
    f_low = Finding("r1", "low", "m1", "l1")
    f_med = Finding("r2", "medium", "m2", "l2")
    f_high = Finding("r3", "high", "m3", "l3")
    f_crit = Finding("r4", "critical", "m4", "l4")
    
    findings = [f_low, f_med, f_high, f_crit]
    
    res = filter_findings_by_severity(findings, "high")
    assert len(res) == 2
    assert f_high in res
    assert f_crit in res
    assert f_low not in res
    assert f_med not in res
    
    res_crit = filter_findings_by_severity(findings, "critical")
    assert len(res_crit) == 1
    assert f_crit in res_crit

def test_runner_disable_plugin_by_config():
    plugin = UnsafeOutputExec()
    temp_bad = tempfile.mkdtemp()
    try:
        shutil.copy(os.path.join("tests", "samples", "unsafe_output_exec", "bad.py"), os.path.join(temp_bad, "bad.py"))
        
        config = {
            "target_type": "repo",
            "checks": {
                "unsafe_output_exec": False
            },
            "severity_threshold": "low"
        }
        runner = Runner([plugin], config=config)
        findings = runner.run(temp_bad)
        assert len(findings) == 0
    finally:
        shutil.rmtree(temp_bad)
