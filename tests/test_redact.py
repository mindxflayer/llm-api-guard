import os
import shutil
import tempfile
from scanner.core import Runner, Finding
from scanner.static.hardcoded_keys import HardcodedKeys
from scanner.redact import redact_secret, redact_finding

def test_redact_secret_direct():
    secret_1 = "sk-abcdefghijklmnopqrstuvwxyz0123456789"
    secret_2 = "AKIA1234567890123456"
    secret_3 = "abc"
    
    redacted_1 = redact_secret(secret_1)
    redacted_2 = redact_secret(secret_2)
    redacted_3 = redact_secret(secret_3)
    
    assert secret_1 not in redacted_1
    assert secret_2 not in redacted_2
    assert secret_3 not in redacted_3
    
    assert redacted_1.startswith("sk-")
    assert redacted_1.endswith("789")
    assert redacted_2.startswith("AKI")
    assert redacted_2.endswith("3456")
    assert redacted_3 == "***"

def test_redact_finding_direct():
    f = Finding(
        rule="dummy_rule",
        severity="high",
        message="Vulnerability found with secret sk-1234567890abcdefghijklmnopqrst",
        location="file.py:10",
        suppressed=False
    )
    redacted_f = redact_finding(f)
    
    assert "sk-1234567890abcdefghijklmnopqrst" not in redacted_f.message
    assert "Vulnerability found with secret" in redacted_f.message
    assert redacted_f.message.endswith("qrst")

def test_runner_redaction_integration():
    plugin = HardcodedKeys()
    temp_bad = tempfile.mkdtemp()
    try:
        shutil.copy(os.path.join("tests", "samples", "hardcoded_keys", "bad.py"), os.path.join(temp_bad, "bad.py"))
        runner = Runner([plugin])
        findings = runner.run(temp_bad)
        assert len(findings) >= 3
        for finding in findings:
            assert "sk-abcdefghijklmnopqrstuvwxyz0123456789" not in finding.message
            assert "AKIA1234567890123456" not in finding.message
            assert "token-123456789-abcdefg-xyz" not in finding.message
    finally:
        shutil.rmtree(temp_bad)
