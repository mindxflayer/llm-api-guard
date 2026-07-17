import os
import shutil
import tempfile
from scanner.core import Runner, Finding
from scanner.static.hardcoded_keys import HardcodedKeys


def test_openai_and_aws_keys():
    plugin = HardcodedKeys()
    temp_dir = tempfile.mkdtemp()
    try:
        file_path = os.path.join(temp_dir, "code.py")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write('openai_key = "sk-abcdefghijklmnopqrstuvwxyz0123456789"\n')
            f.write('aws_key = "AKIA1234567890123456"\n')
            
        runner = Runner([plugin])
        findings = runner.run(temp_dir)
        
        openai_findings = [f for f in findings if f.rule == "openai_key"]
        aws_findings = [f for f in findings if f.rule == "aws_key"]
        
        assert len(openai_findings) == 1
        assert openai_findings[0].detection_method == "regex"
        
        assert len(aws_findings) == 1
        assert aws_findings[0].detection_method == "regex"
    finally:
        shutil.rmtree(temp_dir)


def test_ruleset_anthropic_key():
    plugin = HardcodedKeys()
    temp_dir = tempfile.mkdtemp()
    try:
        file_path = os.path.join(temp_dir, "code.py")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write('anthropic_key = "sk-ant-api03-ab1cd2ef3gh4ij5kl6mn7op8qr9st0uvwxYZABcDefGhiJkLmNoPqRsTuVwXyZ1234567890-AbCdEfGhIjKlMnOpQrStAA"\n')
            
        runner = Runner([plugin])
        findings = runner.run(temp_dir)
        
        ruleset_findings = [f for f in findings if f.detection_method == "ruleset"]
        assert len(ruleset_findings) == 1
        assert ruleset_findings[0].rule == "anthropic-api-key"
    finally:
        shutil.rmtree(temp_dir)


def test_entropy_high_entropy_token():
    plugin = HardcodedKeys()
    temp_dir = tempfile.mkdtemp()
    try:
        file_path = os.path.join(temp_dir, "code.py")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write('api_token = "aB1c_D2eF3gH4iJ5k#$@*L6mN7oP8qR"\n')
            
        runner = Runner([plugin])
        findings = runner.run(temp_dir)
        
        entropy_findings = [f for f in findings if f.detection_method == "entropy"]
        assert len(entropy_findings) == 1
        assert entropy_findings[0].rule == "entropy_secret"
    finally:
        shutil.rmtree(temp_dir)


def test_uuid_assigned_variable_not_flagged():
    plugin = HardcodedKeys()
    temp_dir = tempfile.mkdtemp()
    try:
        file_path = os.path.join(temp_dir, "code.py")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write('record_id = "123e4567-e89b-12d3-a456-426614174000"\n')
            
        runner = Runner([plugin])
        findings = runner.run(temp_dir)
        
        assert len(findings) == 0
    finally:
        shutil.rmtree(temp_dir)


def test_test_fixtures_stricter_entropy_filtering():
    plugin = HardcodedKeys()
    temp_dir = tempfile.mkdtemp()
    
    test_dir = os.path.join(temp_dir, "tests")
    os.makedirs(test_dir, exist_ok=True)
    
    try:
        file_path = os.path.join(test_dir, "test_code.py")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write('api_token = "token-123456789-abcdefg#$@*"\n')
            f.write('secret_key = "aB1c_D2eF3gH4iJ5k#$@*L6mN7oP8qRaB1c_D2eF3gH4iJ5k#$@*L6mN7oP8qR"\n')
            
        runner = Runner([plugin])
        findings = runner.run(temp_dir)
        
        assert len(findings) == 1
        assert findings[0].message == "Potential secret assigned to variable: secret_key"
        assert findings[0].detection_method == "entropy"
    finally:
        shutil.rmtree(temp_dir)


def test_hardcoded_keys_startup_self_check_passes():
    plugin = HardcodedKeys()
    assert len(plugin.rules) >= 150


def test_hardcoded_keys_startup_self_check_fails():
    from unittest.mock import patch
    import pytest
    with patch("scanner.static.hardcoded_keys._load_min_rules_threshold", return_value=300):
        with pytest.raises(ValueError, match="Loaded ruleset rule count .* is below the required minimum of 300"):
            HardcodedKeys()
