import pytest
import os
from scanner.live.payloads import load_payloads

def test_load_payloads_success():
    path = os.path.join("payloads", "injection.yaml")
    payloads = load_payloads(path)
    
    assert isinstance(payloads, list)
    assert len(payloads) >= 12
    for entry in payloads:
        assert "id" in entry
        assert "category" in entry
        assert "payload" in entry
        assert "detection_hint" in entry
        assert "severity" in entry
        
        assert entry["category"] in {
            "instruction_override",
            "role_play_bypass",
            "system_prompt_extraction",
            "delimiter_confusion"
        }

def test_load_payloads_missing_field():
    path = os.path.join("tests", "samples", "payloads", "missing_field.yaml")
    with pytest.raises(ValueError) as exc:
        load_payloads(path)
    assert "misses required fields" in str(exc.value)

def test_load_payloads_invalid_category():
    path = os.path.join("tests", "samples", "payloads", "invalid_category.yaml")
    with pytest.raises(ValueError) as exc:
        load_payloads(path)
    assert "has invalid category" in str(exc.value)

def test_load_payloads_nonexistent_file():
    with pytest.raises(ValueError) as exc:
        load_payloads("nonexistent_file.yaml")
    assert "Payload file not found" in str(exc.value)
