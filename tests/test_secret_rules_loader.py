import os
import pytest
import re
from scanner.secret_rules.loader import load_ruleset


def test_load_ruleset_success():
    rules_path = "scanner/secret_rules/gitleaks.toml"
    assert os.path.exists(rules_path)
    
    rules = load_ruleset(rules_path)
    assert len(rules) > 0
    
    for rule in rules:
        assert "id" in rule
        assert "description" in rule
        assert "regex" in rule
        assert "tags" in rule
        assert "keywords" in rule
        
        assert isinstance(rule["id"], str)
        assert isinstance(rule["description"], str)
        assert isinstance(rule["regex"], type(re.compile("")))
        assert isinstance(rule["tags"], list)
        assert isinstance(rule["keywords"], list)


def test_load_ruleset_missing_file():
    with pytest.raises(FileNotFoundError, match="Ruleset file '.*' not found"):
        load_ruleset("scanner/secret_rules/nonexistent_gitleaks_rules.toml")


def test_load_ruleset_malformed_file(tmp_path):
    malformed_path = tmp_path / "malformed.toml"
    malformed_path.write_text("rules = [\n  { id = 'test-rule', regex = 'unclosed_string\n]", encoding="utf-8")
    
    with pytest.raises(ValueError, match="Malformed TOML ruleset file"):
        load_ruleset(str(malformed_path))


def test_load_ruleset_anthropic_pattern():
    rules_path = "scanner/secret_rules/gitleaks.toml"
    rules = load_ruleset(rules_path)
    
    anthropic_rule = next((r for r in rules if r["id"] == "anthropic-api-key"), None)
    assert anthropic_rule is not None
    
    pattern = anthropic_rule["regex"]
    valid_key = "sk-ant-api03-" + "a" * 93 + "AA"
    invalid_key_too_short = "sk-ant-api03-" + "a" * 92 + "AA"
    invalid_key_bad_prefix = "sk-ant-api02-" + "a" * 93 + "AA"
    
    assert pattern.search(valid_key) is not None
    assert pattern.search(invalid_key_too_short) is None
    assert pattern.search(invalid_key_bad_prefix) is None
