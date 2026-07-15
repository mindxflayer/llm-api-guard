import os
import re

try:
    import tomllib
except ImportError:
    import tomli as tomllib


def _clean_regex(pattern: str) -> str:
    if not isinstance(pattern, str):
        return pattern
    
    replacements = {
        "[[:alnum:]]": "[a-zA-Z0-9]",
        "[[:alpha:]]": "[a-zA-Z]",
        "[[:digit:]]": "[0-9]",
        "[[:xdigit:]]": "[a-fA-F0-9]",
        "[[:space:]]": r"\s",
        "[^[:alnum:]]": "[^a-zA-Z0-9]",
        "[^[:alpha:]]": "[^a-zA-Z]",
        "[^[:digit:]]": "[^0-9]",
        "[^[:xdigit:]]": "[^a-fA-F0-9]",
    }
    
    cleaned = pattern
    for posix, py_regex in replacements.items():
        cleaned = cleaned.replace(posix, py_regex)
        
    cleaned = cleaned.replace(r"\z", r"\Z")
    return cleaned


def load_ruleset(path: str = "scanner/secret_rules/gitleaks.toml") -> list[dict]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Ruleset file '{path}' not found.")
        
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        raise ValueError(f"Malformed TOML ruleset file '{path}': {e}")
    except Exception as e:
        raise ValueError(f"Failed to read ruleset file '{path}': {e}")

    rules = data.get("rules", [])
    parsed_rules = []
    
    for rule in rules:
        rule_id = rule.get("id")
        if not rule_id:
            continue
            
        description = rule.get("description", "")
        raw_regex = rule.get("regex", "")
        if not raw_regex:
            continue
            
        cleaned_regex = _clean_regex(raw_regex)
        try:
            compiled = re.compile(cleaned_regex)
        except re.error as e:
            raise ValueError(f"Failed to compile regex for rule '{rule_id}': {e}")
            
        tags = rule.get("tags", [])
        keywords = rule.get("keywords", [])
        
        parsed_rules.append({
            "id": rule_id,
            "description": description,
            "regex": compiled,
            "tags": tags,
            "keywords": keywords,
        })
        
    return parsed_rules
