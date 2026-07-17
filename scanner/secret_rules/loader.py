import os
import re
import logging

try:
    import tomllib
except ImportError:
    import tomli as tomllib

logger = logging.getLogger("llm-api-guard")


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

    flag_matches = re.findall(r"\(\?([aimsx]+)\)", cleaned)
    if flag_matches:
        all_flags = "".join(sorted(set("".join(flag_matches))))
        cleaned = re.sub(r"\(\?([aimsx]+)\)", "", cleaned)
        cleaned = f"(?{all_flags}){cleaned}"

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
            
        try:
            cleaned_regex = _clean_regex(raw_regex)
            compiled = re.compile(cleaned_regex)
        except (re.error, ValueError) as e:
            logger.info(f"Skipping rule '{rule_id}' due to regex compilation failure: {e}")
            continue
            
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
