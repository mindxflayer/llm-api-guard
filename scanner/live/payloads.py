import os
import yaml

def load_payloads(path: str = "payloads/injection.yaml") -> list[dict]:
    if not os.path.exists(path):
        raise ValueError(f"Payload file not found at: {path}")

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        raise ValueError(f"Failed to parse payload YAML: {e}")

    if not isinstance(data, list):
        raise ValueError("Invalid format: top-level elements must be a list")

    required_fields = {"id", "category", "intent", "payload", "owasp_ref", "severity", "source"}
    valid_categories = {
        "instruction_override",
        "role_play_bypass",
        "system_prompt_extraction",
        "delimiter_confusion"
    }

    for idx, entry in enumerate(data):
        if not isinstance(entry, dict):
            raise ValueError(f"Entry at index {idx} is not a dictionary")

        missing = required_fields - entry.keys()
        if missing:
            raise ValueError(f"Entry at index {idx} misses required fields: {', '.join(missing)}")

        for field in required_fields:
            if entry[field] is None:
                raise ValueError(f"Entry at index {idx} has null value for field '{field}'")

        category = entry["category"]
        if category not in valid_categories:
            raise ValueError(
                f"Entry at index {idx} has invalid category '{category}'. "
                f"Must be one of: {', '.join(valid_categories)}"
            )

    return data
