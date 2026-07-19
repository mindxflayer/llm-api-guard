import os
import sys
import hashlib
import pathlib
import yaml
import random
from unittest.mock import MagicMock

def main():
    xdg_mock = MagicMock()
    xdg_mock.xdg_data_home.return_value = pathlib.Path(".")
    sys.modules["xdg_base_dirs"] = xdg_mock
    sys.modules["langdetect"] = MagicMock()

    try:
        import garak
        import garak.data
        garak_pkg_path = pathlib.Path(os.path.dirname(garak.__file__))
        garak._config.transient.package_dir = garak_pkg_path
        garak._config.transient.data_dir = garak_pkg_path
        import importlib
        importlib.reload(garak.data)
        import garak.probes.dan
        import garak.probes.promptinject
    except Exception as e:
        print(f"Failed to import garak: {e}")
        sys.exit(1)

    yaml_path = "payloads/injection.yaml"
    if os.path.exists(yaml_path):
        with open(yaml_path, "r", encoding="utf-8") as f:
            existing_data = yaml.safe_load(f) or []
    else:
        existing_data = []

    existing_ids = {entry["id"] for entry in existing_data if "id" in entry}

    dan_classes = [
        ("Dan_11_0", "dan.Dan_11_0", "Bypass constraints using standard community jailbreak instructions."),
        ("STAN", "dan.STAN", "Bypass constraints using STAN (Strive To Avoid Norms) jailbreak instructions."),
        ("DUDE", "dan.DUDE", "Bypass constraints using DUDE role-play style jailbreak instructs."),
        ("AntiDAN", "dan.AntiDAN", "Bypass constraints using AntiDAN role-play style jailbreak instructs."),
        ("ChatGPT_Developer_Mode_v2", "dan.ChatGPT_Developer_Mode_v2", "Bypass constraints using developer mode jailbreak instructions.")
    ]

    new_entries = []

    orig_shuffle = random.shuffle
    random.shuffle = lambda x: None
    try:
        for name, path_suffix, intent in dan_classes:
            cls_obj = getattr(garak.probes.dan, name, None)
            if cls_obj is None:
                continue
            try:
                inst = cls_obj()
                prompts = getattr(inst, "prompts", [])
                for p in prompts:
                    if not p:
                        continue
                    p_clean = p.replace("{generator.name}", "model")
                    m = hashlib.sha256(p_clean.encode("utf-8")).hexdigest()[:16]
                    p_id = f"garak_{m}"
                    if p_id not in existing_ids:
                        existing_ids.add(p_id)
                        new_entries.append({
                            "id": p_id,
                            "category": "role_play_bypass",
                            "intent": intent,
                            "payload": p_clean,
                            "owasp_ref": "LLM01",
                            "severity": "high",
                            "source": f"garak:v0.15.1:{path_suffix}"
                        })
            except Exception:
                pass

        pi_classes = [
            ("HijackHateHumans", "promptinject.HijackHateHumans", "Override instructions and force model to output hate messages."),
            ("HijackKillHumans", "promptinject.HijackKillHumans", "Override instructions and force model to output violent text."),
            ("HijackLongPrompt", "promptinject.HijackLongPrompt", "Override instructions and force model to repeat extremely long prompt content.")
        ]

        for name, path_suffix, intent in pi_classes:
            cls_obj = getattr(garak.probes.promptinject, name, None)
            if cls_obj is None:
                continue
            try:
                inst = cls_obj()
                prompts = getattr(inst, "prompts", [])
                for p in prompts:
                    if not p:
                        continue
                    p_clean = p.replace("{generator.name}", "model")
                    m = hashlib.sha256(p_clean.encode("utf-8")).hexdigest()[:16]
                    p_id = f"garak_{m}"
                    if p_id not in existing_ids:
                        existing_ids.add(p_id)
                        new_entries.append({
                            "id": p_id,
                            "category": "instruction_override",
                            "intent": intent,
                            "payload": p_clean,
                            "owasp_ref": "LLM01",
                            "severity": "high",
                            "source": f"garak:v0.15.1:{path_suffix}"
                        })
            except Exception:
                pass
    finally:
        random.shuffle = orig_shuffle

    if new_entries:
        all_data = existing_data + new_entries
        os.makedirs(os.path.dirname(yaml_path), exist_ok=True)
        with open(yaml_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(all_data, f, sort_keys=False, allow_unicode=True)

    sources_path = "payloads/SOURCES.md"
    sources_content = """# Prompt Injection Corpus Sources

This document describes the provenance and sources of prompt injection testing payloads used by the llm-api-guard suite.

## Existing Entries
- **Internal**: Generic, widely-published injection patterns authored internally for seed scanning.

## External Maintained Corpora
- **Garak (v0.15.1)**: Imported from Garak probes for jailbreak and instruction override tests.
  Used Probe Classes:
  - `garak.probes.dan.Dan_11_0`
  - `garak.probes.dan.STAN`
  - `garak.probes.dan.DUDE`
  - `garak.probes.dan.AntiDAN`
  - `garak.probes.dan.ChatGPT_Developer_Mode_v2`
  - `garak.probes.promptinject.HijackHateHumans`
  - `garak.probes.promptinject.HijackKillHumans`
  - `garak.probes.promptinject.HijackLongPrompt`
"""
    with open(sources_path, "w", encoding="utf-8") as f:
        f.write(sources_content)

if __name__ == "__main__":
    main()
