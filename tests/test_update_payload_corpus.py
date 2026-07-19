import os
import pytest
import yaml
from scripts.update_payload_corpus import main as run_update
from scanner.live.payloads import load_payloads

def test_update_payload_corpus_execution():
    try:
        import garak
    except ImportError:
        pytest.skip("garak package is not installed in the current environment")

    yaml_path = "payloads/injection.yaml"
    
    backup_data = None
    if os.path.exists(yaml_path):
        with open(yaml_path, "r", encoding="utf-8") as f:
            backup_data = yaml.safe_load(f)

    try:
        run_update()
        
        with open(yaml_path, "r", encoding="utf-8") as f:
            data_first = yaml.safe_load(f)
            
        assert len(data_first) > 0
        
        sources = [entry.get("source", "") for entry in data_first]
        assert any(src.startswith("garak:") for src in sources)
        
        run_update()
        
        with open(yaml_path, "r", encoding="utf-8") as f:
            data_second = yaml.safe_load(f)
            
        assert len(data_second) == len(data_first)
        
        loaded_payloads = load_payloads(yaml_path, tier="basic")
        assert len(loaded_payloads) == len(data_first)
        
        for p in loaded_payloads:
            assert "id" in p
            assert "category" in p
            assert "intent" in p
            assert "payload" in p
            assert "owasp_ref" in p
            assert "severity" in p
            assert "source" in p
            
    finally:
        if backup_data is not None:
            with open(yaml_path, "w", encoding="utf-8") as f:
                yaml.safe_dump(backup_data, f, sort_keys=False, allow_unicode=True)
