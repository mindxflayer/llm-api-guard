import os
import shutil
import pytest


@pytest.fixture(autouse=True)
def clean_judge_cache():
    cache_dir = os.path.expanduser("~/.cache/llm-api-guard/judge")
    if os.path.exists(cache_dir):
        try:
            shutil.rmtree(cache_dir)
        except Exception:
            pass
    yield
    if os.path.exists(cache_dir):
        try:
            shutil.rmtree(cache_dir)
        except Exception:
            pass
