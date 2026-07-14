import os
import sys
import json
import time
import shutil
import tempfile
import pytest
from unittest.mock import patch, MagicMock
import requests

from scanner.osv_client import query_osv_batch, get_cache_path

@pytest.fixture
def temp_cache_dir():
    temp_dir = tempfile.mkdtemp()
    with patch("os.path.expanduser", return_value=temp_dir):
        yield temp_dir
    try:
        shutil.rmtree(temp_dir)
    except Exception:
        pass

def test_successful_query_format(temp_cache_dir):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "results": [
            {
                "vulns": [
                    {
                        "id": "CVE-2023-36095",
                        "summary": "RCE in langchain",
                        "severity": [{"type": "CVSS_V3", "score": "9.8"}],
                        "affected": [
                            {
                                "package": {"name": "langchain", "ecosystem": "PyPI"},
                                "ranges": [
                                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0.0.236"}]}
                                ]
                            }
                        ]
                    }
                ]
            }
        ]
    }

    with patch("requests.post", return_value=mock_response) as mock_post:
        res = query_osv_batch([("PyPI", "langchain", "0.0.235")])
        mock_post.assert_called_once()
        payload = mock_post.call_args[1]["json"]
        assert len(payload["queries"]) == 1
        assert payload["queries"][0]["package"]["name"] == "langchain"

        key = ("PyPI", "langchain", "0.0.235")
        assert key in res
        vulns = res[key]
        assert len(vulns) == 1
        assert vulns[0]["id"] == "CVE-2023-36095"
        assert vulns[0]["summary"] == "RCE in langchain"
        assert vulns[0]["severity"][0]["score"] == "9.8"
        assert len(vulns[0]["ranges"]) == 1

        expected_cache = get_cache_path("PyPI", "langchain", "0.0.235")
        assert os.path.exists(expected_cache)
        with open(expected_cache, "r", encoding="utf-8") as f:
            cached = json.load(f)
            assert "timestamp" in cached
            assert len(cached["vulns"]) == 1

def test_cache_hit_skips_network(temp_cache_dir):
    cache_path = get_cache_path("PyPI", "langchain", "0.0.235")
    cached_vulns = [{"id": "CVE-2023-36095", "summary": "RCE", "severity": None, "ranges": []}]
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump({"timestamp": time.time(), "vulns": cached_vulns}, f)

    with patch("requests.post") as mock_post:
        res = query_osv_batch([("PyPI", "langchain", "0.0.235")], cache_ttl_hours=1.0)
        mock_post.assert_not_called()
        key = ("PyPI", "langchain", "0.0.235")
        assert len(res[key]) == 1
        assert res[key][0]["id"] == "CVE-2023-36095"

def test_network_failure_expired_cache(temp_cache_dir, capsys):
    cache_path = get_cache_path("PyPI", "langchain", "0.0.235")
    cached_time = time.time() - 10800
    cached_vulns = [{"id": "CVE-2023-36095", "summary": "RCE", "severity": None, "ranges": []}]
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump({"timestamp": cached_time, "vulns": cached_vulns}, f)

    with patch("requests.post", side_effect=requests.exceptions.ConnectionError()):
        res = query_osv_batch([("PyPI", "langchain", "0.0.235")], cache_ttl_hours=1.0)
        key = ("PyPI", "langchain", "0.0.235")
        assert len(res[key]) == 1
        assert res[key][0]["id"] == "CVE-2023-36095"
        captured = capsys.readouterr()
        assert "stale OSV data, last updated" in captured.err

def test_network_failure_no_cache_offline_fallback(temp_cache_dir):
    with patch("requests.post", side_effect=requests.exceptions.Timeout()):
        res = query_osv_batch([
            ("PyPI", "langchain", "0.0.235"),
            ("PyPI", "langchain-core", "0.3.50"),
            ("npm", "axios", "1.7.0")
        ])
        assert len(res[("PyPI", "langchain", "0.0.235")]) >= 1
        langchain_vuln = res[("PyPI", "langchain", "0.0.235")][0]
        assert langchain_vuln["id"] == "CVE-2023-36095"
        assert langchain_vuln["source"] == "offline_snapshot"

        assert len(res[("PyPI", "langchain-core", "0.3.50")]) >= 1
        langchain_core_vuln = res[("PyPI", "langchain-core", "0.3.50")][0]
        assert langchain_core_vuln["id"] == "CVE-2025-68664"
        assert langchain_core_vuln["source"] == "offline_snapshot"

        assert len(res[("npm", "axios", "1.7.0")]) >= 1
        axios_vuln = res[("npm", "axios", "1.7.0")][0]
        assert axios_vuln["id"] == "GHSA-jrv5-628v-59g8"
        assert axios_vuln["source"] == "offline_snapshot"

        res_safe = query_osv_batch([("PyPI", "langchain-core", "0.3.81")])
        assert len(res_safe[("PyPI", "langchain-core", "0.3.81")]) == 0

@pytest.mark.network
def test_real_network_call_sanity():
    try:
        res = query_osv_batch([("PyPI", "langchain", "0.0.235")], cache_ttl_hours=0.0)
        assert ("PyPI", "langchain", "0.0.235") in res
        vulns = res[("PyPI", "langchain", "0.0.235")]
        assert len(vulns) >= 1
        assert any(v["id"] in ("GHSA-2qmj-7962-cjq8", "CVE-2023-36095") for v in vulns)
    except Exception as e:
        pytest.fail(f"Real connection to OSV failed: {e}")
