import pytest
from unittest.mock import patch, MagicMock
from scanner.core import LiveTarget
from scanner.live.pii_leak_check import PiiLeakCheck

def test_non_streaming_pii_match():
    mock_resp = MagicMock()
    mock_resp.headers = {"Content-Type": "application/json"}
    mock_resp.text = "Customer email is john.doe@example.com and SSN is 000-12-3456"

    with patch("scanner.live.pii_leak_check.PROBE_PROMPTS", ["probe_prompt"]), \
         patch("scanner.live.pii_leak_check.ThrottledRequester") as MockRequester:
        instance = MockRequester.return_value
        instance.post.return_value = mock_resp

        plugin = PiiLeakCheck()
        findings = plugin.run(LiveTarget(url="http://test.com/api"))

        assert len(findings) == 2
        
        rules = [f.rule for f in findings]
        assert all(r == "pii_leak_check" for r in rules)
        assert all(f.severity == "high" for f in findings)
        
        messages = [f.message for f in findings]
        assert any("email" in m for m in messages)
        assert any("SSN" in m for m in messages)

def test_non_streaming_no_pii():
    mock_resp = MagicMock()
    mock_resp.headers = {"Content-Type": "application/json"}
    mock_resp.text = "I cannot provide sensitive customer information or list database entries."

    with patch("scanner.live.pii_leak_check.PROBE_PROMPTS", ["probe_prompt"]), \
         patch("scanner.live.pii_leak_check.ThrottledRequester") as MockRequester:
        instance = MockRequester.return_value
        instance.post.return_value = mock_resp

        plugin = PiiLeakCheck()
        findings = plugin.run(LiveTarget(url="http://test.com/api"))

        assert len(findings) == 0

def test_streaming_pii_match():
    mock_resp = MagicMock()
    mock_resp.headers = {"Content-Type": "text/event-stream"}
    mock_resp.iter_lines.return_value = [
        "Data chunk 1: ",
        "OpenAI API key sk-AbCdEfGhIjKlMnOpQrStUvWxYz",
        " and AWS key AKIAIOSFODNN7EXAMPLE"
    ]

    with patch("scanner.live.pii_leak_check.PROBE_PROMPTS", ["probe_prompt"]), \
         patch("scanner.live.pii_leak_check.ThrottledRequester") as MockRequester:
        instance = MockRequester.return_value
        instance.post.return_value = mock_resp

        plugin = PiiLeakCheck()
        findings = plugin.run(LiveTarget(url="http://test.com/api"))

        assert len(findings) == 2
        
        messages = [f.message for f in findings]
        assert any("OpenAI" in m for m in messages)
        assert any("AWS" in m for m in messages)

def test_pii_request_timeout():
    mock_resp = MagicMock()
    mock_resp.headers = {"Content-Type": "application/json"}
    mock_resp.text = "Email leaked: alice@test.com"

    with patch("scanner.live.pii_leak_check.PROBE_PROMPTS", ["p1", "p2", "p3", "p4"]), \
         patch("scanner.live.pii_leak_check.ThrottledRequester") as MockRequester:
        instance = MockRequester.return_value
        instance.post.side_effect = [None, None, None, mock_resp]

        plugin = PiiLeakCheck()
        findings = plugin.run(LiveTarget(url="http://test.com/api"))

        assert len(findings) == 1
        assert "email" in findings[0].message
