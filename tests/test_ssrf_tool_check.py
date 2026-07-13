import pytest
from unittest.mock import patch, MagicMock
from scanner.core import LiveTarget
from scanner.live.ssrf_tool_check import SsrfToolCheck

def test_ssrf_non_streaming_success():
    mock_resp = MagicMock()
    mock_resp.headers = {"Content-Type": "application/json"}
    mock_resp.text = "Metadata response: ami-id = ami-12345"

    with patch("scanner.live.ssrf_tool_check.PROBE_PROMPTS", ["probe_prompt"]), \
         patch("scanner.live.ssrf_tool_check.ThrottledRequester") as MockRequester:
        instance = MockRequester.return_value
        instance.post.return_value = mock_resp

        plugin = SsrfToolCheck()
        findings = plugin.run(LiveTarget(url="http://test.com/api"))

        assert len(findings) == 1
        assert findings[0].rule == "ssrf_tool_check"
        assert findings[0].severity == "high"

def test_ssrf_non_streaming_refusal():
    mock_resp = MagicMock()
    mock_resp.headers = {"Content-Type": "application/json"}
    mock_resp.text = "Request not allowed: external resources cannot be accessed."

    with patch("scanner.live.ssrf_tool_check.PROBE_PROMPTS", ["probe_prompt"]), \
         patch("scanner.live.ssrf_tool_check.ThrottledRequester") as MockRequester:
        instance = MockRequester.return_value
        instance.post.return_value = mock_resp

        plugin = SsrfToolCheck()
        findings = plugin.run(LiveTarget(url="http://test.com/api"))

        assert len(findings) == 0

def test_ssrf_streaming_success():
    mock_resp = MagicMock()
    mock_resp.headers = {"Content-Type": "text/event-stream"}
    mock_resp.iter_lines.return_value = ["Connection ", "successful connection to local ", "admin dashboard"]

    with patch("scanner.live.ssrf_tool_check.PROBE_PROMPTS", ["probe_prompt"]), \
         patch("scanner.live.ssrf_tool_check.ThrottledRequester") as MockRequester:
        instance = MockRequester.return_value
        instance.post.return_value = mock_resp

        plugin = SsrfToolCheck()
        findings = plugin.run(LiveTarget(url="http://test.com/api"))

        assert len(findings) == 1
        assert findings[0].rule == "ssrf_tool_check"
        assert findings[0].severity == "high"

def test_ssrf_timeout():
    mock_resp = MagicMock()
    mock_resp.headers = {"Content-Type": "application/json"}
    mock_resp.text = "AWS instance configuration local-ipv4 = 10.0.0.1"

    with patch("scanner.live.ssrf_tool_check.PROBE_PROMPTS", ["p1", "p2"]), \
         patch("scanner.live.ssrf_tool_check.ThrottledRequester") as MockRequester:
        instance = MockRequester.return_value
        instance.post.side_effect = [None, mock_resp]

        plugin = SsrfToolCheck()
        findings = plugin.run(LiveTarget(url="http://test.com/api"))

        assert len(findings) == 1
        assert "p2" in findings[0].message
