import pytest
from unittest.mock import patch, MagicMock
from scanner.core import LiveTarget
from scanner.live.injection_payload_check import InjectionPayloadCheck

def test_non_streaming_compliance():
    mock_resp = MagicMock()
    mock_resp.headers = {"Content-Type": "application/json"}
    mock_resp.text = "Here is the response: INJECTED"
    
    mock_payloads = [
        {
            "id": "test_01",
            "category": "instruction_override",
            "payload": "Ignore rules",
            "detection_hint": "Response contains 'INJECTED'",
            "severity": "high"
        }
    ]

    with patch("scanner.live.injection_payload_check.load_payloads", return_value=mock_payloads), \
         patch("scanner.live.injection_payload_check.ThrottledRequester") as MockRequester:
        instance = MockRequester.return_value
        instance.post.return_value = mock_resp

        plugin = InjectionPayloadCheck()
        findings = plugin.run(LiveTarget(url="http://test.com/api"))

        assert len(findings) == 1
        assert findings[0].rule == "injection_payload_check"
        assert findings[0].severity == "high"
        assert "test_01" in findings[0].message
        assert findings[0].location == "http://test.com/api"

def test_non_streaming_refusal():
    mock_resp = MagicMock()
    mock_resp.headers = {"Content-Type": "application/json"}
    mock_resp.text = "I cannot fulfill this request."

    mock_payloads = [
        {
            "id": "test_01",
            "category": "instruction_override",
            "payload": "Ignore rules",
            "detection_hint": "Response contains 'INJECTED'",
            "severity": "high"
        }
    ]

    with patch("scanner.live.injection_payload_check.load_payloads", return_value=mock_payloads), \
         patch("scanner.live.injection_payload_check.ThrottledRequester") as MockRequester:
        instance = MockRequester.return_value
        instance.post.return_value = mock_resp

        plugin = InjectionPayloadCheck()
        findings = plugin.run(LiveTarget(url="http://test.com/api"))

        assert len(findings) == 0

def test_streaming_compliance():
    mock_resp = MagicMock()
    mock_resp.headers = {"Content-Type": "text/event-stream"}
    mock_resp.iter_lines.return_value = ["Here is ", "some ", "INJECTED ", "data"]

    mock_payloads = [
        {
            "id": "test_01",
            "category": "instruction_override",
            "payload": "Ignore rules",
            "detection_hint": "Response contains 'INJECTED'",
            "severity": "high"
        }
    ]

    with patch("scanner.live.injection_payload_check.load_payloads", return_value=mock_payloads), \
         patch("scanner.live.injection_payload_check.ThrottledRequester") as MockRequester:
        instance = MockRequester.return_value
        instance.post.return_value = mock_resp

        plugin = InjectionPayloadCheck()
        findings = plugin.run(LiveTarget(url="http://test.com/api"))

        assert len(findings) == 1
        assert findings[0].rule == "injection_payload_check"
        assert findings[0].severity == "high"

def test_payload_request_timeout():
    mock_resp = MagicMock()
    mock_resp.headers = {"Content-Type": "application/json"}
    mock_resp.text = "Here is the response: INJECTED"

    mock_payloads = [
        {
            "id": "test_01",
            "category": "instruction_override",
            "payload": "Ignore rules",
            "detection_hint": "Response contains 'INJECTED'",
            "severity": "high"
        },
        {
            "id": "test_02",
            "category": "instruction_override",
            "payload": "Second rule check",
            "detection_hint": "Response contains 'INJECTED'",
            "severity": "high"
        }
    ]

    with patch("scanner.live.injection_payload_check.load_payloads", return_value=mock_payloads), \
         patch("scanner.live.injection_payload_check.ThrottledRequester") as MockRequester:
        instance = MockRequester.return_value
        instance.post.side_effect = [None, mock_resp]

        plugin = InjectionPayloadCheck()
        findings = plugin.run(LiveTarget(url="http://test.com/api"))

        assert len(findings) == 1
        assert "test_02" in findings[0].message
