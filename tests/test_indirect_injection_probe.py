import pytest
from unittest.mock import MagicMock, patch
from scanner.core import Runner, LiveTarget
from scanner.live.indirect_injection_probe import IndirectInjectionProbe

class MockResponse:
    def __init__(self, text, status_code=200):
        self.text = text
        self.status_code = status_code
        self.headers = {"Content-Type": "text/plain"}
    def iter_content(self, chunk_size=1, decode_unicode=True):
        yield self.text

class MockJudgeResult:
    def __init__(self, verdict, confidence, exploit_explanation):
        self.verdict = verdict
        self.confidence = confidence
        self.exploit_explanation = exploit_explanation

@patch("scanner.live.throttle.requests.request")
def test_indirect_injection_probe_document_true_positive(mock_request):
    mock_request.return_value = MockResponse("yes master")
    
    config = {
        "checks": {},
        "live_checks": {
            "indirect_injection_probe": True
        },
        "indirect_injection": {
            "fixtures": [
                {
                    "type": "document",
                    "content": "Secret document.",
                    "trigger_field": "context"
                }
            ]
        }
    }
    
    mock_judge = MagicMock()
    mock_judge.judge.return_value = MockJudgeResult(
        verdict="true_positive",
        confidence=90,
        exploit_explanation="Exploit explanation: model followed instruction."
    )
    
    plugin = IndirectInjectionProbe()
    runner = Runner([plugin], config=config, judge_provider=mock_judge)
    findings = runner.run(LiveTarget(url="http://localhost:8080/chat"))
    
    assert len(findings) == 1
    assert findings[0].rule == "indirect_injection_probe"
    assert findings[0].message == "Exploit explanation: model followed instruction."
    
    args, kwargs = mock_request.call_args
    assert kwargs["json"]["context"].startswith("Secret document.")
    assert "[INSTRUCTION]" in kwargs["json"]["context"]

@patch("scanner.live.throttle.requests.request")
def test_indirect_injection_probe_document_false_positive(mock_request):
    mock_request.return_value = MockResponse("no way")
    
    config = {
        "checks": {},
        "live_checks": {
            "indirect_injection_probe": True
        },
        "indirect_injection": {
            "fixtures": [
                {
                    "type": "document",
                    "content": "Secret document.",
                    "trigger_field": "context"
                }
            ]
        }
    }
    
    mock_judge = MagicMock()
    mock_judge.judge.return_value = MockJudgeResult(
        verdict="false_positive",
        confidence=80,
        exploit_explanation="Model did not follow instruction."
    )
    
    plugin = IndirectInjectionProbe()
    runner = Runner([plugin], config=config, judge_provider=mock_judge)
    findings = runner.run(LiveTarget(url="http://localhost:8080/chat"))
    
    assert len(findings) == 0

def test_indirect_injection_probe_no_fixtures(caplog):
    config = {
        "checks": {},
        "live_checks": {
            "indirect_injection_probe": True
        },
        "indirect_injection": {
            "fixtures": []
        }
    }
    
    plugin = IndirectInjectionProbe()
    runner = Runner([plugin], config=config)
    findings = runner.run(LiveTarget(url="http://localhost:8080/chat"))
    
    assert len(findings) == 0
    assert any("indirect_injection_probe enabled but no fixtures configured" in record.message for record in caplog.records)

@patch("scanner.live.throttle.requests.request")
def test_indirect_injection_probe_url_pass_through(mock_request):
    mock_request.return_value = MockResponse("ok")
    
    config = {
        "checks": {},
        "live_checks": {
            "indirect_injection_probe": True
        },
        "indirect_injection": {
            "fixtures": [
                {
                    "type": "url",
                    "url": "https://example.com/target-page",
                    "trigger_field": "url_input"
                }
            ]
        }
    }
    
    mock_judge = MagicMock()
    mock_judge.judge.return_value = MockJudgeResult(
        verdict="false_positive",
        confidence=80,
        exploit_explanation="Nothing."
    )
    
    plugin = IndirectInjectionProbe()
    runner = Runner([plugin], config=config, judge_provider=mock_judge)
    runner.run(LiveTarget(url="http://localhost:8080/chat"))
    
    args, kwargs = mock_request.call_args
    assert kwargs["json"]["url_input"] == "https://example.com/target-page"
