from unittest.mock import patch, MagicMock
from scanner.core import LiveTarget
from scanner.live.cors_misconfig import CorsMisconfig

def test_cors_wildcard_with_credentials():
    mock_resp = MagicMock()
    mock_resp.headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true"
    }
    with patch("scanner.live.cors_misconfig.ThrottledRequester") as MockRequester:
        instance = MockRequester.return_value
        instance.get.return_value = mock_resp
        
        plugin = CorsMisconfig()
        findings = plugin.run(LiveTarget(url="http://test.com/api"))
        
        assert len(findings) == 1
        assert findings[0].rule == "cors_misconfig"
        assert findings[0].severity == "high"
        assert "Wildcard origin allowed with credentials" in findings[0].message
        assert instance.get.call_count == 1
        
        _, kwargs = instance.get.call_args
        assert kwargs["headers"]["Origin"] == "https://evil-test-origin.example.com"

def test_cors_wildcard_no_credentials():
    mock_resp = MagicMock()
    mock_resp.headers = {
        "Access-Control-Allow-Origin": "*"
    }
    with patch("scanner.live.cors_misconfig.ThrottledRequester") as MockRequester:
        instance = MockRequester.return_value
        instance.get.return_value = mock_resp
        
        plugin = CorsMisconfig()
        findings = plugin.run(LiveTarget(url="http://test.com/api"))
        
        assert len(findings) == 1
        assert findings[0].rule == "cors_misconfig"
        assert findings[0].severity == "medium"
        assert "Wildcard origin (*) allowed without credentials" in findings[0].message
        assert instance.get.call_count == 1

def test_cors_reflected_origin():
    mock_resp = MagicMock()
    mock_resp.headers = {
        "Access-Control-Allow-Origin": "https://evil-test-origin.example.com"
    }
    with patch("scanner.live.cors_misconfig.ThrottledRequester") as MockRequester:
        instance = MockRequester.return_value
        instance.get.return_value = mock_resp
        
        plugin = CorsMisconfig()
        findings = plugin.run(LiveTarget(url="http://test.com/api"))
        
        assert len(findings) == 1
        assert findings[0].rule == "cors_misconfig"
        assert findings[0].severity == "high"
        assert "reflected and allowed" in findings[0].message
        assert instance.get.call_count == 1

def test_cors_safe_or_absent():
    mock_resp_missing = MagicMock()
    mock_resp_missing.headers = {}
    
    mock_resp_restricted = MagicMock()
    mock_resp_restricted.headers = {
        "Access-Control-Allow-Origin": "https://safe-origin.example.com"
    }
    
    with patch("scanner.live.cors_misconfig.ThrottledRequester") as MockRequester:
        instance = MockRequester.return_value
        plugin = CorsMisconfig()
        
        instance.get.return_value = mock_resp_missing
        findings = plugin.run(LiveTarget(url="http://test.com/api"))
        assert len(findings) == 0
        
        instance.get.return_value = mock_resp_restricted
        findings = plugin.run(LiveTarget(url="http://test.com/api"))
        assert len(findings) == 0

def test_cors_unreachable():
    with patch("scanner.live.cors_misconfig.ThrottledRequester") as MockRequester:
        instance = MockRequester.return_value
        instance.get.return_value = None
        
        plugin = CorsMisconfig()
        findings = plugin.run(LiveTarget(url="http://test.com/api"))
        
        assert len(findings) == 1
        assert findings[0].rule == "cors_misconfig"
        assert findings[0].severity == "low"
        assert "unreachable" in findings[0].message
        assert instance.get.call_count == 1
