from unittest.mock import patch, MagicMock
from scanner.core import LiveTarget
from scanner.live.rate_limit_check import RateLimitCheck

def test_rate_limit_not_observed():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {}
    with patch("scanner.live.rate_limit_check.ThrottledRequester") as MockRequester:
        instance = MockRequester.return_value
        instance.get.return_value = mock_resp
        instance.get_stats.return_value = {
            "requests_made": 15,
            "requests_succeeded": 15,
            "requests_failed": 0,
            "time_elapsed": 7.5
        }
        plugin = RateLimitCheck(num_requests=15)
        findings = plugin.run(LiveTarget(url="http://test.com/api"))
        assert len(findings) == 1
        assert findings[0].rule == "rate_limit_check"
        assert findings[0].severity == "medium"
        assert "No rate limiting observed" in findings[0].message
        assert instance.get.call_count == 15

def test_rate_limit_observed_429():
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_resp.headers = {}
    with patch("scanner.live.rate_limit_check.ThrottledRequester") as MockRequester:
        instance = MockRequester.return_value
        instance.get.return_value = mock_resp
        plugin = RateLimitCheck(num_requests=15)
        findings = plugin.run(LiveTarget(url="http://test.com/api"))
        assert len(findings) == 0
        assert instance.get.call_count == 1

def test_rate_limit_observed_headers():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"X-RateLimit-Remaining": "0"}
    with patch("scanner.live.rate_limit_check.ThrottledRequester") as MockRequester:
        instance = MockRequester.return_value
        instance.get.return_value = mock_resp
        plugin = RateLimitCheck(num_requests=15)
        findings = plugin.run(LiveTarget(url="http://test.com/api"))
        assert len(findings) == 0
        assert instance.get.call_count == 1

def test_rate_limit_target_unreachable():
    with patch("scanner.live.rate_limit_check.ThrottledRequester") as MockRequester:
        instance = MockRequester.return_value
        instance.get.return_value = None
        instance.get_stats.return_value = {
            "requests_made": 1,
            "requests_succeeded": 0,
            "requests_failed": 1,
            "time_elapsed": 10.0
        }
        plugin = RateLimitCheck(num_requests=15)
        findings = plugin.run(LiveTarget(url="http://test.com/api"))
        assert len(findings) == 1
        assert findings[0].rule == "rate_limit_check"
        assert findings[0].severity == "low"
        assert "unreachable" in findings[0].message
        assert instance.get.call_count == 1
