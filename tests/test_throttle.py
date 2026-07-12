import time
import pytest
import logging
from unittest.mock import patch, MagicMock
import requests.exceptions
from scanner.live.throttle import ThrottledRequester

def test_clamp_max_requests(caplog):
    with caplog.at_level(logging.WARNING):
        req = ThrottledRequester(max_requests=250)
        assert req.max_requests == 200
        assert any("max_requests 250 exceeds cap of 200" in record.message for record in caplog.records)

def test_request_cap_stops_execution():
    req = ThrottledRequester(max_requests=3, min_delay=0.0)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    with patch("requests.request", return_value=mock_resp) as mock_req:
        res1 = req.get("http://test.com/1")
        res2 = req.get("http://test.com/2")
        res3 = req.get("http://test.com/3")
        res4 = req.get("http://test.com/4")
        assert res1 is not None
        assert res2 is not None
        assert res3 is not None
        assert res4 is None
        assert mock_req.call_count == 3
        stats = req.get_stats()
        assert stats["requests_made"] == 3
        assert stats["requests_succeeded"] == 3
        assert stats["requests_failed"] == 0

def test_minimum_delay_respected():
    req = ThrottledRequester(max_requests=5, min_delay=0.5)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    times = [10.0, 10.1, 10.7, 10.8]
    time_idx = 0

    def mock_time():
        nonlocal time_idx
        t = times[time_idx]
        if time_idx < len(times) - 1:
            time_idx += 1
        return t

    with patch("time.time", side_effect=mock_time), \
         patch("time.sleep") as mock_sleep, \
         patch("requests.request", return_value=mock_resp):
        req.get("http://test.com/1")
        req.get("http://test.com/2")
        mock_sleep.assert_called_once()
        args, _ = mock_sleep.call_args
        assert abs(args[0] - 0.4) < 1e-5

def test_exponential_backoff_on_5xx_and_gives_up():
    req = ThrottledRequester(max_requests=5, min_delay=0.5)
    mock_resp = MagicMock()
    mock_resp.status_code = 502
    with patch("requests.request", return_value=mock_resp) as mock_req, \
         patch("time.sleep") as mock_sleep:
        res = req.get("http://test.com/fail")
        assert res is None
        assert mock_req.call_count == 4
        assert mock_sleep.call_count > 3
        sleep_args = [args[0] for args, _ in mock_sleep.call_args_list]
        expected_backoffs = [0.5 * 1, 0.5 * 2, 0.5 * 4]
        for backoff in expected_backoffs:
            assert any(abs(s - backoff) < 1e-5 for s in sleep_args)
        stats = req.get_stats()
        assert stats["requests_made"] == 1
        assert stats["requests_succeeded"] == 0
        assert stats["requests_failed"] == 1

def test_exponential_backoff_on_connection_error():
    req = ThrottledRequester(max_requests=5, min_delay=0.5)
    with patch("requests.request", side_effect=requests.exceptions.ConnectionError) as mock_req, \
         patch("time.sleep") as mock_sleep:
        res = req.post("http://test.com/post")
        assert res is None
        assert mock_req.call_count == 4
        assert req.requests_failed == 1

def test_overall_run_timeout():
    req = ThrottledRequester(max_requests=5, min_delay=0.1, run_timeout=1.0)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    with patch("requests.request", return_value=mock_resp), \
         patch("time.sleep"):
        res1 = req.get("http://test.com/1")
        assert res1 is not None
        with patch("time.time", return_value=req.start_time + 1.5):
            res2 = req.get("http://test.com/2")
            assert res2 is None
        stats = req.get_stats()
        assert stats["requests_made"] == 1
        assert stats["requests_succeeded"] == 1
        assert stats["requests_failed"] == 0

