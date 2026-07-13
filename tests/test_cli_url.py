import pytest
import os
import tempfile
from unittest.mock import patch, MagicMock
from cli import main
from scanner.core import Plugin, Finding

def test_url_command_unauthorized_exit():
    test_args = ["cli.py", "url", "--url", "http://test.com/api"]
    
    with patch("sys.argv", test_args), \
         patch("cli.confirm_authorization", return_value=False) as mock_auth, \
         patch("scanner.core.Runner.run") as mock_runner_run, \
         pytest.raises(SystemExit) as exc:
        
        main()

    assert exc.value.code == 1
    mock_auth.assert_called_once_with("http://test.com/api", interactive=True, permission_flag=False)
    mock_runner_run.assert_not_called()

def test_url_command_authorized_runner_execution():
    config_content = """
target_type: url
checks:
  hardcoded_keys: true
live_checks:
  rate_limit_check: true
  cors_misconfig: false
  injection_payload_check: false
  pii_leak_check: false
  ssrf_tool_check: false
severity_threshold: medium
"""
    fd, config_path = tempfile.mkstemp(suffix=".yaml")
    os.write(fd, config_content.encode('utf-8'))
    os.close(fd)

    report_path = tempfile.mktemp(suffix=".json")

    test_args = [
        "cli.py", "url",
        "--url", "http://test.com/api",
        "--header", "Authorization: Bearer test",
        "--header", "X-Custom: val",
        "--config", config_path,
        "--output", report_path,
        "--i-have-permission"
    ]

    try:
        mock_findings = [Finding(rule="rate_limit_check", severity="medium", message="rate limited", location="http://test.com/api")]

        with patch("sys.argv", test_args), \
             patch("cli.confirm_authorization", return_value=True) as mock_auth, \
             patch("scanner.core.Runner.run", return_value=mock_findings) as mock_runner_run:
            
            main()

            mock_auth.assert_called_once_with("http://test.com/api", interactive=True, permission_flag=True)
            mock_runner_run.assert_called_once()
            
            called_target = mock_runner_run.call_args[0][0]
            assert called_target.url == "http://test.com/api"
            assert called_target.headers == {"Authorization": "Bearer test", "X-Custom": "val"}

            assert os.path.exists(report_path)
    finally:
        os.remove(config_path)
        if os.path.exists(report_path):
            os.remove(report_path)

def test_url_command_ssrf_disabled_by_default():
    config_content = """
target_type: url
checks:
  hardcoded_keys: true
live_checks:
  rate_limit_check: true
  cors_misconfig: true
  injection_payload_check: false
  pii_leak_check: false
  ssrf_tool_check: false
severity_threshold: medium
"""
    fd, config_path = tempfile.mkstemp(suffix=".yaml")
    os.write(fd, config_content.encode('utf-8'))
    os.close(fd)

    test_args = [
        "cli.py", "url",
        "--url", "http://test.com/api",
        "--config", config_path,
        "--i-have-permission"
    ]

    class FakeRateLimitCheck(Plugin):
        name = "rate_limit_check"
        severity = "medium"
        owasp_ref = "LLM02"
        run = MagicMock(return_value=[])

    class FakeSsrfToolCheck(Plugin):
        name = "ssrf_tool_check"
        severity = "high"
        owasp_ref = "LLM08"
        run = MagicMock(return_value=[])

    try:
        with patch("scanner.core.PluginLoader.load_plugins", return_value=[FakeRateLimitCheck, FakeSsrfToolCheck]), \
             patch("sys.argv", test_args), \
             patch("cli.confirm_authorization", return_value=True):
            
            main()

            FakeRateLimitCheck.run.assert_called_once()
            FakeSsrfToolCheck.run.assert_not_called()
    finally:
        os.remove(config_path)
