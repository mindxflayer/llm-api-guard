import pytest
import sys
from cli import main
from unittest.mock import patch

def test_version_flag(capsys):
    with patch("sys.argv", ["cli.py", "--version"]):
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == 0
        captured = capsys.readouterr()
        assert "llm-api-guard" in captured.out or "llm-api-guard" in captured.err

def test_nonexistent_repo(capsys):
    with patch("sys.argv", ["cli.py", "repo", "--repo", "nonexistent_directory_abc_123"]):
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code != 0
        captured = capsys.readouterr()
        assert "Error: Repo path" in captured.out

def test_nonexistent_config(capsys):
    with patch("sys.argv", ["cli.py", "repo", "--repo", ".", "--config", "nonexistent_config_xyz.yaml"]):
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code != 0
        captured = capsys.readouterr()
        assert "Error: Config file" in captured.out

def test_invalid_fail_on():
    with patch("sys.argv", ["cli.py", "repo", "--repo", ".", "--fail-on", "invalid_value"]):
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code != 0

def test_invalid_url_scheme(capsys):
    with patch("sys.argv", ["cli.py", "url", "--url", "localhost:8000"]):
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code != 0
        captured = capsys.readouterr()
        assert "Error: Invalid URL" in captured.out
