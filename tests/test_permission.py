import os
import tempfile
import shutil
import pytest
from unittest.mock import patch
from scanner.live import confirm_authorization, log_authorization

@pytest.fixture
def temp_cwd():
    temp_dir = tempfile.mkdtemp()
    with patch('os.getcwd', return_value=temp_dir):
        yield temp_dir
    shutil.rmtree(temp_dir)

def test_confirm_authorization_permission_flag_true(temp_cwd):
    with patch('getpass.getuser', return_value='test_user'):
        with patch('builtins.input') as mock_input:
            res = confirm_authorization("http://example.com/api", permission_flag=True)
            assert res is True
            mock_input.assert_not_called()
        
        log_file = os.path.join(temp_cwd, ".llm-api-guard-audit.log")
        assert os.path.exists(log_file)
        with open(log_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        assert len(lines) == 1
        assert "Operator: test_user" in lines[0]
        assert "URL: http://example.com/api" in lines[0]
        assert "Status: GRANTED" in lines[0]

def test_confirm_authorization_interactive_false_no_permission(temp_cwd):
    with patch('getpass.getuser', return_value='test_user'):
        with patch('builtins.input') as mock_input:
            res = confirm_authorization("http://example.com/api", interactive=False, permission_flag=False)
            assert res is False
            mock_input.assert_not_called()
            
        log_file = os.path.join(temp_cwd, ".llm-api-guard-audit.log")
        assert os.path.exists(log_file)
        with open(log_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        assert len(lines) == 1
        assert "Operator: test_user" in lines[0]
        assert "URL: http://example.com/api" in lines[0]
        assert "Status: DENIED" in lines[0]

@pytest.mark.parametrize("user_input,expected_res,expected_status", [
    ("y", True, "GRANTED"),
    ("yes", True, "GRANTED"),
    ("YES", True, "GRANTED"),
    ("y ", True, "GRANTED"),
    ("n", False, "DENIED"),
    ("no", False, "DENIED"),
    ("", False, "DENIED"),
    ("   ", False, "DENIED"),
    ("anything_else", False, "DENIED")
])
def test_confirm_authorization_interactive_prompt(temp_cwd, user_input, expected_res, expected_status):
    with patch('getpass.getuser', return_value='test_user'):
        with patch('builtins.input', return_value=user_input):
            res = confirm_authorization("http://example.com/api", interactive=True, permission_flag=False)
            assert res is expected_res
            
        log_file = os.path.join(temp_cwd, ".llm-api-guard-audit.log")
        assert os.path.exists(log_file)
        with open(log_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        assert len(lines) == 1
        assert f"Status: {expected_status}" in lines[0]

def test_confirm_authorization_keyboard_interrupt(temp_cwd):
    with patch('getpass.getuser', return_value='test_user'):
        with patch('builtins.input', side_effect=KeyboardInterrupt):
            res = confirm_authorization("http://example.com/api", interactive=True, permission_flag=False)
            assert res is False

def test_log_authorization_appends_and_overwrites_not(temp_cwd):
    log_authorization("http://api1.com", "user1", True)
    log_authorization("http://api2.com", "user2", False)
    
    log_file = os.path.join(temp_cwd, ".llm-api-guard-audit.log")
    assert os.path.exists(log_file)
    with open(log_file, "r", encoding="utf-8") as f:
        lines = f.readlines()
    
    assert len(lines) == 2
    assert "Operator: user1" in lines[0]
    assert "URL: http://api1.com" in lines[0]
    assert "Status: GRANTED" in lines[0]
    assert "Operator: user2" in lines[1]
    assert "URL: http://api2.com" in lines[1]
    assert "Status: DENIED" in lines[1]

