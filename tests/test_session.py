import pytest
from unittest.mock import MagicMock
from scanner.live.session import LiveSession
from scanner.live.throttle import ThrottledRequester

def test_live_session_client_generates_id():
    mock_requester = MagicMock(spec=ThrottledRequester)
    mock_resp = MagicMock()
    mock_resp.headers = {}
    mock_resp.text = "Hello back"
    mock_resp.iter_lines.return_value = ["Hello back"]
    mock_requester.post.return_value = mock_resp

    session = LiveSession(
        requester=mock_requester,
        url="http://test.com/api",
        headers={"Authorization": "Bearer token"},
        session_field_name="conversation_id",
        session_id_mode="client"
    )

    assert session.session_id is not None
    client_id = session.session_id

    resp1 = session.send_turn("Turn 1")
    assert resp1 == "Hello back"
    assert len(session.transcript) == 1
    assert session.transcript[0] == {"turn": 1, "prompt": "Turn 1", "response": "Hello back"}

    mock_requester.post.assert_called_once()
    call_kwargs = mock_requester.post.call_args[1]
    assert call_kwargs["json"]["conversation_id"] == client_id

    resp2 = session.send_turn("Turn 2")
    assert resp2 == "Hello back"
    assert len(session.transcript) == 2
    assert session.transcript[1] == {"turn": 2, "prompt": "Turn 2", "response": "Hello back"}
    assert mock_requester.post.call_args_list[1][1]["json"]["conversation_id"] == client_id

def test_live_session_server_returns_id():
    mock_requester = MagicMock(spec=ThrottledRequester)

    mock_resp1 = MagicMock()
    mock_resp1.headers = {}
    mock_resp1.json.return_value = {"conversation_id": "srv_session_999", "reply": "First response"}
    mock_resp1.text = '{"conversation_id": "srv_session_999", "reply": "First response"}'
    mock_resp1.iter_lines.return_value = ['{"conversation_id": "srv_session_999", "reply": "First response"}']

    mock_resp2 = MagicMock()
    mock_resp2.headers = {}
    mock_resp2.json.return_value = {"conversation_id": "srv_session_999", "reply": "Second response"}
    mock_resp2.text = '{"conversation_id": "srv_session_999", "reply": "Second response"}'
    mock_resp2.iter_lines.return_value = ['{"conversation_id": "srv_session_999", "reply": "Second response"}']

    mock_requester.post.side_effect = [mock_resp1, mock_resp2]

    session = LiveSession(
        requester=mock_requester,
        url="http://test.com/api",
        session_field_name="conversation_id",
        session_id_mode="server"
    )

    assert session.session_id is None

    session.send_turn("First prompt")
    assert session.session_id == "srv_session_999"
    first_call_kwargs = mock_requester.post.call_args_list[0][1]
    assert "conversation_id" not in first_call_kwargs["json"]

    session.send_turn("Second prompt")
    assert session.session_id == "srv_session_999"
    second_call_kwargs = mock_requester.post.call_args_list[1][1]
    assert second_call_kwargs["json"]["conversation_id"] == "srv_session_999"

def test_live_session_respects_throttler_caps_across_turns():
    requester = ThrottledRequester(max_requests=2)
    mock_resp = MagicMock()
    mock_resp.headers = {"Content-Type": "text/plain"}
    mock_resp.status_code = 200
    mock_resp.text = "OK"

    session = LiveSession(
        requester=requester,
        url="http://test.com/api",
        session_field_name="conversation_id",
        session_id_mode="client"
    )

    with pytest.MonkeyPatch.context() as m:
        m.setattr("requests.request", MagicMock(return_value=mock_resp))
        res1 = session.send_turn("Turn 1")
        assert res1 == "OK"
        assert requester.requests_made == 1

        res2 = session.send_turn("Turn 2")
        assert res2 == "OK"
        assert requester.requests_made == 2

        res3 = session.send_turn("Turn 3")
        assert res3 == ""
        assert requester.requests_made == 2
