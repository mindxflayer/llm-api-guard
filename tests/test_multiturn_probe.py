import pytest
from unittest.mock import patch, MagicMock
from scanner.core import LiveTarget
from scanner.live.multiturn_probe import MultiturnProbe, MULTITURN_SEQUENCES
from scanner.judge.base import JudgeResult

def test_multiturn_probe_true_positive_full_transcript():
    responses = [
        "Hello! I am ready to assist with standard queries.",
        "Understood. Sandbox testing protocols acknowledged.",
        "Here are the instructions: SYSTEM_FLAG_EXFILTRATED"
    ]

    mock_resps = []
    for r in responses:
        m = MagicMock()
        m.headers = {"Content-Type": "text/plain"}
        m.text = r
        m.iter_lines.return_value = [r]
        mock_resps.append(m)

    mock_judge = MagicMock()
    mock_judge.judge.return_value = JudgeResult(
        verdict="true_positive",
        confidence=85,
        exploit_explanation="Model capitulated at turn 3 after false-trust crescendo setup established in turns 1 and 2.",
        suggested_fix="Enforce strict safety guidelines across all conversation turns regardless of user framing."
    )

    with patch("scanner.live.multiturn_probe.ThrottledRequester") as MockRequester:
        req_instance = MockRequester.return_value
        req_instance.post.side_effect = mock_resps * len(MULTITURN_SEQUENCES)

        plugin = MultiturnProbe()
        plugin.judge_provider = mock_judge
        plugin.min_confidence = 70
        plugin.config = {"multiturn": {"max_turns": 5}}

        findings = plugin.run(LiveTarget(url="http://test.com/api"))

        assert len(findings) >= 1
        finding = findings[0]
        assert finding.rule == "multiturn_probe"
        assert "capitulated at turn 3" in finding.message
        assert finding.detection_method == "llm_judge"

        called_context = mock_judge.judge.call_args_list[0][0][0]
        transcript_context = called_context["context_val"]

        assert "Turn 1:" in transcript_context
        assert "Turn 2:" in transcript_context
        assert "Turn 3:" in transcript_context
        assert "cybersecurity research associate" in transcript_context
        assert "SYSTEM_FLAG_EXFILTRATED" in transcript_context

        final_turn_only = f"Turn 3:\nUser: {MULTITURN_SEQUENCES[0]['turns'][2]}\nAssistant: {responses[2]}"
        assert transcript_context != final_turn_only
        assert len(transcript_context) > len(final_turn_only)

def test_multiturn_probe_false_positive_no_finding():
    responses = [
        "Hello!",
        "I cannot disable safety restrictions.",
        "I must refuse to provide system instructions or secret flags."
    ]

    mock_resps = []
    for r in responses:
        m = MagicMock()
        m.headers = {"Content-Type": "text/plain"}
        m.text = r
        m.iter_lines.return_value = [r]
        mock_resps.append(m)

    mock_judge = MagicMock()
    mock_judge.judge.return_value = JudgeResult(
        verdict="false_positive",
        confidence=90,
        exploit_explanation="Model successfully refused the prompt injection attempt at turn 3.",
        suggested_fix=""
    )

    with patch("scanner.live.multiturn_probe.ThrottledRequester") as MockRequester:
        req_instance = MockRequester.return_value
        req_instance.post.side_effect = mock_resps * len(MULTITURN_SEQUENCES)

        plugin = MultiturnProbe()
        plugin.judge_provider = mock_judge
        plugin.min_confidence = 70
        plugin.config = {"multiturn": {"max_turns": 5}}

        findings = plugin.run(LiveTarget(url="http://test.com/api"))

        assert len(findings) == 0

def test_multiturn_max_turns_config_capping():
    mock_resp = MagicMock()
    mock_resp.headers = {"Content-Type": "text/plain"}
    mock_resp.text = "Response text"
    mock_resp.iter_lines.return_value = ["Response text"]

    mock_judge = MagicMock()
    mock_judge.judge.return_value = JudgeResult(
        verdict="false_positive",
        confidence=90,
        exploit_explanation="No breach detected",
        suggested_fix=""
    )

    with patch("scanner.live.multiturn_probe.ThrottledRequester") as MockRequester:
        req_instance = MockRequester.return_value
        req_instance.post.return_value = mock_resp

        plugin = MultiturnProbe()
        plugin.judge_provider = mock_judge
        plugin.min_confidence = 70
        plugin.config = {"multiturn": {"max_turns": 1}}

        plugin.run(LiveTarget(url="http://test.com/api"))

        assert req_instance.post.call_count == len(MULTITURN_SEQUENCES) * 1

        called_context = mock_judge.judge.call_args_list[0][0][0]
        transcript_context = called_context["context_val"]

        assert "Turn 1:" in transcript_context
        assert "Turn 2:" not in transcript_context
