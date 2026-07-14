import math
import pytest
from scanner.entropy import shannon_entropy, char_class_diversity, secret_likelihood_score, is_valid_uuid

def test_shannon_entropy_calculation():
    val = shannon_entropy("abc")
    assert math.isclose(val, 1.584962500721156, rel_tol=1e-9)

def test_secret_likelihood_score_realistic_token():
    random_token = "aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV"
    score = secret_likelihood_score(random_token)
    assert score > 70

def test_secret_likelihood_score_english_phrase():
    sentence = "The quick brown fox jumps over the lazy dog."
    score = secret_likelihood_score(sentence)
    assert score < 30

def test_secret_likelihood_score_short_string():
    for short_str in ("a", "ab", "abc", "abcd", "abcde", "abcdef", "abcdefg"):
        assert secret_likelihood_score(short_str) == 0

def test_secret_likelihood_score_repeated():
    assert secret_likelihood_score("aaaaaaaaaaaa") == 0
    assert secret_likelihood_score("12345678") == 0
    assert secret_likelihood_score("123456789012") < 20

def test_uuid_validation():
    assert is_valid_uuid("123e4567-e89b-12d3-a456-426614174000") is True
    assert is_valid_uuid("invalid-uuid-string-12345") is False
