import math
import uuid
from collections import Counter

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    cnt = Counter(s)
    total = len(s)
    entropy = 0.0
    for count in cnt.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy

def char_class_diversity(s: str) -> float:
    if not s:
        return 0.0
    classes = 0
    if any(c.isupper() for c in s):
        classes += 1
    if any(c.islower() for c in s):
        classes += 1
    if any(c.isdigit() for c in s):
        classes += 1
    if any(not c.isalnum() for c in s):
        classes += 1
    return classes / 4.0

def secret_likelihood_score(s: str) -> int:
    if len(s) < 8:
        return 0
    if len(s) >= 3:
        diffs = [ord(s[i]) - ord(s[i-1]) for i in range(1, len(s))]
        if len(set(diffs)) == 1 and diffs[0] in (1, -1, 0):
            return 0
    h = shannon_entropy(s)
    if h <= 2.2:
        entropy_factor = 0.0
    else:
        entropy_factor = min(1.0, (h - 2.2) / 2.5)
    div = char_class_diversity(s)
    diversity_factor = 0.1 + 0.9 * div
    if len(s) <= 16:
        length_factor = 0.6 + 0.4 * (len(s) - 8) / 8
    else:
        length_factor = 1.0
    score = int(100.0 * entropy_factor * diversity_factor * length_factor)
    if any(c.isspace() for c in s):
        score = int(score * 0.1)
    return min(100, max(0, score))

def is_valid_uuid(s: str) -> bool:
    try:
        uuid.UUID(s)
        return True
    except ValueError:
        return False
