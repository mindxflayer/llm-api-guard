import os
import re
import ast
from scanner.static.hardcoded_keys import OPENAI_RE, AWS_RE, ENV_LINE_RE, SECRET_KEYWORDS, should_filter
from scanner.secret_rules.loader import load_ruleset
from scanner.entropy import secret_likelihood_score

rules_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "secret_rules", "gitleaks.toml")
try:
    rules = load_ruleset(rules_path)
except Exception:
    rules = []

STRING_LITERAL_RE = re.compile(
    r'"""[\s\S]*?"""|'
    r"'''[\s\S]*?'''|"
    r'`[\s\S]*?`|'
    r'"[^"\\]*(?:\\.[^"\\]*)*"|'
    r"'[^'\\]*(?:\\.[^'\\]*)*'"
)

def is_secret(val: str) -> bool:
    threshold = 70
    filepath = "dummy.py"
    if OPENAI_RE.search(val):
        return True
    if AWS_RE.search(val):
        return True
    for rule in rules:
        for m in rule["regex"].finditer(val):
            rule_val = m.group(1) if m.groups() and m.group(1) else m.group(0)
            if not should_filter(rule_val, filepath, threshold):
                return True
    if not should_filter(val, filepath, threshold):
        try:
            if secret_likelihood_score(val) >= threshold:
                return True
        except Exception:
            pass
    return False

def string_replacer(match) -> str:
    literal_val = match.group(0)
    inner_val = literal_val
    if inner_val.startswith('"""') and inner_val.endswith('"""'):
        inner_val = inner_val[3:-3]
    elif inner_val.startswith("'''") and inner_val.endswith("'''"):
        inner_val = inner_val[3:-3]
    elif (inner_val.startswith('"') and inner_val.endswith('"')) or \
         (inner_val.startswith("'") and inner_val.endswith("'")) or \
         (inner_val.startswith('`') and inner_val.endswith('`')):
        inner_val = inner_val[1:-1]
        
    if is_secret(inner_val):
        return "[REDACTED_SECRET]"
    return "[REDACTED_STRING]"

def redact_standalone_secrets(text: str) -> str:
    text = OPENAI_RE.sub("[REDACTED_SECRET]", text)
    text = AWS_RE.sub("[REDACTED_SECRET]", text)
    
    threshold = 70
    filepath = "dummy.py"
    matches_to_replace = []
    
    for rule in rules:
        for m in rule["regex"].finditer(text):
            val = m.group(1) if m.groups() and m.group(1) else m.group(0)
            if not should_filter(val, filepath, threshold):
                matches_to_replace.append(val)
                
    try:
        tree = ast.parse(text)
        from scanner.static.hardcoded_keys import SecretAssignmentVisitor
        visitor = SecretAssignmentVisitor()
        visitor.visit(tree)
        for var_name, val, _ in visitor.assignments:
            if any(kw in var_name.lower() for kw in SECRET_KEYWORDS):
                if not should_filter(val, filepath, threshold):
                    matches_to_replace.append(val)
    except Exception:
        pass

    for val in sorted(list(set(matches_to_replace)), key=len, reverse=True):
        if val:
            text = text.replace(val, "[REDACTED_SECRET]")
    return text

def redact_text(text: str) -> str:
    if not isinstance(text, str):
        return text
    text = redact_standalone_secrets(text)
    text = STRING_LITERAL_RE.sub(string_replacer, text)
    text = re.sub(r'/\*[\s\S]*?\*/', '[REDACTED_COMMENT]', text)
    text = re.sub(r'//.*', '[REDACTED_COMMENT]', text)
    text = re.sub(r'#.*', '[REDACTED_COMMENT]', text)
    return text

def redact_finding_context(finding_context: dict) -> dict:
    new_context = dict(finding_context)
    keys_to_redact = {"code_snippet", "snippet", "transcript", "context_val", "context", "message"}
    for k in keys_to_redact:
        if k in new_context and isinstance(new_context[k], str):
            new_context[k] = redact_text(new_context[k])
    return new_context
