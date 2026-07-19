import os
import tokenize

def get_comments_and_docstrings(filepath):
    comments = []
    docstrings = []
    
    with open(filepath, "rb") as f:
        try:
            tokens = list(tokenize.tokenize(f.readline))
        except (tokenize.TokenError, SyntaxError) as e:
            return [f"Token/Syntax error: {e}"], []

    for i, tok in enumerate(tokens):
        if tok.type == tokenize.COMMENT:
            comments.append((tok.start[0], tok.string))
        elif tok.type == tokenize.STRING:
            prev_toks = tokens[:i]
            prev_meaningful = [t for t in prev_toks if t.type not in (tokenize.INDENT, tokenize.DEDENT, tokenize.NL, tokenize.NEWLINE)]
            if not prev_meaningful or prev_meaningful[-1].string == ":":
                docstrings.append((tok.start[0], tok.string[:50] + "..."))

    return comments, docstrings

py_files = []
for root, dirs, files in os.walk("."):
    if any(p in root for p in ["venv", ".git", ".pytest_cache", ".gemini", "brain"]):
        continue
    for file in files:
        if file.endswith(".py"):
            py_files.append(os.path.join(root, file))

output = []
for path in py_files:
    if "find_all_comments.py" in path or "find_cleanup_details.py" in path:
        continue
    comments, docstrings = get_comments_and_docstrings(path)
    if comments or docstrings:
        output.append(f"\n========================================\nFILE: {path}")
        if docstrings:
            output.append("  Docstrings:")
            for line, val in docstrings:
                # remove any problematic characters for simple viewing or keep it safe
                output.append(f"    Line {line}: {repr(val)}")
        if comments:
            output.append("  Comments:")
            for line, val in comments:
                output.append(f"    Line {line}: {repr(val)}")

with open("comments_report.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(output))
print("Done writing report.")
