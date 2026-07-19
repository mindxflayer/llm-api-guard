import os
import re

# Regex to find emojis
emoji_pattern = re.compile(
    r"[\U00010000-\U0010FFFF\u2600-\u26FF\u2700-\u27BF\u2300-\u23FF]"
)

py_files = []
for root, dirs, files in os.walk("."):
    if any(p in root for p in ["venv", ".git", ".pytest_cache", ".gemini", "brain"]):
        continue
    for file in files:
        if file.endswith(".py"):
            py_files.append(os.path.join(root, file))

output = []
output.append(f"Scanning {len(py_files)} Python files...")

for path in py_files:
    if "find_cleanup_details.py" in path:
        continue
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    content = "".join(lines)
    emojis_found = emoji_pattern.findall(content)
    
    comment_lines = []
    for idx, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            comment_lines.append((idx, line.strip()))
        elif "#" in line:
            # Simple check for # in line
            comment_lines.append((idx, line.strip()))

    docstring_matches = list(re.finditer(r'"""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'', content))
    
    if emojis_found or comment_lines or docstring_matches:
        output.append(f"\n========================================\nFILE: {path}")
        if emojis_found:
            output.append(f"  Emojis found: {emojis_found}")
        if docstring_matches:
            output.append(f"  Docstrings: {len(docstring_matches)} found")
        if comment_lines:
            output.append(f"  Comments count: {len(comment_lines)}")
            for idx, c in comment_lines[:10]:
                output.append(f"    Line {idx}: {c}")

with open("cleanup_report.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(output))
print("Done writing report.")
