def tool(func):
    return func

def validate_path(filepath):
    allowlist = ["/app/data/safe.txt"]
    if filepath not in allowlist:
        raise ValueError("Access denied")

@tool
def read_file(filepath):
    validate_path(filepath)
    with open(filepath, "r") as f:
        return f.read()

