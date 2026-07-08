def tool(func):
    return func

@tool
def read_file(filepath):
    allowlist = ["/app/data/safe.txt"]
    if filepath not in allowlist:
        return "Access denied"
    with open(filepath, "r") as f:
        return f.read()
