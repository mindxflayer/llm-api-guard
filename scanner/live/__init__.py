import os
import getpass
import datetime

def log_authorization(target_url: str, operator: str, granted: bool) -> None:
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    status = "GRANTED" if granted else "DENIED"
    log_line = f"[{timestamp}] Operator: {operator} | URL: {target_url} | Status: {status}\n"
    audit_file_path = os.path.join(os.getcwd(), ".llm-api-guard-audit.log")
    with open(audit_file_path, "a", encoding="utf-8") as f:
        f.write(log_line)

def confirm_authorization(target_url: str, interactive: bool = True, permission_flag: bool = False) -> bool:
    try:
        operator = getpass.getuser()
    except Exception:
        operator = "unknown"

    if permission_flag:
        log_authorization(target_url, operator, True)
        return True

    if not interactive:
        log_authorization(target_url, operator, False)
        return False

    print("=" * 60)
    print("WARNING: Live scanning sends REAL HTTP requests to the target endpoint.")
    print("This may include rate-limit probes and active prompt injection payloads.")
    print(f"Target URL: {target_url}")
    print("=" * 60)
    
    try:
        user_input = input("Do you confirm and authorize this live scan? (y/n): ")
    except (KeyboardInterrupt, EOFError):
        user_input = ""

    granted = user_input.strip().lower() in ("y", "yes")
    log_authorization(target_url, operator, granted)
    return granted

