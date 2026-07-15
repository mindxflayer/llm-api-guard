import os
import sys
import urllib.request

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scanner.secret_rules.loader import load_ruleset

RULES_URL = "https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml"
RULES_PATH = "scanner/secret_rules/gitleaks.toml"
TEMP_PATH = "scanner/secret_rules/gitleaks.toml.tmp"


def main():
    print(f"Fetching latest Gitleaks ruleset from {RULES_URL}...")
    old_count = 0
    if os.path.exists(RULES_PATH):
        try:
            old_rules = load_ruleset(RULES_PATH)
            old_count = len(old_rules)
            print(f"Current ruleset has {old_count} rules.")
        except Exception as e:
            print(f"Warning: Failed to parse existing ruleset: {e}. Assuming count is 0.")
    else:
        print("No existing ruleset found. This will write a new one.")

    os.makedirs(os.path.dirname(RULES_PATH), exist_ok=True)

    try:
        urllib.request.urlretrieve(RULES_URL, TEMP_PATH)
    except Exception as e:
        print(f"Error: Failed to download upstream ruleset: {e}", file=sys.stderr)
        if os.path.exists(TEMP_PATH):
            os.remove(TEMP_PATH)
        sys.exit(1)

    try:
        new_rules = load_ruleset(TEMP_PATH)
        new_count = len(new_rules)
    except Exception as e:
        print(f"Error: The downloaded ruleset is malformed or invalid: {e}", file=sys.stderr)
        if os.path.exists(TEMP_PATH):
            os.remove(TEMP_PATH)
        sys.exit(1)

    try:
        if os.path.exists(RULES_PATH):
            os.remove(RULES_PATH)
        os.rename(TEMP_PATH, RULES_PATH)
    except Exception as e:
        print(f"Error: Failed to replace ruleset file: {e}", file=sys.stderr)
        if os.path.exists(TEMP_PATH):
            os.remove(TEMP_PATH)
        sys.exit(1)

    diff = new_count - old_count
    print("--------------------------------------------------")
    print("Secret detection ruleset updated successfully.")
    print(f"Old rule count: {old_count}")
    print(f"New rule count: {new_count}")
    print(f"Difference: {diff:+} rules")
    print("--------------------------------------------------")


if __name__ == "__main__":
    main()
