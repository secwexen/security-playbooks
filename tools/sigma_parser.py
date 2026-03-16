import yaml
from pathlib import Path

RULES_DIR = Path("detection-rules/sigma")

def load_sigma_rule(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def main() -> None:
    if not RULES_DIR.exists():
        print(f"[!] Sigma rules directory not found: {RULES_DIR}")
        return

    print(f"[+] Loading Sigma rules from: {RULES_DIR}")
    for rule_file in RULES_DIR.glob("*.yml"):
        rule = load_sigma_rule(rule_file)
        print(f"\n=== {rule_file.name} ===")
        print(f"Title   : {rule.get('title')}")
        print(f"ID      : {rule.get('id')}")
        print(f"Status  : {rule.get('status')}")
        print(f"Level   : {rule.get('level')}")
        print(f"Tags    : {rule.get('tags')}")

if __name__ == "__main__":
    main()
