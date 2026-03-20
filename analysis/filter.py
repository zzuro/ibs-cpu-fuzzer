#!/usr/bin/env python3
from pathlib import Path
import json
import sys

LOG_DIR = Path("/home/avezzu/ibs-cpu-fuzzer/logs/ibs_findings")


def should_remove_entry(entry: dict) -> bool:
    """
    Apply the filtering criteria to a single res_entry item:

    """
    #RMP protected
    LOW = 0xA0000000
    HIGH = 0xA4000000
    PAGE_SIZE = 0x1000
    msr = [0xfffffc079b87c, 0xfffffc059b87c, 0xfffffc059b87c, 0xfffffc079c95c]

    phys = int(entry["phys_addr"], 16)
    lin = int(entry["lin_addr"], 16)
    uop_cnt = int(entry["uop_cnt"])
    if uop_cnt > 1300:
        return True
    if lin != 0:
        return True
    in_fixed_range = LOW <= phys <= HIGH
    if in_fixed_range:
        return True
    for msr_val in msr:
        page_base = msr_val & ~(PAGE_SIZE - 1)
        if page_base <= phys < page_base + PAGE_SIZE:
            return True
        
    return False


def process_json_file(path: Path) -> str:
    """
    Process one JSON file:
    - remove res_entry items whose phys_addr starts with 0x1d
    - delete the whole file if res_entry becomes empty
    """
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        return f"[ERROR] Failed to read {path}: {e}"

    if not isinstance(data, dict):
        return f"[SKIP] {path}: top-level JSON is not an object"

    res_entry = data.get("res_entry")
    if not isinstance(res_entry, list):
        return f"[SKIP] {path}: missing or invalid 'res_entry'"

    original_count = len(res_entry)
    filtered_res_entry = [entry for entry in res_entry if not should_remove_entry(entry)]
    removed_count = original_count - len(filtered_res_entry)

    if not filtered_res_entry:
        try:
            path.unlink()
            return f"[DELETE] {path} (removed {removed_count} entries, res_entry became empty)"
        except Exception as e:
            return f"[ERROR] Failed to delete {path}: {e}"

    data["res_entry"] = filtered_res_entry

    try:
        with path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
        return f"[UPDATE] {path} (removed {removed_count} entries, kept {len(filtered_res_entry)})"
    except Exception as e:
        return f"[ERROR] Failed to write {path}: {e}"


def main() -> int:
    if not LOG_DIR.exists():
        print(f"Directory does not exist: {LOG_DIR}")
        return

    for json_file in LOG_DIR.rglob("*.json"):
        print(process_json_file(json_file))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())