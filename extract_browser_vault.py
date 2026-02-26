#!/usr/bin/env python3
"""Extract Bitwarden vault data from browser extension LevelDB storage into a data.json
compatible with BitwardenDecrypt.py and brute.py.

Usage:
    python3 extract_browser_vault.py /path/to/leveldb/folder
    python3 extract_browser_vault.py /path/to/leveldb/folder -o my_vault.json

The LevelDB folder is the extension's local storage directory containing files like
000003.log, CURRENT, MANIFEST-000001, etc. See README.md for paths per browser/OS.

Requires: pip install plyvel
"""

import argparse
import json
import sys

try:
    import plyvel
except ModuleNotFoundError:
    print("This script requires the 'plyvel' package.")
    print("Install it with: pip install plyvel")
    sys.exit(1)


# Keys that BitwardenDecrypt.py / brute.py expect at the top level of data.json
REQUIRED_KEYS = {"userEmail", "kdfIterations", "encKey", "encPrivateKey"}
OPTIONAL_KEYS = {"userId", "encOrgKeys"}
# Prefixes for vault collection data
COLLECTION_PREFIXES = ("folders_", "ciphers_", "organizations_", "collections_", "sends_")


def extract_from_leveldb(db_path):
    """Read all key-value pairs from a LevelDB database."""
    try:
        db = plyvel.DB(db_path, create_if_missing=False)
    except Exception as e:
        print(f"ERROR: Could not open LevelDB at {db_path}: {e}", file=sys.stderr)
        sys.exit(1)

    entries = {}
    for raw_key, raw_value in db:
        try:
            key = raw_key.decode("utf-8")
        except UnicodeDecodeError:
            continue

        try:
            value = json.loads(raw_value.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            # Store raw string if it's not JSON
            try:
                value = raw_value.decode("utf-8")
            except UnicodeDecodeError:
                continue

        entries[key] = value

    db.close()
    return entries


def build_data_json(entries):
    """Map LevelDB entries to a data.json-compatible dict.

    The browser extension may store keys directly (e.g. "userEmail") or
    nested inside a wrapper. This function handles both cases.
    """
    data = {}

    # Check if entries are already in the expected flat format
    if any(k in entries for k in REQUIRED_KEYS):
        data = entries
    else:
        # Some versions nest data under a user ID key or other wrapper.
        # Try to find required keys anywhere in the values.
        for key, value in entries.items():
            if isinstance(value, dict):
                if any(k in value for k in REQUIRED_KEYS):
                    # Found a nested dict containing vault keys — merge it up
                    data.update(value)
                    break

        # If still not found, flatten all dict values as a last resort
        if not any(k in data for k in REQUIRED_KEYS):
            for key, value in entries.items():
                if isinstance(value, str) or isinstance(value, (int, float)):
                    data[key] = value
                elif isinstance(value, dict):
                    data.update(value)

    return data


def validate_data(data):
    """Check that the extracted data has the required keys for decryption."""
    missing = REQUIRED_KEYS - set(data.keys())
    if missing:
        print(f"WARNING: Missing required keys: {', '.join(sorted(missing))}", file=sys.stderr)
        print("The extracted data.json may not work with brute.py/BitwardenDecrypt.py.", file=sys.stderr)
        print("", file=sys.stderr)
        print("Available keys:", file=sys.stderr)
        for k in sorted(data.keys()):
            v = str(data[k])
            preview = v[:80] + "..." if len(v) > 80 else v
            print(f"  {k}: {preview}", file=sys.stderr)
        return False
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Extract Bitwarden vault data from browser extension LevelDB storage."
    )
    parser.add_argument("leveldb_path", help="Path to the LevelDB folder (extension local storage)")
    parser.add_argument("-o", "--output", default="data.json", help="Output file (default: data.json)")
    parser.add_argument("--dump-raw", action="store_true",
                        help="Dump all raw LevelDB entries to stdout for debugging")
    args = parser.parse_args()

    print(f"Reading LevelDB: {args.leveldb_path}", file=sys.stderr)
    entries = extract_from_leveldb(args.leveldb_path)
    print(f"Found {len(entries)} entries", file=sys.stderr)

    if args.dump_raw:
        print(json.dumps(entries, indent=2, default=str))
        return

    data = build_data_json(entries)
    valid = validate_data(data)

    with open(args.output, "w") as f:
        json.dump(data, f, indent=2)

    if valid:
        print(f"Extracted to {args.output} — ready for brute.py", file=sys.stderr)
    else:
        print(f"Wrote {args.output} anyway — inspect it manually to check the structure.", file=sys.stderr)


if __name__ == "__main__":
    main()
