#!./venv/bin/python3
"""Extract Bitwarden vault data from browser extension LevelDB storage into a data.json
compatible with brute.py.

The browser extension stores vault data across multiple LevelDB entries with keys like:
    user_<UUID>_kdfConfig_           -> {"kdfType": 0, "iterations": 100000}
    user_<UUID>_crypto_account...    -> {"V1": {"private_key": "2.xxx|yyy|zzz"}}
    masterPasswordUnlock_...         -> {"salt": "email", ..., "masterKeyWrappedUserKey": "2.xxx|yyy|zzz"}
    loginEmail_storedEmail           -> "user@example.com"

This script scans the raw .log and .ldb files, extracts these values, and writes a
data.json that brute.py can use for password testing.

Usage:
    python3 extract_browser_vault.py /path/to/leveldb/folder
    python3 extract_browser_vault.py /path/to/leveldb/folder -o my_vault.json
    python3 extract_browser_vault.py /path/to/leveldb/folder --dump-raw

No extra dependencies required.
"""

import argparse
import glob
import json
import os
import re
import sys


def read_leveldb_raw(db_path):
    """Read all .log and .ldb files into a single byte string."""
    target_files = []
    for ext in ("*.log", "*.ldb"):
        target_files.extend(glob.glob(os.path.join(db_path, ext)))

    if not target_files:
        print(f"ERROR: No .log or .ldb files found in {db_path}", file=sys.stderr)
        sys.exit(1)

    raw = b""
    for filepath in sorted(target_files):
        try:
            with open(filepath, "rb") as f:
                raw += f.read()
        except OSError as e:
            print(f"  Warning: could not read {filepath}: {e}", file=sys.stderr)

    return raw


def extract_json_values(text):
    """Find all {"__json__":true,"value":"..."} blocks and return their parsed inner values.

    Returns list of (preceding_context, parsed_value) tuples.
    """
    results = []
    prefix = '{"__json__":true,"value":"'
    idx = 0

    while True:
        start = text.find(prefix, idx)
        if start < 0:
            break

        val_start = start + len(prefix)

        # Walk to find the closing unescaped quote
        i = val_start
        while i < len(text) - 1:
            if text[i] == '\\':
                i += 2
            elif text[i] == '"':
                break
            else:
                i += 1

        json_end = i + 2  # include "}
        raw_block = text[start:json_end]

        try:
            parsed = json.loads(raw_block)
            inner_raw = parsed["value"]
            try:
                inner = json.loads(inner_raw)
            except (json.JSONDecodeError, TypeError):
                inner = inner_raw

            # Get preceding context to identify the key
            ctx_start = max(0, start - 300)
            preceding = text[ctx_start:start]

            results.append((preceding, inner))
        except (json.JSONDecodeError, KeyError):
            pass

        idx = json_end

    return results


def extract_vault_data(db_path):
    """Extract Bitwarden vault fields from browser extension LevelDB storage."""
    raw = read_leveldb_raw(db_path)
    text = raw.decode("utf-8", errors="replace")

    entries = extract_json_values(text)
    print(f"Found {len(entries)} JSON entries in LevelDB files", file=sys.stderr)

    vault = {}

    for preceding, value in entries:
        # Clean preceding context for matching
        ctx = re.sub(r'[^\x20-\x7e]', ' ', preceding).strip()

        # --- KDF Config ---
        if isinstance(value, dict) and "kdfType" in value and "iterations" in value:
            vault["kdfType"] = value["kdfType"]
            vault["kdfIterations"] = value["iterations"]

        # --- Stored email ---
        if "loginEmail_storedEmail" in ctx and isinstance(value, str) and "@" in value:
            vault["userEmail"] = value

        # --- Crypto account (private key) ---
        if isinstance(value, dict) and "V1" in value:
            v1 = value["V1"]
            if isinstance(v1, dict) and "private_key" in v1:
                vault["encPrivateKey"] = v1["private_key"]

        # --- Master password unlock data (contains the user key / encKey) ---
        if isinstance(value, dict) and "salt" in value:
            if "salt" in value and "@" in str(value.get("salt", "")):
                vault.setdefault("userEmail", value["salt"])

            # The user key is under masterKeyWrappedUserKey (direct or nested)
            user_key = value.get("masterKeyWrappedUserKey")
            if not user_key:
                # May be nested under a sub-object
                for k, v in value.items():
                    if isinstance(v, dict):
                        user_key = v.get("masterKeyWrappedUserKey")
                        if user_key:
                            break
            if user_key:
                vault["encKey"] = user_key

        # --- Global account (may have email) ---
        if isinstance(value, dict) and "global_account" in ctx:
            for uid, info in value.items():
                if isinstance(info, dict) and "email" in info:
                    vault.setdefault("userEmail", info["email"])
                    vault.setdefault("userId", uid)

    # The masterPasswordUnlock entry is sometimes split across binary boundaries.
    # Fall back to regex if we didn't find encKey.
    if "encKey" not in vault:
        # Look for CipherString pattern near "KeyWrappedUser" text
        pattern = re.compile(
            r'KeyWrappedUse[a-zA-Z]*[^2]*?(2\.[A-Za-z0-9+/=]+\|[A-Za-z0-9+/=]+\|[A-Za-z0-9+/=]+)'
        )
        for m in pattern.finditer(text):
            vault["encKey"] = m.group(1)
            break

    # Also try to find email from salt pattern
    if "userEmail" not in vault:
        m = re.search(r'"salt"\s*:\s*"([^"]+@[^"]+)"', text)
        if m:
            vault["userEmail"] = m.group(1)

    # Try to find KDF iterations from raw text if not found
    if "kdfIterations" not in vault:
        m = re.search(r'"iterations"\s*:\s*(\d+)', text)
        if m:
            vault["kdfIterations"] = int(m.group(1))

    # Ensure encOrgKeys exists (even if empty) for compatibility
    vault.setdefault("encOrgKeys", {})

    return vault, entries


def validate_vault(vault):
    """Check that required keys for brute.py are present."""
    required = {"userEmail", "kdfIterations", "encKey", "encPrivateKey"}
    missing = required - set(vault.keys())
    if missing:
        print(f"WARNING: Missing required keys: {', '.join(sorted(missing))}", file=sys.stderr)
        print("", file=sys.stderr)
        print("Extracted keys:", file=sys.stderr)
        for k in sorted(vault.keys()):
            v = str(vault[k])
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
                        help="Dump all extracted JSON entries to stdout for debugging")
    args = parser.parse_args()

    print(f"Reading LevelDB: {args.leveldb_path}", file=sys.stderr)
    vault, all_entries = extract_vault_data(args.leveldb_path)

    if args.dump_raw:
        for ctx, val in all_entries:
            ctx_clean = re.sub(r'[^\x20-\x7e]', ' ', ctx[-100:]).strip()
            val_str = json.dumps(val, default=str)
            if len(val_str) > 200:
                val_str = val_str[:200] + "..."
            print(f"[{ctx_clean[-60:]}] -> {val_str}")
        return

    valid = validate_vault(vault)

    with open(args.output, "w") as f:
        json.dump(vault, f, indent=2)

    if valid:
        print(f"", file=sys.stderr)
        print(f"Extracted to {args.output}:", file=sys.stderr)
        print(f"  Email:        {vault.get('userEmail', '?')}", file=sys.stderr)
        print(f"  KDF iters:    {vault.get('kdfIterations', '?')}", file=sys.stderr)
        print(f"  encKey:       {str(vault.get('encKey', '?'))[:50]}...", file=sys.stderr)
        print(f"  encPrivateKey: {str(vault.get('encPrivateKey', '?'))[:50]}...", file=sys.stderr)
        print(f"", file=sys.stderr)
        print(f"Ready for brute.py:", file=sys.stderr)
        print(f"  python3 brute.py {args.output} wordlist.txt", file=sys.stderr)
    else:
        print(f"Wrote {args.output} — inspect it manually.", file=sys.stderr)


if __name__ == "__main__":
    main()
