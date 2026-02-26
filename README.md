# BitwardenCrackle

A fast, parallel Bitwarden vault brute-forcer with targeted wordlist generation. Fork of [BitwardenDecryptBrute](https://github.com/S3cur3Th1sSh1t/BitwardenDecryptBrute) with major performance improvements.

## What's different from upstream

- **`brute.py`** — Parallel brute-forcer that replaces the slow `decrypt.sh` shell loop. Loads the vault once, tests passwords across all CPU cores, and rejects wrong passwords early via MAC check (no AES decryption needed for mismatches). ~10-100x faster than the original approach.
- **`WordlistGenerator.py`** — Targeted wordlist generator for when you know most of the password but need to test combinations in specific character slots.

## Setup

Requires Python 3.8+. Run the setup script to create a virtual environment and install dependencies:

```bash
bash setup.sh
source venv/bin/activate
```

## Usage

### Fast brute-force (recommended)

```bash
# From a wordlist file
python3 brute.py data.json wordlist.txt

# Piped directly from the wordlist generator (no intermediate file)
python3 WordlistGenerator.py | python3 brute.py data.json -

# Custom worker count
python3 brute.py data.json wordlist.txt -w 8
```

### Generate a targeted wordlist

Edit `WordlistGenerator.py` to set your template and character sets, then run:

```bash
python3 WordlistGenerator.py
```

Use `#` as wildcard slots in the template. Each slot maps to its own configurable character set, so you can narrow the search space per position.

### Legacy shell brute-force

```bash
bash decrypt.sh /path/to/data.json /path/to/wordlist.txt
```

### Where to find your vault data

#### Desktop app

The desktop app stores your vault as a plain `data.json` file. Pass it directly to `brute.py`.

See: https://bitwarden.com/help/article/where-is-data-stored-computer/

#### Browser extension

The browser extension stores the same encrypted vault data inside a **LevelDB** database rather than a plain JSON file. You need to find the storage folder and extract the JSON from it.

**Step 1: Find the storage folder**

Look for the Bitwarden extension ID (usually `nngceckbapebfimnlniiiahkandclblb` for Chrome/Edge-based browsers).

| Browser | OS | Path |
|---|---|---|
| Chrome | Windows | `%LocalAppData%\Google\Chrome\User Data\Default\Local Extension Settings\nngceckbapebfimnlniiiahkandclblb` |
| Chrome | macOS | `~/Library/Application Support/Google/Chrome/Default/Local Extension Settings/nngceckbapebfimnlniiiahkandclblb` |
| Chrome | Linux | `~/.config/google-chrome/Default/Local Extension Settings/nngceckbapebfimnlniiiahkandclblb` |
| Firefox | Windows | `%AppData%\Mozilla\Firefox\Profiles\[your-profile]\storage\default\moz-extension+++[UUID]` |
| Edge | Windows | `%LocalAppData%\Microsoft\Edge\User Data\Default\Local Extension Settings\jbkfoedolllekgbhcbcoahefnbanhhlh` |

Inside that folder you'll see LevelDB files like `000003.log`, `CURRENT`, `MANIFEST-000001` — not a `data.json`.

**Step 2: Extract JSON from LevelDB**

Use the included `extract_browser_vault.py` to dump the LevelDB into a `data.json` that BitwardenCrackle can read:

```bash
# plyvel is included in requirements.txt / setup.sh

# Extract vault data
python3 extract_browser_vault.py /path/to/extension/leveldb/folder

# If the key structure looks off, dump all raw entries to inspect
python3 extract_browser_vault.py /path/to/extension/leveldb/folder --dump-raw
```

The script validates that the required keys (`userEmail`, `kdfIterations`, `encKey`, `encPrivateKey`) are present and warns you if anything is missing. Then use the extracted `data.json` with `brute.py` as normal.

## How it works

```
password
  -> PBKDF2-SHA256 (salt=email, N iterations) -> master key
  -> HKDF-Expand (info="mac")                 -> stretched MAC key
  -> HMAC-SHA256 check against stored MAC      -> REJECT on mismatch (fast path)
  -> HKDF-Expand (info="enc")                 -> stretched encryption key
  -> AES-CBC decrypt + PKCS7 unpad            -> CONFIRM match
  -> full vault decryption                     -> Cleartext.json
```

On success, the decrypted vault is written to `Cleartext.json`.

## Limitations

- Does not work with Bitwarden Encrypted JSON Exports (these lack the Protected Symmetric Key needed to decrypt entries)
- Can only decrypt EncryptionType: 2 (AesCbc256_HmacSha256_B64) — this is the default for personal vault entries
- Initial support for EncryptionType: 4 (Rsa2048_OaepSha1_B64) for Organization/Collection items

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

* [Kyle Spearrin](https://github.com/kspearrin) for creating [Bitwarden](https://github.com/bitwarden).
* Joshua Stein ([Rubywarden](https://github.com/jcs/rubywarden)) for the reverse engineered Bitwarden documentation.
* [GurpreetKang](https://github.com/GurpreetKang) for the code base - [BitwardenDecrypt](https://github.com/GurpreetKang/BitwardenDecrypt)
* [S3cur3Th1sSh1t](https://github.com/S3cur3Th1sSh1t/BitwardenDecryptBrute) for the brute-force wrapper.
