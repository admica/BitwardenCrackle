#!/usr/bin/env bash
set -euo pipefail

MIN_PYTHON="3.8"
VENV_DIR="venv"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Find a python3 binary ────────────────────────────────────────────────
PYTHON=""
for candidate in python3 python; do
    if command -v "$candidate" &>/dev/null; then
        PYTHON="$candidate"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    echo "ERROR: No python3 or python found in PATH."
    echo "Install Python ${MIN_PYTHON}+ and make sure it's on your PATH."
    exit 1
fi

# ── Check version ────────────────────────────────────────────────────────
PY_VERSION=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_OK=$("$PYTHON" -c "import sys; print(int(sys.version_info >= (3, 8)))")

if [ "$PY_OK" != "1" ]; then
    echo "ERROR: Python ${MIN_PYTHON}+ is required, but found Python ${PY_VERSION}."
    exit 1
fi

echo "Using $PYTHON ($PY_VERSION)"

# ── Check that venv module is available ──────────────────────────────────
if ! "$PYTHON" -c "import venv" &>/dev/null; then
    echo ""
    echo "ERROR: Python 'venv' module is not available."
    echo "On Debian/Ubuntu this is a separate package. Install it with:"
    echo "  sudo apt install python3-venv"
    echo ""
    echo "On other distros it is usually included with python3."
    exit 1
fi

# ── Create venv ──────────────────────────────────────────────────────────
if [ -d "$VENV_DIR" ]; then
    echo "Removing existing venv..."
    rm -rf "$VENV_DIR"
fi

echo "Creating virtual environment in ./${VENV_DIR}..."
"$PYTHON" -m venv "$VENV_DIR"

# ── Install core requirements ────────────────────────────────────────────
echo "Installing core dependencies..."
"${VENV_DIR}/bin/pip" install --upgrade pip --quiet
"${VENV_DIR}/bin/pip" install -r requirements.txt --quiet

# ── Try to install plyvel (optional, for browser vault extraction) ───────
echo ""
echo "Installing plyvel (optional — needed for extract_browser_vault.py)..."
if "${VENV_DIR}/bin/pip" install plyvel --quiet 2>/dev/null; then
    echo "  plyvel installed successfully."
else
    echo "  WARNING: plyvel failed to install. This is only needed if you want to"
    echo "  extract vault data from a browser extension's LevelDB storage."
    echo "  It requires the LevelDB C library headers to compile:"
    echo "    Debian/Ubuntu:  sudo apt install libleveldb-dev"
    echo "    RHEL/Fedora:    sudo dnf install leveldb-devel"
    echo "  Then re-run: ${VENV_DIR}/bin/pip install plyvel"
fi

echo ""
echo "Done. Activate the venv with:"
echo "  source ${VENV_DIR}/bin/activate"
echo ""
echo "Then run:"
echo "  python3 brute.py data.json wordlist.txt"
