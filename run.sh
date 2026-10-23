#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON_CMD="${PYTHON:-python3}"
VENV_DIR="${STEGO_VENV_DIR:-$SCRIPT_DIR/.venv}"
VENV_PYTHON="$VENV_DIR/bin/python"

if [[ ! -x "$VENV_PYTHON" ]]; then
  "$PYTHON_CMD" -m venv "$VENV_DIR"
fi

"$VENV_PYTHON" -m pip install -r "$SCRIPT_DIR/requirements.txt" >/dev/null

if [[ $# -gt 0 ]]; then
  exec "$VENV_PYTHON" "$SCRIPT_DIR/app.py" "$@"
fi

DEMO_DIR="$(mktemp -d "${TMPDIR:-/tmp}/steganography-tk-demo.XXXXXX")"
trap 'rm -rf -- "$DEMO_DIR"' EXIT

"$VENV_PYTHON" -c \
  'from PIL import Image; import sys; Image.new("RGB", (32, 32), (127, 127, 127)).save(sys.argv[1])' \
  "$DEMO_DIR/cover.png"
"$VENV_PYTHON" "$SCRIPT_DIR/app.py" encode \
  --image "$DEMO_DIR/cover.png" \
  --out "$DEMO_DIR/stego.png" \
  --message "Hello, World"
"$VENV_PYTHON" "$SCRIPT_DIR/app.py" decode \
  --image "$DEMO_DIR/stego.png" \
  --out "$DEMO_DIR/recovered.txt"
cmp "$DEMO_DIR/recovered.txt" <(printf '%s' 'Hello, World')
printf '%s\n' 'PNG encode/decode demo completed successfully.'
