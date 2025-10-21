#!/usr/bin/env bash
set -euo pipefail

# Path setup
REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_DIR="/opt/autopwn-suite"
VENV_DIR="$TARGET_DIR/.venv"
WRAPPER="/usr/local/bin/autopwn-suite"

echo "[1/4] Copying repo to $TARGET_DIR ..."
sudo rm -rf "$TARGET_DIR"
sudo mkdir -p "$TARGET_DIR"
rsync -a --exclude='.venv' --exclude='/.git' "$REPO_DIR"/ "$TARGET_DIR"/
sudo chown -R "$USER":"$USER" "$TARGET_DIR"

echo "[2/4] Creating virtual environment at $VENV_DIR ..."
python3 -m venv "$VENV_DIR"

echo "[3/4] Installing Python dependencies ..."
source "$VENV_DIR/bin/activate"
pip install --upgrade pip setuptools wheel
if [ -f "$TARGET_DIR/requirements.txt" ]; then
    pip install -r "$TARGET_DIR/requirements.txt"
fi
deactivate

echo "[4/4] Creating wrapper command at $WRAPPER ..."
sudo tee "$WRAPPER" > /dev/null <<EOF
#!/usr/bin/env bash
REPO_DIR="$TARGET_DIR"
VENV_PY="\$REPO_DIR/.venv/bin/python"
ENTRY="\$REPO_DIR/autopwn.py"

if [ ! -x "\$VENV_PY" ]; then
    echo "Error: virtualenv python not found at \$VENV_PY" >&2
    exit 1
fi

exec "\$VENV_PY" "\$ENTRY" "\$@"
EOF
sudo chmod +x "$WRAPPER"

echo "Installation complete!"
echo "You can now run AutoPWN Suite simply with:"
echo "  autopwn-suite"
echo "or as root:"
echo "  sudo autopwn-suite"
