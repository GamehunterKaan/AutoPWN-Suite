#!/usr/bin/env bash
set -euo pipefail

TARGET_DIR="/opt/autopwn-suite"
WRAPPER="/usr/local/bin/autopwn-suite"
SERVICE_FILE="/etc/systemd/system/autopwn-daemon.service"
SERVICE_NAME="autopwn-daemon.service"

echo "[1/3] Checking for systemd service ..."
if [ -f "$SERVICE_FILE" ]; then
    echo "Stopping and disabling $SERVICE_NAME ..."
    sudo systemctl stop "$SERVICE_NAME" || true
    sudo systemctl disable "$SERVICE_NAME" || true
    sudo rm -f "$SERVICE_FILE"
    sudo systemctl daemon-reload
    echo "Service $SERVICE_NAME removed."
else
    echo "No systemd service file found at $SERVICE_FILE; skipping."
fi

echo "[2/3] Removing AutoPWN Suite directory $TARGET_DIR ..."
if [ -d "$TARGET_DIR" ]; then
    sudo rm -rf "$TARGET_DIR"
    echo "Removed $TARGET_DIR"
else
    echo "Directory $TARGET_DIR does not exist; skipping."
fi

echo "[3/3] Removing wrapper $WRAPPER ..."
if [ -f "$WRAPPER" ]; then
    sudo rm -f "$WRAPPER"
    echo "Removed wrapper $WRAPPER"
else
    echo "Wrapper $WRAPPER does not exist; skipping."
fi

echo "Uninstallation complete!"
