#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: [VARIABLE=value ...] bash uninstall.sh

Removes what install.sh installed. Honors the same variables as install.sh,
and they must match the values used at install time:
  PREFIX      Default: /usr/local
  BINDIR      Default: $PREFIX/bin
  APPDIR      Default: /opt/autopwn-suite, or $PREFIX/lib/autopwn-suite when
              PREFIX is set
  SYSTEMDDIR  Directory holding the daemon unit. Default: /etc/systemd/system
  DESTDIR     Staging root. Files are removed from under "$DESTDIR"; systemd is
              not contacted and sudo is not used.
USAGE
}

case "${1:-}" in
    -h|--help) usage; exit 0 ;;
    "") ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
esac

DESTDIR="${DESTDIR:-}"

strip_slashes() {
    local value="$1"
    while [ "${#value}" -gt 1 ] && [ "${value%/}" != "$value" ]; do
        value="${value%/}"
    done
    printf '%s' "$value"
}

PREFIX_GIVEN="${PREFIX:-}"
PREFIX="$(strip_slashes "${PREFIX:-/usr/local}")"
BINDIR="$(strip_slashes "${BINDIR:-$PREFIX/bin}")"
if [ -n "${APPDIR:-}" ]; then
    APPDIR="$(strip_slashes "$APPDIR")"
elif [ -n "$PREFIX_GIVEN" ]; then
    APPDIR="$PREFIX/lib/autopwn-suite"
else
    APPDIR="/opt/autopwn-suite"
fi
SYSTEMDDIR="$(strip_slashes "${SYSTEMDDIR:-/etc/systemd/system}")"
if [ -n "$DESTDIR" ]; then
    DESTDIR="$(strip_slashes "$DESTDIR")"
    case "$DESTDIR" in
        /*) ;;
        *) echo "Error: DESTDIR must be an absolute path, got '$DESTDIR'" >&2; exit 2 ;;
    esac
fi

for var in PREFIX BINDIR APPDIR SYSTEMDDIR; do
    value="${!var}"
    case "$value" in
        /*) ;;
        *) echo "Error: $var must be an absolute path, got '$value'" >&2; exit 2 ;;
    esac
done
if [ "$APPDIR" = "/" ] || [ "$BINDIR" = "/" ]; then
    echo "Error: refusing to use / as APPDIR or BINDIR" >&2
    exit 2
fi

SERVICE_NAME="autopwn-daemon.service"
TARGET_DIR="$DESTDIR$APPDIR"
WRAPPER="$DESTDIR$BINDIR/autopwn-suite"
SERVICE_FILE="$DESTDIR$SYSTEMDDIR/$SERVICE_NAME"

# sudo only when needed: not for a staged install, not as root, and not when the
# path's parent directory is writable by the current user.
run_for() {
    local path="$1"
    shift
    if [ -z "$DESTDIR" ] && [ "$(id -u)" -ne 0 ] && [ ! -w "$(dirname "$path")" ]; then
        sudo "$@"
    else
        "$@"
    fi
}

echo "[1/3] Checking for systemd service ..."
if [ -f "$SERVICE_FILE" ]; then
    if [ -z "$DESTDIR" ]; then
        echo "Stopping and disabling $SERVICE_NAME ..."
        run_for "$SERVICE_FILE" systemctl stop "$SERVICE_NAME" || true
        run_for "$SERVICE_FILE" systemctl disable "$SERVICE_NAME" || true
    fi
    run_for "$SERVICE_FILE" rm -f "$SERVICE_FILE"
    if [ -z "$DESTDIR" ]; then
        run_for "$SERVICE_FILE" systemctl daemon-reload
    fi
    echo "Service $SERVICE_NAME removed."
else
    echo "No systemd service file found at $SERVICE_FILE; skipping."
fi

echo "[2/3] Removing AutoPWN Suite directory $TARGET_DIR ..."
if [ -d "$TARGET_DIR" ]; then
    run_for "$TARGET_DIR" rm -rf "$TARGET_DIR"
    echo "Removed $TARGET_DIR"
else
    echo "Directory $TARGET_DIR does not exist; skipping."
fi

echo "[3/3] Removing wrapper $WRAPPER ..."
if [ -f "$WRAPPER" ]; then
    run_for "$WRAPPER" rm -f "$WRAPPER"
    echo "Removed wrapper $WRAPPER"
else
    echo "Wrapper $WRAPPER does not exist; skipping."
fi

echo "Uninstallation complete!"
