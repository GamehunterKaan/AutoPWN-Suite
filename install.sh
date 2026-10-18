#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: [VARIABLE=value ...] bash install.sh

Installs AutoPWN Suite system-wide from this checkout: a virtual environment
in the application directory holds the package and its dependencies, and the
autopwn-suite command in BINDIR links to it. Defaults are unchanged from earlier
releases: application in /opt/autopwn-suite, command in /usr/local/bin.

Variables (standard GNU/packaging conventions):
  PREFIX             Installation prefix. Default: /usr/local. When set
                     explicitly, the application directory defaults to
                     $PREFIX/lib/autopwn-suite.
  BINDIR             Where the autopwn-suite command goes. Default: $PREFIX/bin
  APPDIR             Application directory. Default: /opt/autopwn-suite, or
                     $PREFIX/lib/autopwn-suite when PREFIX is set.
  DESTDIR            Staging root for packagers. Every file is written under
                     "$DESTDIR"; the command link still refers to the final
                     (non-DESTDIR) path. No sudo, ownership change, or virtualenv
                     is created when DESTDIR is set: the source is staged in
                     "$DESTDIR$APPDIR/src" and the commands that create the
                     virtualenv on the target system are printed instead.
  PYTHON             Python interpreter used to create the virtualenv.
                     Default: python3
  REQUIREMENTS_FILE  Dependency file inside the repository. Default:
                     requirements.txt. Use requirements-locked.txt for
                     hash-verified, lockfile-exact installs.
  SYSTEMDDIR         Directory holding the daemon unit, checked for a service
                     that an earlier release installed. Default:
                     /etc/systemd/system
USAGE
}

case "${1:-}" in
    -h|--help) usage; exit 0 ;;
    "") ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
esac

# Path setup (mirrored in uninstall.sh)
REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON="${PYTHON:-python3}"
REQUIREMENTS_FILE="${REQUIREMENTS_FILE:-requirements.txt}"
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
        *) mkdir -p "$DESTDIR"; DESTDIR="$(cd "$DESTDIR" && pwd)" ;;
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
case "$REQUIREMENTS_FILE" in
    /*|*..*) echo "Error: REQUIREMENTS_FILE must be a path inside the repository" >&2; exit 2 ;;
esac

# Final (runtime) locations vs. where files are written now.
TARGET_DIR="$APPDIR"
VENV_DIR="$TARGET_DIR/.venv"
WRAPPER="$BINDIR/autopwn-suite"
STAGE_TARGET_DIR="$DESTDIR$TARGET_DIR"
STAGE_BINDIR="$DESTDIR$BINDIR"
STAGE_WRAPPER="$DESTDIR$WRAPPER"

# Use sudo only when needed: never for a staged install, never as root, and
# not when the nearest existing parent directory is already writable.
needs_sudo() {
    local path="$1"
    [ -z "$DESTDIR" ] || return 1
    [ "$(id -u)" -ne 0 ] || return 1
    while [ ! -e "$path" ] && [ "$path" != "/" ]; do
        path="$(dirname "$path")"
    done
    [ ! -w "$path" ]
}

run_for() {
    local path="$1"
    shift
    if needs_sudo "$path"; then
        sudo "$@"
    else
        "$@"
    fi
}

if [ -n "$DESTDIR" ]; then
    echo "Staged install into DESTDIR=$DESTDIR (no virtualenv, no ownership changes)."
fi

# Final (runtime) location of the staged source, and what pip installs from.
if [ -n "$DESTDIR" ]; then
    SOURCE_DIR="$TARGET_DIR/src"
else
    SOURCE_DIR="$REPO_DIR"
fi

if [ -n "$DESTDIR" ]; then
    echo "[1/3] Staging source in $STAGE_TARGET_DIR/src ..."
    run_for "$STAGE_TARGET_DIR/src" rm -rf "$STAGE_TARGET_DIR/src"
    run_for "$STAGE_TARGET_DIR/src" mkdir -p "$STAGE_TARGET_DIR/src"
    (cd "$REPO_DIR" && tar -cf - --exclude='.venv' --exclude='./.git' .)         | (cd "$STAGE_TARGET_DIR/src" && tar -xpf - --no-same-owner)
    echo "[2/3] Skipping virtualenv and package installation (DESTDIR is set)."
else
    echo "[1/3] Creating virtual environment at $VENV_DIR ..."
    run_for "$TARGET_DIR" rm -rf "$VENV_DIR"
    run_for "$TARGET_DIR" mkdir -p "$TARGET_DIR"
    if needs_sudo "$TARGET_DIR"; then
        # The directory was just created by root; hand it to the invoking user first.
        sudo chown "$(id -un)":"$(id -gn)" "$TARGET_DIR"
    fi
    "$PYTHON" -m venv "$VENV_DIR"

    echo "[2/3] Installing Python dependencies and AutoPWN Suite ..."
    # shellcheck disable=SC1091
    source "$VENV_DIR/bin/activate"
    pip install --upgrade pip setuptools wheel
    if [ -f "$REPO_DIR/$REQUIREMENTS_FILE" ]; then
        pip install -r "$REPO_DIR/$REQUIREMENTS_FILE"
    fi
    pip install --no-deps "$SOURCE_DIR"
    deactivate
fi

echo "[3/3] Linking command $STAGE_WRAPPER -> $VENV_DIR/bin/autopwn-suite ..."
run_for "$STAGE_BINDIR" mkdir -p "$STAGE_BINDIR"
# The link targets the final path ($VENV_DIR), never the DESTDIR path.
run_for "$STAGE_WRAPPER" ln -sfn "$VENV_DIR/bin/autopwn-suite" "$STAGE_WRAPPER"

if [ -n "$DESTDIR" ]; then
    echo "Staged installation complete under $DESTDIR."
    echo "On the target system, create the virtualenv the command links to:"
    echo "  $PYTHON -m venv $VENV_DIR"
    echo "  $VENV_DIR/bin/pip install -r $SOURCE_DIR/$REQUIREMENTS_FILE"
    echo "  $VENV_DIR/bin/pip install --no-deps $SOURCE_DIR"
    exit 0
fi

echo "Installation complete!"
echo "You can now run AutoPWN Suite simply with:"
echo "  autopwn-suite"
echo "or as root:"
echo "  sudo autopwn-suite"

# A daemon that release 2.6 or earlier installed runs its own copy of the source (autopwn.py) that this
# script never touches, so it keeps running that older version until its unit is regenerated.
SERVICE_UNIT="$SYSTEMDDIR/autopwn-daemon.service"
if [ -f "$SERVICE_UNIT" ] && grep -q 'autopwn\.py' "$SERVICE_UNIT"; then
    echo
    echo "WARNING: $SERVICE_UNIT still starts the copy of AutoPWN Suite that an"
    echo "earlier release installed (autopwn.py), so the daemon keeps running that older version."
    echo "Regenerate the service so it runs this installation, then restart it:"
    echo "  sudo autopwn-suite --daemon-install     # asks for the configuration again"
    echo "  sudo systemctl restart autopwn-daemon"
    if [ "$(id -u)" -ne 0 ]; then
        echo "The daemon runs as root and only accepts a root-owned installation: run 'sudo bash install.sh' first."
    fi
fi
