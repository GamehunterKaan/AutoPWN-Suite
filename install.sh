#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: [VARIABLE=value ...] bash install.sh

Installs AutoPWN Suite system-wide. Defaults are unchanged from earlier
releases: application in /opt/autopwn-suite, command in /usr/local/bin.

Variables (standard GNU/packaging conventions):
  PREFIX             Installation prefix. Default: /usr/local. When set
                     explicitly, the application directory defaults to
                     $PREFIX/lib/autopwn-suite.
  BINDIR             Where the autopwn-suite command goes. Default: $PREFIX/bin
  APPDIR             Application directory. Default: /opt/autopwn-suite, or
                     $PREFIX/lib/autopwn-suite when PREFIX is set.
  DESTDIR            Staging root for packagers. Every file is written under
                     "$DESTDIR"; the generated wrapper still refers to the final
                     (non-DESTDIR) path. No sudo, ownership change, or virtualenv
                     is created when DESTDIR is set; the command to create the
                     virtualenv on the target system is printed instead.
  PYTHON             Python interpreter used to create the virtualenv.
                     Default: python3
  REQUIREMENTS_FILE  Dependency file inside the repository. Default:
                     requirements.txt. Use requirements-locked.txt for
                     hash-verified, lockfile-exact installs.
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
if [ -n "$DESTDIR" ]; then
    DESTDIR="$(strip_slashes "$DESTDIR")"
    case "$DESTDIR" in
        /*) ;;
        *) mkdir -p "$DESTDIR"; DESTDIR="$(cd "$DESTDIR" && pwd)" ;;
    esac
fi

for var in PREFIX BINDIR APPDIR; do
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

echo "[1/4] Copying repo to $STAGE_TARGET_DIR ..."
run_for "$STAGE_TARGET_DIR" rm -rf "$STAGE_TARGET_DIR"
run_for "$STAGE_TARGET_DIR" mkdir -p "$STAGE_TARGET_DIR"
if needs_sudo "$STAGE_TARGET_DIR"; then
    # The directory was just created by root; hand it to the invoking user first.
    sudo chown "$(id -un)":"$(id -gn)" "$STAGE_TARGET_DIR"
fi
(cd "$REPO_DIR" && tar -cf - --exclude='.venv' --exclude='./.git' .) \
    | (cd "$STAGE_TARGET_DIR" && tar -xpf - --no-same-owner)
if [ -z "$DESTDIR" ]; then
    run_for "$TARGET_DIR" chown -R "$(id -un)":"$(id -gn)" "$TARGET_DIR"
fi

if [ -n "$DESTDIR" ]; then
    echo "[2/4] Skipping virtualenv creation (DESTDIR is set)."
    echo "[3/4] Skipping dependency installation (DESTDIR is set)."
else
    echo "[2/4] Creating virtual environment at $VENV_DIR ..."
    "$PYTHON" -m venv "$VENV_DIR"

    echo "[3/4] Installing Python dependencies ..."
    # shellcheck disable=SC1091
    source "$VENV_DIR/bin/activate"
    pip install --upgrade pip setuptools wheel
    if [ -f "$TARGET_DIR/$REQUIREMENTS_FILE" ]; then
        pip install -r "$TARGET_DIR/$REQUIREMENTS_FILE"
    fi
    deactivate
fi

echo "[4/4] Creating wrapper command at $STAGE_WRAPPER ..."
run_for "$STAGE_BINDIR" mkdir -p "$STAGE_BINDIR"
# The wrapper embeds the final path ($TARGET_DIR), never the DESTDIR path.
run_for "$STAGE_WRAPPER" tee "$STAGE_WRAPPER" > /dev/null <<EOF
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
run_for "$STAGE_WRAPPER" chmod 0755 "$STAGE_WRAPPER"

if [ -n "$DESTDIR" ]; then
    echo "Staged installation complete under $DESTDIR."
    echo "On the target system, create the virtualenv the wrapper expects:"
    echo "  $PYTHON -m venv $VENV_DIR"
    echo "  $VENV_DIR/bin/pip install -r $TARGET_DIR/$REQUIREMENTS_FILE"
    exit 0
fi

echo "Installation complete!"
echo "You can now run AutoPWN Suite simply with:"
echo "  autopwn-suite"
echo "or as root:"
echo "  sudo autopwn-suite"
