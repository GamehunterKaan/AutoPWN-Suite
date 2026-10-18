# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
# Builds the standalone single-file binary. Run from the repository root:
#   pyinstaller --clean --noconfirm packaging/autopwn-suite.spec
import os
import re
from pathlib import Path

from PyInstaller.utils.hooks import copy_metadata

root = Path(SPECPATH).parent  # noqa: F821 - SPECPATH is provided by PyInstaller
package = root / "autopwn_suite"

datas = [
    (str(package / "data"), "autopwn_suite/data"),
    (str(package / "web_ui_static"), "autopwn_suite/web_ui_static"),
    # The proof-of-concept generator reads these two files as text and embeds them in the scripts it
    # produces, so they must exist next to the frozen module as source.
    (str(package / "web" / "poc_runtime.py"), "autopwn_suite/web"),
    (str(package / "web" / "transport.py"), "autopwn_suite/web"),
    # License and notice of this project travel with the binary.
    (str(root / "LICENSE"), "."),
    (str(root / "NOTICE"), "."),
]

# Distribution metadata of every bundled package, including the license files it ships, for attribution.
for requirement in re.findall(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==", (root / "requirements-locked.txt").read_text(encoding="utf-8"), re.MULTILINE):
    try:
        datas += copy_metadata(requirement)
    except Exception:  # noqa: BLE001 - requirement excluded by an environment marker on this platform
        pass

analysis = Analysis(  # noqa: F821
    [str(root / "packaging" / "pyinstaller_entry.py")],
    pathex=[str(root)],
    datas=datas,
    excludes=["tkinter", "pytest"],
)

# What the installer recorded about the build machine does not belong in the binary. RECORD holds the hash of each
# console script and those scripts name the virtual environment's path, so with it the binary differs by the
# directory it was built in (PyInstaller's own hooks collect these files too, so they are removed after the analysis).
INSTALLER_FILES = {"RECORD", "INSTALLER", "REQUESTED", "direct_url.json"}
analysis.datas[:] = [
    entry for entry in analysis.datas
    if not (os.path.basename(entry[0]) in INSTALLER_FILES and ".dist-info" in entry[0])
]
# Every glibc system provides libgcc_s (the C library loads it itself); PyInstaller would bundle the copy it finds
# on the build machine, which makes the binary depend on that machine's package versions.
analysis.binaries[:] = [entry for entry in analysis.binaries if os.path.basename(entry[0]) != "libgcc_s.so.1"]

executable = EXE(  # noqa: F821
    PYZ(analysis.pure),  # noqa: F821
    analysis.scripts,
    analysis.binaries,
    analysis.datas,
    # PyInstaller ignores PYTHONUTF8 at runtime. Without UTF-8 mode the banner fails to print on Windows
    # whenever output is redirected, because rich then writes through the legacy console code page.
    [("X utf8", None, "OPTION")],
    name="autopwn-suite",
    console=True,
    upx=False,
)
