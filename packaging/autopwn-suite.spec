# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
# Builds the standalone single-file binary. Run from the repository root:
#   pyinstaller --clean --noconfirm packaging/autopwn-suite.spec
from pathlib import Path

root = Path(SPECPATH).parent  # noqa: F821 - SPECPATH is provided by PyInstaller
package = root / "autopwn_suite"

datas = [
    (str(package / "data"), "autopwn_suite/data"),
    (str(package / "web_ui_static"), "autopwn_suite/web_ui_static"),
    # The proof-of-concept generator reads these two files as text and embeds them in the scripts it
    # produces, so they must exist next to the frozen module as source.
    (str(package / "web" / "poc_runtime.py"), "autopwn_suite/web"),
    (str(package / "web" / "transport.py"), "autopwn_suite/web"),
]

analysis = Analysis(  # noqa: F821
    [str(root / "packaging" / "pyinstaller_entry.py")],
    pathex=[str(root)],
    datas=datas,
    excludes=["tkinter", "pytest"],
)

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
