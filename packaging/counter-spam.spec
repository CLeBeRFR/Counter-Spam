# -*- mode: python -*-
"""PyInstaller recipe: one stand-alone executable for the current OS.

From the repository root, with ``pip install -r packaging/requirements.txt``::

    pyinstaller packaging/counter-spam.spec

The result is ``dist/counter-spam.exe`` on Windows, ``dist/counter-spam``
on macOS and Linux.
"""

import platform
import re
import sys
from pathlib import Path

ROOT = Path(SPECPATH).parent  # noqa: F821 (defined by PyInstaller)
VERSION = re.search(r'__version__ = "([^"]+)"',
                    (ROOT / "counter_spam" / "__init__.py")
                    .read_text(encoding="utf-8")).group(1)

binaries, hiddenimports = [], []
datas = [(str(ROOT / "counter_spam" / "web"), "counter_spam/web")]
if sys.platform.startswith("linux"):
    # msal_extensions encrypts the tokens with libsecret (GNOME Keyring,
    # KWallet) through PyGObject, imported dynamically: bundle it.
    from PyInstaller.utils.hooks.gi import GiModuleInfo

    secret = GiModuleInfo("Secret", "1")
    if not secret.available:
        raise SystemExit("libsecret is missing: sudo apt install "
                         "python3-gi gir1.2-secret-1")
    found = secret.collect_typelib_data()
    binaries += found[0]
    datas += found[1]
    hiddenimports += found[2]

a = Analysis(  # noqa: F821
    [str(ROOT / "packaging" / "counter-spam.py")],
    pathex=[str(ROOT)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=["tkinter", "pytest", "PIL"],
)

# The Selenium wheel carries Selenium Manager for every OS: keep only the
# one of this platform (about 15 MB saved).
if sys.platform == "win32":
    MANAGER = "windows"
elif sys.platform == "darwin":
    MANAGER = "macos"
elif platform.machine().lower() in ("aarch64", "arm64"):
    MANAGER = "linux-arm64"
else:
    MANAGER = "linux-x86_64"
OTHER_MANAGERS = [f"selenium/webdriver/common/{name}/" for name in
                  ("windows", "macos", "linux-x86_64", "linux-arm64")
                  if name != MANAGER]


def _for_this_os(entries):
    return [entry for entry in entries
            if not any(prefix in entry[0].replace("\\", "/")
                       for prefix in OTHER_MANAGERS)]


a.binaries = _for_this_os(a.binaries)
a.datas = _for_this_os(a.datas)

pyz = PYZ(a.pure)  # noqa: F821

version_info = None
if sys.platform == "win32":
    from PyInstaller.utils.win32 import versioninfo as vi

    numbers = tuple(int(part) for part in VERSION.split(".")) + (0,)
    version_info = vi.VSVersionInfo(
        ffi=vi.FixedFileInfo(filevers=numbers, prodvers=numbers),
        kids=[
            vi.StringFileInfo([vi.StringTable("040904B0", [
                vi.StringStruct("CompanyName", "Counter-Spam"),
                vi.StringStruct("FileDescription",
                                "Counter-Spam: report Outlook spam to "
                                "abuse desks"),
                vi.StringStruct("FileVersion", VERSION),
                vi.StringStruct("InternalName", "counter-spam"),
                vi.StringStruct("LegalCopyright",
                                "PolyForm Noncommercial License 1.0.0"),
                vi.StringStruct("OriginalFilename", "counter-spam.exe"),
                vi.StringStruct("ProductName", "Counter-Spam"),
                vi.StringStruct("ProductVersion", VERSION),
            ])]),
            vi.VarFileInfo([vi.VarStruct("Translation", [0x0409, 1200])]),
        ])

exe = EXE(  # noqa: F821
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="counter-spam",
    # A console shows the progress and the sign-in instructions; closing
    # it (or the Quit button of the interface) stops the program.
    console=True,
    upx=False,
    icon=str(ROOT / "docs" / "images" / "icon-256.png"),
    version=version_info,
)
