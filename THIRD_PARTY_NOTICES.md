# Third-party software

ProxyLatch's own code is under the MIT license (see `LICENSE`). The Windows build also
contains the following third-party component.

## WinDivert 2.2 (Windows only)

- Files: `WinDivert64.dll`, `WinDivert64.sys` (packed into `ProxyLatch.exe`; taken from the
  [pydivert](https://github.com/ffalcinelli/pydivert) package at build time)
- Project: https://github.com/basil00/WinDivert
- Copyright (C) Basil Ferkous (basil00)
- License: dual-licensed under the **GNU Lesser General Public License v3.0** or the
  **GNU General Public License v2.0**. ProxyLatch uses it under the LGPL v3.0.

ProxyLatch loads WinDivert as a separate library and does not modify it. Under the LGPL you may
replace it with another (e.g. self-built) version of WinDivert 2.x: put `WinDivert64.dll` and
`WinDivert64.sys` in a `windivert` folder next to the program, or build ProxyLatch from source
with your own copy (see `build.bat`). The full license texts are available at
https://www.gnu.org/licenses/lgpl-3.0.html and https://www.gnu.org/licenses/gpl-2.0.html.

## Python and Tcl/Tk

The packaged programs contain the Python runtime (PSF License) and Tcl/Tk (BSD-style license),
bundled by [PyInstaller](https://pyinstaller.org) (GPL v2 with a bootloader exception that allows
distributing the result under any license).
