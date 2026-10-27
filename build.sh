#!/usr/bin/env bash
# Builds dist/proxylatch for Linux (a single file) on Ubuntu / Debian.
#
#   ./build.sh            install what's missing, then build
#   ./build.sh --install  ...and also install to /opt/proxylatch + an app menu entry
#
# Run it as your normal user; it asks for sudo only to install packages.
set -euo pipefail
cd "$(dirname "$0")"

INSTALL=0
for arg in "$@"; do
  case "$arg" in
    --install) INSTALL=1 ;;
    -h|--help) sed -n '2,7p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg"; exit 1 ;;
  esac
done

if [ "$(id -u)" -eq 0 ]; then
  echo "Run this as your normal user, not root (it uses sudo where needed)."
  exit 1
fi

# --------------------------------------------------------------------------- #
# 1. System packages
#    build:   python3, python3-venv (build environment), python3-tk (GUI),
#             binutils (PyInstaller needs objdump on Linux)
#    runtime: nftables (redirect rules), pkexec (password prompt), iproute2 (ss),
#             util-linux (setpriv, used by the Launch button)
# --------------------------------------------------------------------------- #
PACKAGES=(python3 python3-venv python3-tk binutils nftables pkexec iproute2 util-linux)

if ! command -v apt-get >/dev/null; then
  echo "This script installs packages with apt (Ubuntu/Debian)."
  echo "On other distributions install the equivalents of: ${PACKAGES[*]}"
  exit 1
fi

missing=()
for p in "${PACKAGES[@]}"; do
  dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q "install ok installed" || missing+=("$p")
done
# Ubuntu releases before 22.04 ship pkexec inside policykit-1
if [[ " ${missing[*]-} " == *" pkexec "* ]] && ! apt-cache show pkexec >/dev/null 2>&1; then
  missing=("${missing[@]/pkexec/policykit-1}")
fi

if [ ${#missing[@]} -gt 0 ]; then
  echo "=== Installing: ${missing[*]} ==="
  sudo apt-get install -y "${missing[@]}"
else
  echo "=== All required packages are installed ==="
fi

# --------------------------------------------------------------------------- #
# 2. Checks
# --------------------------------------------------------------------------- #
python3 - <<'EOF' || exit 1
import sys
if sys.version_info < (3, 9):
    sys.exit(f"Python 3.9 or newer is needed (found {sys.version.split()[0]})")
import tkinter  # noqa: F401  (python3-tk)
EOF
if [ ! -f /sys/fs/cgroup/cgroup.controllers ]; then
  echo "warning: cgroup v2 is not active; ProxyLatch needs Ubuntu 21.10 or newer to run."
fi

# --------------------------------------------------------------------------- #
# 3. Build (in a private virtual environment, so the system Python stays clean)
# --------------------------------------------------------------------------- #
echo "=== Preparing build environment (.build-venv) ==="
if [ ! -x .build-venv/bin/python ]; then
  rm -rf .build-venv
  python3 -m venv .build-venv
fi
# install / upgrade only on the first build or when requirements.txt changed
if [ ! -f .build-venv/.installed ] || [ requirements.txt -nt .build-venv/.installed ]; then
  .build-venv/bin/python -m pip install --quiet --upgrade pip
  .build-venv/bin/python -m pip install --quiet --upgrade -r requirements.txt pyinstaller
  touch .build-venv/.installed
fi

echo "=== Building proxylatch ==="
.build-venv/bin/python -m PyInstaller --noconfirm --onefile --name proxylatch proxylatch.py

echo
echo "Done: $(pwd)/dist/proxylatch"

# --------------------------------------------------------------------------- #
# 4. Optional install
# --------------------------------------------------------------------------- #
if [ "$INSTALL" -eq 1 ]; then
  if [ ! -f dist/proxylatch ]; then
    echo "dist/proxylatch was not built - see the messages above."
    exit 1
  fi
  echo "=== Installing to /opt/proxylatch ==="
  sudo mkdir -p /opt/proxylatch
  sudo install -m755 dist/proxylatch /opt/proxylatch/proxylatch
  sudo ln -sf /opt/proxylatch/proxylatch /usr/local/bin/proxylatch   # so "proxylatch" works in a terminal

  # app menu entry (written here, so no extra file has to be copied along)
  apps_dir="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
  mkdir -p "$apps_dir"
  cat > "$apps_dir/proxylatch.desktop" <<'DESKTOP'
[Desktop Entry]
Type=Application
Name=ProxyLatch
Comment=Send chosen apps through a SOCKS5 or HTTP proxy
Exec=/opt/proxylatch/proxylatch
Icon=network-vpn
Terminal=false
Categories=Network;
DESKTOP
  chmod 644 "$apps_dir/proxylatch.desktop"
  command -v update-desktop-database >/dev/null && update-desktop-database "$apps_dir" || true
  echo "Installed. Start it from the app menu (\"ProxyLatch\") or run: proxylatch"
else
  echo "Run it with: ./dist/proxylatch      (or ./build.sh --install for an app menu entry)"
fi
