#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
command -v pyinstaller >/dev/null 2>&1 || {
  echo "Install PyInstaller in this environment: pip install pyinstaller" >&2
  exit 1
}
exec pyinstaller --clean --noconfirm packaging/pyinstaller.spec
