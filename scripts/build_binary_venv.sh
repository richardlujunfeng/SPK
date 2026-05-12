#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
VENV="${SPK_BUILD_VENV:-${ROOT}/.venv-spk-release}"

python3 -m venv "${VENV}"
# shellcheck disable=SC1090
source "${VENV}/bin/activate"
pip install --upgrade pip setuptools wheel
pip install --no-cache-dir -r requirements.txt -c constraints.txt pyinstaller
pyinstaller --clean --noconfirm packaging/pyinstaller.spec
chmod +x "${ROOT}/dist/spk-runner"
echo "Wrote ${ROOT}/dist/spk-runner"
