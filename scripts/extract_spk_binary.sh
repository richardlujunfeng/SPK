#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
IMAGE="${SPK_BINARY_BUILD_IMAGE:-spk-runner-build:local}"

PY_IMAGE="${SPK_PY_BUILD_IMAGE:-python:3.10-bookworm}"
DEBIAN_IMAGE="${SPK_DEBIAN_RUNTIME_IMAGE:-debian:bookworm-slim}"

fail_hint() {
    cat >&2 <<'EOF'
Docker build failed while pulling base images (often Docker Hub timeout / firewall).

Try ONE of:

  1) Configure a registry mirror or HTTP proxy for Docker, then retry.

  2) Use pull-through mirrors via build-args (examples — pick a mirror you trust):

       export SPK_PY_BUILD_IMAGE=docker.m.daocloud.io/library/python:3.10-bookworm
       export SPK_DEBIAN_RUNTIME_IMAGE=docker.m.daocloud.io/library/debian:bookworm-slim
       bash scripts/extract_spk_binary.sh

  3) Pre-pull on a machine with access, save/load tar:

       docker pull python:3.10-bookworm
       docker save python:3.10-bookworm | gzip > python-310-bookworm.tar.gz
       # on offline host: gunzip -c python-310-bookworm.tar.gz | docker load

  4) Skip Docker and build on the host with a clean venv:

       bash scripts/build_binary_venv.sh

EOF
}

set +e
docker build \
    -f Dockerfile.binary \
    --target builder \
    --build-arg "PY_IMAGE=${PY_IMAGE}" \
    --build-arg "DEBIAN_IMAGE=${DEBIAN_IMAGE}" \
    -t "${IMAGE}" \
    .
BUILD_RC=$?
set -e
if [[ "${BUILD_RC}" -ne 0 ]]; then
    fail_hint
    exit "${BUILD_RC}"
fi

CID="$(docker create "${IMAGE}")"
mkdir -p dist
docker cp "${CID}:/build/dist/spk-runner" ./dist/spk-runner
docker rm "${CID}" >/dev/null
chmod +x ./dist/spk-runner
echo "Wrote $(pwd)/dist/spk-runner"
