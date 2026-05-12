# Maintainer notes (do not ship to clients)

## What this achieves

- **Docker multi-stage build**: compile wheels against **libgmp**, install offline into a slim runtime, non-root user, optional filesystem tightening on `.py` permissions (raises bar only).
- **Pinned dependencies**: `constraints.txt` — reproducible installs.
- **PyInstaller** (optional): produces a single executable with bundled interpreter fragments — **not** secret (strings and bytecode can still be recovered); it mainly discourages casual edits.

## Sealed Linux binary (`spk-runner`) — preferred handoff

Build inside Docker (recommended when Docker Hub / proxies work):

```bash
bash scripts/extract_spk_binary.sh
```

If **`extract_spk_binary.sh` fails pulling `python:3.10-bookworm`** (timeout, canceled request): configure a registry mirror / proxy, **pre-pull** images on another network, or set mirror URLs, for example:

```bash
export SPK_PY_BUILD_IMAGE=docker.m.daocloud.io/library/python:3.10-bookworm
export SPK_DEBIAN_RUNTIME_IMAGE=docker.m.daocloud.io/library/debian:bookworm-slim
bash scripts/extract_spk_binary.sh
```

(Mirror hostnames are examples only — use whatever your organization provides.)

**Without Docker** — clean virtualenv + PyInstaller (avoids some conda/PyInstaller conflicts):

```bash
bash scripts/build_binary_venv.sh
```

Produces **`dist/spk-runner`**. Ship that file + **`CLIENT_INSTRUCTIONS.txt`**.

Runtime image wrapping the same artifact:

```bash
docker build -f Dockerfile.binary -t spk-runner:runtime .
docker run --rm spk-runner:runtime
```

## Interpreter-based Docker (sources inside image)

Compose v2:

```bash
docker compose build --no-cache
docker compose run --rm spk
```

Docker Engine without Compose plugin:

```bash
docker build -t spk-kdtree:release .
docker run --rm spk-kdtree:release
```

Recipients should only receive **`CLIENT_INSTRUCTIONS.txt`** plus an image tarball or registry reference:

```bash
docker save spk-kdtree:release | gzip > spk-kdtree-release.tar.gz
```

## Optional local PyInstaller (maintainers only)

When the host environment is clean:

```bash
pip install pyinstaller
bash scripts/run_pyinstaller.sh
```

Artifacts land in `./dist/`.

## Honest limits

Obfuscation != cryptography. Determined reviewers can still reverse-engineer Python stacks. For stronger protection you need legal agreements, hardware, or a rewrite into distributed trust assumptions — not packaging alone.
