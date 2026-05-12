# SPK

Experimental outsourced KD-tree queries with Paillier ciphertexts. Python 3.9+ recommended.

## Distribution (`spk-runner`)

Build (publisher):

```bash
cd publish-version/SPK
bash scripts/extract_spk_binary.sh
```

Run (recipient): `./spk-runner` after `chmod +x`. Packaging notes: **`MAINTAINERS_PACKAGING.md`**, user-facing notes: **`CLIENT_INSTRUCTIONS.txt`**.

Optional Docker image: see **`Dockerfile.binary`**.

## Developer

```bash
cd publish-version/SPK
pip install -r requirements.txt
```

Install the local **`spk_engine`** package (orchestration + run defaults; optional Cython extensions for `spk_engine.pipeline` and `spk_engine.run_config` when **Cython** is available):

```bash
pip install -e .
```

Rebuild this step after changing code under `spk_engine/` if you rely on the compiled `.so` modules.

Reproducible install: `pip install -r requirements.txt -c constraints.txt`. Optional speedups: **gmpy2** / **libgmp** (see `requirements.txt`).

## Reference

KD-tree code derives from [stefankoegl/kdtree](https://github.com/stefankoegl/kdtree).
