# Tenuo runtime wheel

The JavaScript action installs third-party deps from `requirements.lock` and the
Ubuntu/manylinux `tenuo` wheel from this directory.

v1 supports Ubuntu runners (`ubuntu-latest`). `package_runtime.py` copies the
wheel here after `maturin build --release` on Linux. Wheels are part of the
assembled action artifact and are not committed.

```bash
(cd tenuo-python && maturin build --release)
python github-actions/package_runtime.py
```
