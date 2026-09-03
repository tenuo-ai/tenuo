# Tenuo runtime wheel

The JavaScript action installs third-party deps from `requirements.lock` and the
exact compatible `tenuo` wheel from this directory (or `TENUO_WHEEL`).

Release packaging copies `tenuo-*.whl` here after `maturin build --release` in
`tenuo-python`. Wheels are not committed.
