# Build from the monorepo root after producing a tenuo wheel:
#   (cd tenuo-python && maturin build --release)
#   docker build -f github-actions/Dockerfile \
#     --build-arg TENUO_WHEEL=tenuo-python/target/wheels/tenuo-<ver>-*.whl .

FROM python:3.12-slim-bookworm
ARG TENUO_WHEEL

RUN useradd --create-home --uid 1000 --shell /usr/sbin/nologin tenuo \
    && mkdir -p /state /etc/tenuo \
    && chown -R tenuo:tenuo /state

WORKDIR /app
COPY ${TENUO_WHEEL} /tmp/tenuo.whl
COPY github-actions /src/github-actions

RUN pip install --no-cache-dir /tmp/tenuo.whl \
    && pip install --no-cache-dir --no-deps /src/github-actions \
    && pip install --no-cache-dir "pyyaml>=6.0" "fastmcp>=3.2.1" \
    && rm -rf /tmp/tenuo.whl /src

USER 1000
WORKDIR /state
ENV PYTHONUNBUFFERED=1
EXPOSE 8000
ENTRYPOINT ["python", "-m", "tenuo_gha"]
