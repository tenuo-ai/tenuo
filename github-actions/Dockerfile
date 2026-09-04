# Concierge image. Build from the monorepo root:
#   docker build --platform linux/amd64 -f github-actions/Dockerfile .
# Installs a PyPI *wheel* (never an sdist) unless docker/wheels/ has a file.
# Pin a version with --build-arg TENUO_PIP_SPEC=tenuo==0.2.5
# linux/amd64 matches the published manylinux wheel. linux/arm64 needs a
# wheel in github-actions/docker/wheels/.

FROM python:3.12-slim-trixie
ARG TENUO_PIP_SPEC=tenuo==0.2.4

RUN useradd --create-home --uid 1000 --shell /usr/sbin/nologin tenuo \
    && mkdir -p /state /etc/tenuo \
    && chown -R tenuo:tenuo /state

WORKDIR /app
COPY github-actions /src/github-actions

RUN if ls /src/github-actions/docker/wheels/*.whl >/dev/null 2>&1; then \
      pip install --no-cache-dir /src/github-actions/docker/wheels/*.whl; \
    else \
      pip install --no-cache-dir --only-binary=:all: "${TENUO_PIP_SPEC}"; \
    fi \
    && pip install --no-cache-dir /src/github-actions \
    && rm -rf /src

USER 1000
WORKDIR /state
ENV PYTHONUNBUFFERED=1
EXPOSE 8000
ENTRYPOINT ["python", "-m", "tenuo_gha"]
