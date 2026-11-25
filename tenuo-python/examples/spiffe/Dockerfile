# Isolated Linux environment for the real SPIRE interoperability demo.
FROM python:3.13-slim@sha256:7249d5587b78209a006dc4a3b5340678f84ea729239193aa559962cd8c1fce50
ARG TARGETARCH
RUN python -c 'import hashlib, io, os, platform, tarfile, urllib.request; arch=os.environ.get("TARGETARCH") or {"x86_64":"amd64","aarch64":"arm64"}[platform.machine()]; expected={"amd64":"7bcf5e167151a1fc58293768462b44e155ba8784214582aefa6adf18c633d1d5", "arm64":"ba2804905a27ca72b0478ae790b580ea26233abafac7e480bbaf54152d5c2c5b"}[arch]; data=urllib.request.urlopen(f"https://github.com/spiffe/spire/releases/download/v1.16.0/spire-1.16.0-linux-{arch}-musl.tar.gz").read(); assert hashlib.sha256(data).hexdigest()==expected, "SPIRE checksum mismatch"; tarfile.open(fileobj=io.BytesIO(data),mode="r:gz").extractall("/opt",filter="data")'
RUN pip install --no-cache-dir 'tenuo==0.3.8' 'cryptography>=42'
ENV PATH="/opt/spire-1.16.0/bin:${PATH}"
ENV PYTHONPATH=/work/tenuo-python
WORKDIR /work
CMD ["python", "tenuo-python/examples/spiffe/live_spire.py"]
