# /// script
# requires-python = ">=3.9"
# dependencies = ["pyyaml>=6"]
# ///
"""Static checks for the Envoy and Istio quickstart manifests.

- every YAML document in the quickstart files parses
- the gateway.yaml / envoy.yaml embedded in all-in-one.yaml (and the
  gateway.yaml in istio/tenuo.yaml) are byte-identical to the standalone files
  next to this script, so the docker compose e2e test covers the k8s config
- nothing configures gRPC ext_authz, which the authorizer does not serve
- the authorizer Deployments probe the separate health port, never the
  ext_authz port (a 200 there would read as ALLOW)
- optionally (--envoy-validate) runs `envoy --mode validate` on the embedded
  envoy.yaml inside the pinned Envoy image

Usage: uv run docs/quickstart/envoy/check_manifests.py [--envoy-validate]
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
QUICKSTART = HERE.parent
FILES = [
    HERE / "all-in-one.yaml",
    HERE / "docker-compose.yaml",
    HERE / "docker-compose.build.yaml",
    HERE / "envoy.yaml",
    HERE / "gateway.yaml",
    QUICKSTART / "istio" / "tenuo.yaml",
    QUICKSTART / "istio" / "httpbin.yaml",
    QUICKSTART / "istio" / "mesh-config.yaml",
]


def fail(msg: str) -> None:
    print(f"FAIL {msg}")
    sys.exit(1)


def load_all(path: Path) -> list:
    try:
        return [d for d in yaml.safe_load_all(path.read_text()) if d is not None]
    except yaml.YAMLError as e:
        fail(f"{path.relative_to(QUICKSTART)}: {e}")
        raise


def configmap_data(docs: list, name: str) -> dict:
    for d in docs:
        if d.get("kind") == "ConfigMap" and d["metadata"]["name"] == name:
            return d["data"]
    fail(f"ConfigMap {name} not found")
    return {}


def check_authorizer_probes(docs: list, where: str) -> None:
    """Probes must target the health port (9091), not the ext_authz port."""
    for d in docs:
        if d.get("kind") != "Deployment" or d["metadata"]["name"] != "tenuo-authorizer":
            continue
        for c in d["spec"]["template"]["spec"]["containers"]:
            ports = {p.get("name"): p["containerPort"] for p in c.get("ports", [])}
            if ports.get("health") != 9091:
                fail(f"{where}: authorizer container has no `health` port 9091")
            for probe in ("readinessProbe", "livenessProbe"):
                port = c.get(probe, {}).get("httpGet", {}).get("port")
                if port not in ("health", 9091):
                    fail(f"{where}: authorizer {probe} targets {port!r}, want the health port")
        print(f"ok   {where}: authorizer probes target the health port")
        return
    fail(f"{where}: tenuo-authorizer Deployment not found")


def envoy_image(docs: list) -> str:
    for d in docs:
        if d.get("kind") == "Deployment" and d["metadata"]["name"] == "envoy":
            return d["spec"]["template"]["spec"]["containers"][0]["image"]
    fail("envoy Deployment not found")
    return ""


def main() -> None:
    parsed = {}
    for path in FILES:
        parsed[path] = load_all(path)
        print(f"ok   {path.relative_to(QUICKSTART)}: {len(parsed[path])} document(s)")

    aio = parsed[HERE / "all-in-one.yaml"]
    embedded = {
        "gateway.yaml": configmap_data(aio, "tenuo-config")["gateway.yaml"],
        "envoy.yaml": configmap_data(aio, "envoy-config")["envoy.yaml"],
    }
    for name, text in embedded.items():
        yaml.safe_load(text)
        if text != (HERE / name).read_text():
            fail(f"all-in-one.yaml embedded {name} differs from envoy/{name}")
        print(f"ok   all-in-one.yaml embedded {name} parses and matches envoy/{name}")

    istio_gw = configmap_data(parsed[QUICKSTART / "istio" / "tenuo.yaml"], "tenuo-config")["gateway.yaml"]
    if istio_gw != (HERE / "gateway.yaml").read_text():
        fail("istio/tenuo.yaml embedded gateway.yaml differs from envoy/gateway.yaml")
    print("ok   istio/tenuo.yaml embedded gateway.yaml matches envoy/gateway.yaml")

    check_authorizer_probes(aio, "envoy/all-in-one.yaml")
    check_authorizer_probes(parsed[QUICKSTART / "istio" / "tenuo.yaml"], "istio/tenuo.yaml")

    for path in FILES:
        text = path.read_text()
        for needle in ("grpc_service:", "envoyExtAuthzGrpc:"):
            if needle in text:
                fail(f"{path.relative_to(QUICKSTART)} uses {needle}; the authorizer only serves HTTP ext_authz")
    print("ok   no gRPC ext_authz configuration")

    if "--envoy-validate" in sys.argv:
        image = envoy_image(aio)
        with tempfile.TemporaryDirectory(dir=HERE) as tmp:
            cfg = Path(tmp) / "envoy.yaml"
            cfg.write_text(embedded["envoy.yaml"])
            cmd = [
                "docker", "run", "--rm", "-v", f"{cfg}:/etc/envoy/envoy.yaml:ro",
                image, "envoy", "--mode", "validate", "-c", "/etc/envoy/envoy.yaml",
            ]
            out = subprocess.run(cmd, capture_output=True, text=True)
            if out.returncode != 0 or "OK" not in out.stdout + out.stderr:
                print(out.stdout, out.stderr)
                fail(f"envoy --mode validate ({image})")
        print(f"ok   envoy --mode validate ({image})")


if __name__ == "__main__":
    main()
