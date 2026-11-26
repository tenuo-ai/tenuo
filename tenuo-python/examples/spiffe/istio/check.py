#!/usr/bin/env python3
"""Run the forwarded-identity exchange in a disposable Kubernetes cluster with Istio.

Needs docker, kubectl and helm on PATH, and nothing else: the cluster is a
single k3s container, and every kubectl and helm call uses a kubeconfig in a
temporary directory, so your own contexts are never read or changed.

    python tenuo-python/examples/spiffe/istio/check.py          # run and clean up
    python tenuo-python/examples/spiffe/istio/check.py --keep   # leave the cluster up to look around

    python tenuo-python/examples/spiffe/istio/check.py --spire  # SPIRE issues the mesh's certificates

Set TENUO_SPIFFE_IMAGE to an image already built from ../Dockerfile to skip the build.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

K3S_IMAGE = "rancher/k3s:v1.34.1-k3s1"
ISTIO_VERSION = "1.30.8"
ISTIO_CHARTS = "https://istio-release.storage.googleapis.com/charts"
IMAGE = "tenuo-spiffe-demo:istio"  # The name the manifests use.
HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[3]
ISSUER = "issuer.tenuo.svc.cluster.local:8080"  # Listens on a Unix socket.
ISSUER_TCP = "issuer-tcp.tenuo.svc.cluster.local:8080"  # Listens on TCP, trusts 127.0.0.6.
GATEWAY = "istio-ingress.istio-ingress.svc.cluster.local"
SPIRE_CHARTS = "https://spiffe.github.io/helm-charts-hardened/"
SPIRE_CHART_VERSION, SPIRE_CRDS_VERSION = "0.31.0", "0.6.1"

# SPIRE as the mesh's certificate authority: the agent serves Envoy's secret discovery under the names Istio asks for.
SPIRE_VALUES = """
global:
  spire:
    trustDomain: cluster.local
    clusterName: tenuo-check
spire-agent:
  sds:
    enabled: true
    defaultSVIDName: default
    defaultBundleName: "null"
    defaultAllBundlesName: ROOTCA
spire-server:
  controllerManager:
    identities:
      clusterSPIFFEIDs:
        default:
          fallback: true
spiffe-oidc-discovery-provider:
  enabled: false
"""
# An injection template that gives the sidecar the SPIRE agent's socket. Istio 1.30 runs the
# proxy as a native sidecar, which is an init container.
ISTIOD_SPIRE_VALUES = """
meshConfig:
  trustDomain: cluster.local
sidecarInjectorWebhook:
  templates:
    spire: |
      spec:
        initContainers:
        - name: istio-proxy
          volumeMounts:
          - name: workload-socket
            mountPath: /run/secrets/workload-spiffe-uds
            readOnly: true
        volumes:
          - name: workload-socket
            csi:
              driver: "csi.spiffe.io"
              readOnly: true
"""
# The agent's SPIRE entry, with DNS names on its certificates.
AGENT_WITH_DNS_NAMES = """
apiVersion: spire.spiffe.io/v1alpha1
kind: ClusterSPIFFEID
metadata: {{name: agent-with-dns-names}}
spec:
  className: {class_name}
  spiffeIDTemplate: "spiffe://{{{{ .TrustDomain }}}}/ns/{{{{ .PodMeta.Namespace }}}}/sa/{{{{ .PodSpec.ServiceAccountName }}}}"
  podSelector: {{matchLabels: {{app: agent}}}}
  dnsNameTemplates: ["agent.tenuo.svc.cluster.local", "agent"]
"""
# An ingress gateway in front of the issuer: plain HTTP on 80, and mutual TLS with its own authority on 443.
GATEWAY_ROUTES = """
apiVersion: networking.istio.io/v1
kind: Gateway
metadata: {name: issuer, namespace: tenuo}
spec:
  selector: {istio: ingress}
  servers:
  - port: {number: 80, name: http, protocol: HTTP}
    hosts: ["*"]
  - port: {number: 443, name: https, protocol: HTTPS}
    hosts: ["*"]
    tls: {mode: MUTUAL, credentialName: gateway-certificate}
---
apiVersion: networking.istio.io/v1
kind: VirtualService
metadata: {name: issuer, namespace: tenuo}
spec:
  hosts: ["*"]
  gateways: [issuer]
  http:
  - route: [{destination: {host: issuer.tenuo.svc.cluster.local, port: {number: 8080}}}]
"""
# Certificates for the gateway's mutual TLS: a server certificate, and a client certificate
# for an agent outside the cluster, both from an authority that is not the mesh's.
MAKE_GATEWAY_CERTIFICATES = r"""
import json
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

now = datetime.now(timezone.utc)
def new_key(): return ec.generate_private_key(ec.SECP256R1())
def private(key): return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
def public(cert): return cert.public_bytes(serialization.Encoding.PEM).decode()
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "partner.example authority")])
def builder(): return x509.CertificateBuilder().issuer_name(name).not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(hours=6)).serial_number(x509.random_serial_number())
ca_key, server_key, client_key = new_key(), new_key(), new_key()
ca = builder().subject_name(name).public_key(ca_key.public_key()).add_extension(x509.BasicConstraints(True, None), True).add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True).sign(ca_key, hashes.SHA256())
server = builder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "issuer.example")])).public_key(server_key.public_key()).add_extension(x509.SubjectAlternativeName([x509.DNSName("issuer.example")]), False).add_extension(x509.BasicConstraints(False, None), True).sign(ca_key, hashes.SHA256())
client = builder().subject_name(x509.Name([])).public_key(client_key.public_key()).add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier("spiffe://partner.example/agent")]), True).add_extension(x509.BasicConstraints(False, None), True).add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), True).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False).sign(ca_key, hashes.SHA256())
print(json.dumps({"ca.crt": public(ca), "tls.crt": public(server), "tls.key": private(server_key), "client.crt": public(client), "client.key": private(client_key)}))
"""


def run(*command: str, env=None, stdin=None, timeout=600) -> str:
    result = subprocess.run(command, capture_output=True, env=env, input=stdin, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{' '.join(command[:6])} failed:\n{result.stdout.decode()}{result.stderr.decode()}")
    return result.stdout.decode()


class Cluster:
    def __init__(self, directory: Path):
        self.directory = directory
        self.name = f"tenuo-istio-check-{os.getpid()}"
        self.environment = {
            **os.environ,
            "KUBECONFIG": str(directory / "kubeconfig"),
            "HELM_REPOSITORY_CONFIG": str(directory / "helm-repositories.yaml"),
            "HELM_REPOSITORY_CACHE": str(directory / "helm-cache"),
        }

    def start(self) -> None:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        run(
            "docker", "run", "-d", "--name", self.name, "--privileged",
            "-p", f"127.0.0.1:{port}:6443",
            "-v", f"{REPOSITORY}:/work:ro",
            K3S_IMAGE, "server", "--disable=traefik", "--disable=metrics-server", "--tls-san=127.0.0.1",
            # A throwaway cluster on a developer machine: do not evict pods because the disk is fairly full.
            "--kubelet-arg=eviction-hard=imagefs.available<1%,nodefs.available<1%",
            "--kubelet-arg=eviction-minimum-reclaim=imagefs.available=1%,nodefs.available=1%",
        )  # fmt: skip
        deadline = time.monotonic() + 120
        while True:
            try:
                config = run("docker", "exec", self.name, "cat", "/etc/rancher/k3s/k3s.yaml")
                if "server:" in config:
                    break
            except RuntimeError:
                pass
            if time.monotonic() > deadline:
                raise RuntimeError("The cluster did not start")
            time.sleep(1)
        path = self.directory / "kubeconfig"
        path.write_text(config.replace("https://127.0.0.1:6443", f"https://127.0.0.1:{port}"))
        path.chmod(0o600)
        self.wait(lambda: " Ready" in self.kubectl("get", "nodes"), "the node is ready")

    def stop(self) -> None:
        # -v: the k3s image declares volumes, which would otherwise outlive the container.
        subprocess.run(["docker", "rm", "-f", "-v", self.name], capture_output=True)

    def kubectl(self, *arguments: str, stdin=None) -> str:
        return run("kubectl", *arguments, env=self.environment, stdin=stdin)

    def helm(self, *arguments: str) -> str:
        return run("helm", *arguments, env=self.environment)

    def wait(self, condition, what: str, seconds: float = 180) -> None:
        deadline = time.monotonic() + seconds
        while True:
            try:
                if condition():
                    return
            except RuntimeError:
                pass
            if time.monotonic() > deadline:
                raise RuntimeError(f"Timed out waiting until {what}")
            time.sleep(2)

    def load_image(self) -> None:
        saved = subprocess.run(["docker", "save", IMAGE], capture_output=True, check=True).stdout
        run("docker", "exec", "-i", self.name, "ctr", "-n", "k8s.io", "images", "import", "-", stdin=saved)

    def python(self, namespace: str, workload: str, script: str, *arguments: str) -> list:
        """Run one of this directory's scripts in a workload's own container. Returns its output lines."""
        output = self.kubectl(
            "-n", namespace, "exec", f"deploy/{workload}", "-c", workload, "--",
            "python", f"/work/tenuo-python/examples/spiffe/istio/{script}", *arguments,
        )  # fmt: skip
        return output.strip().splitlines()


def expect(what: str, lines: list, wanted: dict) -> None:
    """Each line is 'label: outcome'. ``wanted`` maps a label to text its outcome must contain."""
    outcomes = dict(line.split(": ", 1) for line in lines if ": " in line)
    for label, text in wanted.items():
        if text not in outcomes.get(label, ""):
            raise RuntimeError(f"{what}, {label}: expected {text!r}, got {outcomes.get(label)!r}\n" + "\n".join(lines))


def generated_settings(cluster: Cluster) -> dict:
    """What Istio configured for traffic into the issuer."""
    dump = json.loads(
        cluster.kubectl(
            "-n",
            "tenuo",
            "exec",
            "deploy/issuer-tcp",
            "-c",
            "istio-proxy",
            "--",
            "pilot-agent",
            "request",
            "GET",
            "config_dump",
        )  # fmt: skip
    )
    found = {}

    def walk(node):
        if isinstance(node, dict):
            if str(node.get("stat_prefix", "")).startswith("inbound_0.0.0.0_8080"):
                found["forward_client_cert_details"] = node.get("forward_client_cert_details")
                found["set_current_client_cert_details"] = node.get("set_current_client_cert_details")
            bind = node.get("upstream_bind_config")
            if node.get("name") == "inbound|8080||" and bind:
                found["connects_from"] = bind.get("source_address", {}).get("address")
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(dump)
    return found


def issuer_keys(directory: Path) -> None:
    """The issuer's key pair, made as the guide's make_issuer_key.py does."""
    keys = json.loads(
        run(
            "docker",
            "run",
            "--rm",
            IMAGE,
            "python",
            "-c",
            "import json; from tenuo import SigningKey; key = SigningKey.generate(); "
            "print(json.dumps({'private': key.to_pem(), 'public': key.public_key.to_pem()}))",
        )  # fmt: skip
    )
    (directory / "tenuo-issuer.pem").write_text(keys["private"])
    (directory / "tenuo-issuer.pub").write_text(keys["public"])


def check_exchange(cluster: Cluster) -> None:
    for issuer in (ISSUER, ISSUER_TCP):
        line = None

        def served(issuer=issuer):
            nonlocal line
            line = cluster.python("tenuo", "agent", "agent.py", issuer)[-1]
            return line.startswith("WARRANT")

        try:
            cluster.wait(served, "the agent is issued a warrant", 90)
        except RuntimeError:
            raise RuntimeError(f"The agent got no warrant from {issuer}: {line}") from None
        if "bound_to_holder=True" not in line:
            raise RuntimeError(f"Unexpected warrant: {line}")
        refused = cluster.python("tenuo", "agent", "agent.py", issuer, "another-task")[-1]
        if "not authorized" not in refused:
            raise RuntimeError(f"A task the policy does not approve was not refused: {refused}")


def check_around_the_sidecar(cluster: Cluster) -> None:
    """A workload with another identity, holding its own mesh certificate and connecting around its sidecar."""
    for issuer in (ISSUER, ISSUER_TCP):
        expect(
            f"around the sidecar to {issuer}",
            cluster.python("tenuo", "other", "probe.py", "around", issuer),
            {
                "nothing of its own": "403 refused: Workload is not authorized",
                "a complete made-up entry": "403 unauthenticated: x-forwarded-client-cert describes more than one",
                "an entry that opens a quote": "403 unauthenticated: Malformed",
                "two made-up header lines": "403 unauthenticated: x-forwarded-client-cert describes more than one",
                "a made-up X-Forwarded-For": "403 refused: Workload is not authorized",
            },
        )
    print(
        "Verified: another workload, sending identity headers of its own around its sidecar, "
        "was refused or served as itself."
    )


def check_outside_and_inside(cluster: Cluster) -> None:
    # A pod outside the mesh. Istio's default (PERMISSIVE) lets its plain HTTP through, with no identity.
    labels = ("nothing of its own", "a complete made-up entry", "two made-up header lines")
    expect(
        "outside the mesh",
        cluster.python("outside-mesh", "outsider", "probe.py", "plain", ISSUER),
        {label: "403 unauthenticated: No forwarded client identity" for label in labels},
    )
    print("Verified: a pod without a sidecar got no identity, whatever header it sent.")
    # From inside the issuer's own pod.
    inside = cluster.python(
        "tenuo", "issuer-tcp", "probe.py", "inside", "127.0.0.1:8080", f"http://{ISSUER_TCP}/warrants"
    )
    expect(
        "inside the TCP issuer's pod",
        inside,
        {"loopback": "403 forbidden", "pod address": "403 forbidden", "pod address, as 127.0.0.6": "200 warrant"},
    )
    inside = cluster.python("tenuo", "issuer", "probe.py", "inside", "127.0.0.1:8080", f"http://{ISSUER}/warrants")
    expect(
        "inside the Unix-socket issuer's pod",
        inside,
        {label: "no reply" for label in ("loopback", "pod address", "pod address, as 127.0.0.6")},
    )
    print(
        "Verified: inside the issuer's pod, only a process that binds the sidecar's own address reaches a TCP issuer "
        "(the documented limit); the Unix-socket issuer has no port to reach."
    )


def check_gateway(cluster: Cluster, directory: Path) -> None:
    """Callers that arrive through an Istio ingress gateway and then the issuer's sidecar."""
    certificates = json.loads(run("docker", "run", "--rm", IMAGE, "python", "-c", MAKE_GATEWAY_CERTIFICATES))
    for name, content in certificates.items():
        (directory / name).write_text(content)
    cluster.helm(
        "install", "istio-ingress", "istio/gateway", "-n", "istio-ingress", "--create-namespace",
        "--version", ISTIO_VERSION, "--set", "service.type=ClusterIP", "--wait", "--timeout", "5m",
    )  # fmt: skip
    cluster.kubectl(
        "-n", "istio-ingress", "create", "secret", "generic", "gateway-certificate",
        *(f"--from-file={name}={directory / name}" for name in ("tls.crt", "tls.key", "ca.crt")),
    )  # fmt: skip
    cluster.kubectl(
        "-n", "outside-mesh", "create", "secret", "generic", "gateway-client",
        *(f"--from-file={name}={directory / name}" for name in ("client.crt", "client.key", "ca.crt")),
    )  # fmt: skip
    cluster.kubectl("apply", "-f", "-", stdin=GATEWAY_ROUTES.encode())
    cluster.kubectl("-n", "outside-mesh", "rollout", "restart", "deploy/outsider")  # Picks up the client certificate.
    cluster.kubectl("-n", "outside-mesh", "rollout", "status", "deploy/outsider", "--timeout=300s")
    audience = f"http://{ISSUER}/warrants"
    wanted = {
        # Through a plain gateway every caller is the gateway itself, which no policy should approve.
        "plain HTTP, nothing of its own": "403 refused: Workload is not authorized",
        "plain HTTP, a complete made-up entry": "403 refused: Workload is not authorized",
        # Through mutual TLS the header carries the caller's entry and the gateway's: two hops.
        "mutual TLS, nothing of its own": "403 unauthenticated: x-forwarded-client-cert describes more than one",
        "mutual TLS, a complete made-up entry": "403 unauthenticated: x-forwarded-client-cert describes more than one",
    }
    lines: list = []

    def routed():
        lines[:] = cluster.python("outside-mesh", "outsider", "probe.py", "gateway", GATEWAY, audience)
        expect("through the gateway", lines, wanted)
        return True

    try:
        cluster.wait(routed, "the gateway routes to the issuer", 90)
    except RuntimeError:
        raise RuntimeError("Requests through the gateway did not behave as expected:\n" + "\n".join(lines)) from None
    print(
        "Verified: through an ingress gateway, a caller is the gateway's own identity over plain HTTP "
        "(refused by policy), and is refused as a second proxy hop over mutual TLS."
    )


def check_strict(cluster: Cluster) -> None:
    """With mutual TLS required, the pod outside the mesh is cut off before HTTP."""
    cluster.kubectl(
        "apply", "-f", "-",
        stdin=b"apiVersion: security.istio.io/v1\nkind: PeerAuthentication\n"
        b"metadata: {name: default, namespace: tenuo}\nspec: {mtls: {mode: STRICT}}\n",
    )  # fmt: skip

    def cut_off():
        lines = cluster.python("outside-mesh", "outsider", "probe.py", "plain", ISSUER)
        return all("no reply" in line for line in lines)

    cluster.wait(cut_off, "STRICT mutual TLS cuts off the pod outside the mesh", 90)
    if not cluster.python("tenuo", "agent", "agent.py", ISSUER)[-1].startswith("WARRANT"):
        raise RuntimeError("The agent was not served under STRICT mutual TLS")
    print("Verified: with STRICT mutual TLS the pod outside the mesh is cut off and the agent is still served.")


def check_dns_names(cluster: Cluster) -> None:
    """SPIRE puts DNS names on the agent's certificate. Istio forwards them behind the URI."""
    class_name = cluster.kubectl("get", "clusterspiffeid", "-o", "jsonpath={.items[0].spec.className}")
    cluster.kubectl("apply", "-f", "-", stdin=AGENT_WITH_DNS_NAMES.format(class_name=class_name).encode())

    def reissued():
        certificates = cluster.kubectl(
            "-n", "tenuo", "exec", "deploy/agent", "-c", "istio-proxy", "--", "pilot-agent", "request", "GET", "certs"
        )
        return "agent.tenuo.svc.cluster.local" in certificates

    cluster.wait(reissued, "SPIRE reissues the agent's certificate with DNS names", 120)
    # A fresh pod, so that no connection made with the earlier certificate is reused.
    cluster.kubectl("-n", "tenuo", "rollout", "restart", "deploy/agent")
    cluster.kubectl("-n", "tenuo", "rollout", "status", "deploy/agent", "--timeout=300s")
    cluster.wait(reissued, "the new agent pod has its certificate", 120)
    strict = allowed = ""

    def settled():
        nonlocal strict, allowed
        strict = cluster.python("tenuo", "agent", "agent.py", ISSUER)[-1]
        allowed = cluster.python("tenuo", "agent", "agent.py", ISSUER_TCP)[-1]
        return "see allow_dns_names" in strict and allowed.startswith("WARRANT")

    try:
        cluster.wait(settled, "the two issuers answer", 90)
    except RuntimeError:
        raise RuntimeError(f"Unexpected answers for a certificate with DNS names: {strict} / {allowed}") from None
    print(
        "Verified: for a certificate with DNS names, the issuer refuses by default and issues "
        "once allow_dns_names is set."
    )


def main() -> None:
    keep, spire = "--keep" in sys.argv[1:], "--spire" in sys.argv[1:]
    for tool in ("docker", "kubectl", "helm"):
        if shutil.which(tool) is None:
            raise SystemExit(f"{tool} is not on PATH")
    given = os.environ.get("TENUO_SPIFFE_IMAGE")
    if given:
        run("docker", "tag", given, IMAGE)
    else:
        print("Building the image (SPIRE and Envoy are in it too; only Python is used here)...")
        run("docker", "build", "-q", "-t", IMAGE, "-f", str(HERE.parent / "Dockerfile"), str(REPOSITORY))
    directory = Path(tempfile.mkdtemp(prefix="tenuo-istio-"))
    cluster = Cluster(directory)
    try:
        print("Starting a single-node cluster in a container...")
        cluster.start()
        cluster.load_image()
        cluster.helm("repo", "add", "istio", ISTIO_CHARTS)
        istiod = ["--wait", "--timeout", "8m"]
        if spire:
            print(f"Installing SPIRE (chart {SPIRE_CHART_VERSION})...")
            run("docker", "exec", cluster.name, "mount", "--make-rshared", "/")  # The SPIFFE CSI driver needs it.
            (directory / "spire-values.yaml").write_text(SPIRE_VALUES)
            (directory / "istiod-values.yaml").write_text(ISTIOD_SPIRE_VALUES)
            cluster.helm("repo", "add", "spiffe", SPIRE_CHARTS)
            cluster.helm(
                "install", "spire-crds", "spiffe/spire-crds", "-n", "spire-server", "--create-namespace",
                "--version", SPIRE_CRDS_VERSION, "--wait",
            )  # fmt: skip
            cluster.helm(
                "install", "spire", "spiffe/spire", "-n", "spire-server", "--version", SPIRE_CHART_VERSION,
                "-f", str(directory / "spire-values.yaml"), "--wait", "--timeout", "8m",
            )  # fmt: skip
            istiod += ["-f", str(directory / "istiod-values.yaml")]
        print(
            f"Installing Istio {ISTIO_VERSION}" + (", with SPIRE issuing workload certificates..." if spire else "...")
        )
        cluster.kubectl("create", "namespace", "istio-system")
        cluster.helm("install", "istio-base", "istio/base", "-n", "istio-system", "--version", ISTIO_VERSION, "--wait")
        cluster.helm("install", "istiod", "istio/istiod", "-n", "istio-system", "--version", ISTIO_VERSION, *istiod)

        issuer_keys(directory)
        print("Deploying the issuer, an agent, and the workloads used for the refusal checks...")
        cluster.kubectl("apply", "-f", str(HERE / "manifests.yaml"), "-f", str(HERE / "checks.yaml"))
        cluster.kubectl(
            "-n", "tenuo", "create", "secret", "generic", "issuer-key",
            f"--from-file=tenuo-issuer.pem={directory / 'tenuo-issuer.pem'}",
        )  # fmt: skip
        cluster.kubectl(
            "-n", "tenuo", "create", "configmap", "issuer-pub",
            f"--from-file=tenuo-issuer.pub={directory / 'tenuo-issuer.pub'}",
        )  # fmt: skip
        meshed = ["issuer", "issuer-tcp", "agent", "other"]
        if spire:
            # The around-the-sidecar check needs the workload's key on disk, which Istio only writes for its own
            # certificates. With SPIRE the sidecar fetches the key itself.
            cluster.kubectl("-n", "tenuo", "delete", "deployment", "other")
            meshed.remove("other")
            use_spire = json.dumps(
                {"spec": {"template": {"metadata": {"annotations": {"inject.istio.io/templates": "sidecar,spire"}}}}}
            )
            for workload in meshed:
                cluster.kubectl("-n", "tenuo", "patch", "deployment", workload, "--type", "merge", "-p", use_spire)
            cluster.kubectl("-n", "tenuo", "set", "env", "deploy/issuer-tcp", "ALLOW_DNS_NAMES=1")
        for namespace, workloads in (("tenuo", meshed), ("outside-mesh", ["outsider"])):
            for workload in workloads:
                cluster.kubectl("-n", namespace, "rollout", "status", f"deploy/{workload}", "--timeout=300s")

        settings = generated_settings(cluster)
        print(f"Istio generated for the issuer's inbound listener: {json.dumps(settings)}")
        if (
            settings.get("forward_client_cert_details") != "APPEND_FORWARD"
            or settings.get("connects_from") != "127.0.0.6"
        ):
            raise RuntimeError("Istio's generated settings differ from what the guide describes")

        check_exchange(cluster)
        if spire:
            certificates = cluster.kubectl(
                "-n", "tenuo", "exec", "deploy/agent", "-c", "istio-proxy", "--", "pilot-agent", "request", "GET", "certs"
            )  # fmt: skip
            if '"spiffe://cluster.local"' not in certificates:  # The name on SPIRE's own authority certificate.
                raise RuntimeError("The agent's sidecar is not using certificates from SPIRE")
            print(
                "Verified: with SPIRE issuing the mesh's certificates, an agent was issued a warrant "
                "on its SPIFFE ID, over a Unix socket and over TCP."
            )
            check_outside_and_inside(cluster)
            check_dns_names(cluster)
        else:
            print(
                "Verified: an agent in the mesh was issued a warrant on its Istio identity, "
                "over a Unix socket and over TCP."
            )
            check_around_the_sidecar(cluster)
            check_outside_and_inside(cluster)
            check_gateway(cluster, directory)
            check_strict(cluster)
    finally:
        if keep:
            print(f"Left running. KUBECONFIG={directory / 'kubeconfig'}  Remove with: docker rm -f -v {cluster.name}")
        else:
            cluster.stop()
            shutil.rmtree(directory, ignore_errors=True)


if __name__ == "__main__":
    main()
