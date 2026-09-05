"""Preflight for a platform install. Each failure names the value to change."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, List, Optional
from urllib.parse import urlparse

import httpx

from .check import all_passed, format_table, run_containment
from .config import ConfigError, GatewayConfig


@dataclass
class DoctorRow:
    name: str
    ok: bool
    detail: str
    fix: str = ""

    @property
    def expected(self) -> str:
        return "ok" if self.ok else "fail"

    @property
    def actual(self) -> str:
        return "ok" if self.ok else "fail"


@dataclass
class DoctorReport:
    rows: List[DoctorRow] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(row.ok for row in self.rows)

    def add(self, name: str, ok: bool, detail: str, fix: str = "") -> None:
        self.rows.append(DoctorRow(name, ok, detail, fix))


def format_report(report: DoctorReport) -> str:
    lines = [f"{'name':<42} {'result':<8} detail"]
    for row in report.rows:
        mark = "ok" if row.ok else "FAIL"
        lines.append(f"{row.name:<42} {mark:<8} {row.detail}")
        if not row.ok and row.fix:
            lines.append(f"{'':<42} {'fix':<8} {row.fix}")
    return "\n".join(lines)


def _json(response: Any) -> Any:
    try:
        return response.json()
    except Exception:
        return None


def _get(client: Any, url: str) -> Any:
    return client.get(url)


def _post(client: Any, url: str, payload: Optional[dict] = None) -> Any:
    return client.post(url, json=payload or {})


def probe_ready(client: Any, base: str) -> tuple[Optional[str], str]:
    """Return (role or None, error text)."""
    url = base.rstrip("/") + "/ready"
    try:
        response = _get(client, url)
    except Exception as exc:
        return None, f"could not reach {url} ({exc.__class__.__name__})"
    if getattr(response, "status_code", 0) >= 400:
        return None, f"{url} returned {response.status_code}"
    body = _json(response)
    if not isinstance(body, dict):
        return None, f"{url} returned non-JSON"
    role = body.get("role")
    if not isinstance(role, str) or not role:
        return None, f"{url} omitted role"
    return role, ""


def probe_health(client: Any, base: str) -> tuple[bool, str]:
    url = base.rstrip("/") + "/health"
    try:
        response = _get(client, url)
    except Exception as exc:
        return False, f"could not reach {url} ({exc.__class__.__name__})"
    if getattr(response, "status_code", 0) >= 400:
        return False, f"{url} returned {response.status_code}"
    body = _json(response)
    if isinstance(body, dict) and body.get("status") == "ok":
        return True, "ok"
    return False, f"{url} did not report status=ok"


def run_doctor(
    *,
    gateway_url: str,
    exchange_url: str = "",
    audience: str = "",
    environ: Optional[dict] = None,
    client: Any = None,
    config: Optional[GatewayConfig] = None,
    containment: bool = False,
    gateway_only: bool = False,
) -> DoctorReport:
    """Probe exchange and gateway. Does not mint a warrant or print secrets."""
    env = dict(environ if environ is not None else os.environ)
    report = DoctorReport()
    gateway = gateway_url.rstrip("/")
    exchange = "" if gateway_only else (exchange_url or gateway_url).rstrip("/")
    own = client is None
    http = client or httpx.Client(timeout=10.0)
    try:
        if not gateway:
            report.add(
                "gateway_url",
                False,
                "gateway_url is empty",
                "Set TENUO_GATEWAY_URL or --gateway-url to the gateway Service.",
            )
            return report

        if gateway_only and not audience.strip():
            report.add("audience", True, "skipped (gateway-only)", "")
        elif not audience.strip():
            report.add(
                "audience",
                False,
                "OIDC audience is empty",
                "Set the action audience input (or TENUO_EXCHANGE_AUDIENCE) to exchange.audience, or Cloud tenuo:org/<tenant>.",
            )
        else:
            report.add("audience", True, audience, "")

        token_name = next((name for name in ("GITHUB_TOKEN", "GH_TOKEN") if env.get(name)), "")
        if token_name:
            report.add(
                "no GitHub token in environment",
                False,
                f"{token_name} is set",
                f"Unset {token_name}. The agent and doctor jobs must not hold a GitHub credential.",
            )
        else:
            report.add("no GitHub token in environment", True, "absent", "")

        healthy, detail = probe_health(http, gateway)
        report.add(
            "gateway health",
            healthy,
            detail,
            "" if healthy else "Point gateway_url at the gateway Deployment /health.",
        )
        gw_role, gw_err = probe_ready(http, gateway)
        if gw_role is None:
            report.add(
                "gateway ready",
                False,
                gw_err,
                "Confirm the gateway Service is up and TENUO_ROLE=gateway.",
            )
        elif gw_role == "exchange":
            report.add(
                "gateway ready",
                False,
                "this URL serves the exchange role",
                "Point gateway_url at the gateway Service. Only the gateway mints installation tokens.",
            )
        else:
            report.add("gateway ready", True, f"role={gw_role}", "")

        if gateway_only:
            report.add("exchange health", True, "skipped (gateway-only)", "")
            report.add("exchange ready", True, "skipped (gateway-only)", "")
            report.add("split identities", True, "gateway-only; Cloud or a later exchange Deployment issues warrants", "")
            report.add("exchange route", True, "skipped (gateway-only)", "")
        else:
            healthy, detail = probe_health(http, exchange)
            report.add(
                "exchange health",
                healthy,
                detail,
                "" if healthy else "Point exchange_url at the exchange Deployment /health.",
            )
            ex_role, ex_err = probe_ready(http, exchange)
            if ex_role is None:
                report.add(
                    "exchange ready",
                    False,
                    ex_err,
                    "Confirm the exchange Service is up and TENUO_ROLE=exchange.",
                )
            elif ex_role == "gateway":
                report.add(
                    "exchange ready",
                    False,
                    "this URL serves the gateway role",
                    "Point exchange_url at the exchange Service. TENUO_ROLE=both is a test escape.",
                )
            else:
                report.add("exchange ready", True, f"role={ex_role}", "")

            same = urlparse(gateway).netloc == urlparse(exchange).netloc and urlparse(gateway).path == urlparse(exchange).path
            if same or (gw_role == "both" or ex_role == "both"):
                report.add(
                    "split identities",
                    False,
                    "exchange and gateway share one URL or role=both",
                    "Install two Deployments. TENUO_ROLE=both requires TENUO_ALLOW_COMBINED_ROLES=1 and is not a production install.",
                )
            elif gw_role == "gateway" and ex_role == "exchange":
                report.add("split identities", True, "exchange and gateway are separate", "")

            try:
                posted = _post(http, exchange + "/v1/exchange", {})
                status = getattr(posted, "status_code", 0)
            except Exception as exc:
                report.add(
                    "exchange route",
                    False,
                    f"POST /v1/exchange failed ({exc.__class__.__name__})",
                    "Confirm the exchange Service exposes POST /v1/exchange.",
                )
            else:
                if status == 404:
                    report.add(
                        "exchange route",
                        False,
                        "POST /v1/exchange returned 404",
                        "This process is not serving the exchange. Set TENUO_ROLE=exchange on that Deployment.",
                    )
                else:
                    report.add("exchange route", True, f"POST /v1/exchange returned {status}", "")

        try:
            denied = _post(
                http,
                gateway + "/v1/call",
                {"tool": "github.get_issue", "arguments": {"repository": "acme/widgets", "issue": 1}},
            )
            status = getattr(denied, "status_code", 0)
            body = _json(denied)
        except Exception as exc:
            report.add(
                "gateway fail-closed",
                False,
                f"POST /v1/call failed ({exc.__class__.__name__})",
                "Confirm the gateway Service exposes POST /v1/call.",
            )
        else:
            allowed = isinstance(body, dict) and body.get("allowed") is True
            if status == 404:
                report.add(
                    "gateway fail-closed",
                    False,
                    "POST /v1/call returned 404",
                    "This process is not serving the gateway. Set TENUO_ROLE=gateway on that Deployment.",
                )
            elif allowed:
                report.add(
                    "gateway fail-closed",
                    False,
                    "POST /v1/call allowed a request with no warrant",
                    "The gateway must refuse a call that omits the envelope.",
                )
            else:
                report.add("gateway fail-closed", True, f"POST /v1/call returned {status} without a warrant", "")

        hosted = env.get("RUNNER_ENVIRONMENT") == "github-hosted" or (
            env.get("GITHUB_ACTIONS") == "true" and env.get("RUNNER_NAME", "").startswith("GitHub Actions")
        )
        if env.get("GITHUB_ACTIONS") == "true" and hosted:
            report.add(
                "I2 network policy",
                True,
                "not enforced on GitHub-hosted runners; I1 still denies the agent a token",
                "",
            )
        elif env.get("GITHUB_ACTIONS") == "true":
            report.add(
                "I2 network policy",
                True,
                "self-hosted: confirm the runner NetworkPolicy allows only the gateway",
                "",
            )

        if config is not None:
            if config.audience and audience and config.audience != audience:
                report.add(
                    "audience matches config",
                    False,
                    f"action audience {audience!r} != exchange.audience {config.audience!r}",
                    "Set the action audience input to the exchange.audience value in the chart.",
                )
            elif config.audience:
                report.add("audience matches config", True, config.audience, "")
            report.add(
                "execution catalog",
                True,
                f"packs={','.join(config.packs) or 'none'} repos={len(config.repositories)}",
                "",
            )

        if containment:
            from pathlib import Path
            import tempfile

            from tenuo import Exact, Range
            from tenuo_core import SigningKey, Warrant

            from .app import Gateway

            issuer = SigningKey.generate()
            holder = SigningKey.generate()
            receipts = Path(tempfile.mkdtemp()) / "receipts.jsonl"
            local = GatewayConfig.from_mapping(
                {
                    "version": 1,
                    "trust": {"root_public_keys": ["${TENUO_ROOT_PUBLIC_KEY}"]},
                    "signing": {"provider": "memory"},
                    "ceiling": {"repositories": ["acme/widgets"]},
                    "tools": {"packs": ["github-triage"]},
                    "receipts": {"path": str(receipts)},
                },
                environ={
                    "TENUO_ALLOW_INSECURE_MEMORY_KEYS": "1",
                    "TENUO_ROLE": "gateway",
                    "TENUO_ROOT_PUBLIC_KEY": issuer.public_key.to_bytes().hex(),
                },
            )
            warrant = (
                Warrant.mint_builder()
                .capability("github.get_issue", repository=Exact("acme/widgets"), issue=Range(4127, 4127))
                .capability("github.add_comment", repository=Exact("acme/widgets"), issue=Range(4127, 4127))
                .holder(holder.public_key)
                .ttl(900)
                .mint(issuer)
            )
            rows = run_containment(
                Gateway(local),
                warrant,
                holder,
                bound_repository="acme/widgets",
                bound_issue=4127,
                foreign_repository="acme/payments-internal",
            )
            report.add(
                "in-process containment",
                all_passed(rows),
                "all rows passed" if all_passed(rows) else format_table(rows),
                "" if all_passed(rows) else "The in-process table failed. See rows above.",
            )
    finally:
        if own:
            http.close()
    return report


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Preflight a Tenuo for GitHub Actions install")
    parser.add_argument("--gateway-url", default=os.environ.get("TENUO_GATEWAY_URL", ""))
    parser.add_argument("--exchange-url", default=os.environ.get("TENUO_EXCHANGE_URL", ""))
    parser.add_argument("--audience", default=os.environ.get("TENUO_EXCHANGE_AUDIENCE", ""))
    parser.add_argument("--config", default=os.environ.get("TENUO_GATEWAY_CONFIG", ""))
    parser.add_argument("--containment", action="store_true", help="Also run the in-process containment table")
    parser.add_argument(
        "--gateway-only",
        action="store_true",
        help="Prove the customer box only. Skip Cloud / exchange probes.",
    )
    args = parser.parse_args()
    config = None
    if args.config:
        try:
            config = GatewayConfig.from_yaml(args.config)
        except (ConfigError, OSError) as exc:
            print(f"config: FAIL {exc}")
            raise SystemExit(1) from exc
    report = run_doctor(
        gateway_url=args.gateway_url,
        exchange_url=args.exchange_url,
        audience=args.audience,
        config=config,
        containment=args.containment,
        gateway_only=args.gateway_only,
    )
    print(format_report(report))
    if not report.ok:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
