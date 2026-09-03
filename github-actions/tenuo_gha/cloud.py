"""Cloud-compatible exchange: policy issuer → run warrant stack.

The customer gateway still mints GitHub tokens and calls api.github.com.
Cloud only issues the warrant stack and later ingests receipts / revocation.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

from tenuo import SigningKey, Warrant

from .exchange import Exchange, ExchangeResult, encode_exchange_stack


class CloudCompatibleExchange(Exchange):
    """Mint the two-warrant chain hosted Cloud returns.

    ``tenant_root`` is the configured trust anchor. It signs a policy-issuer
    warrant; the policy issuer signs the run warrant. A run may advertise
    ``root_public_keys``, but the gateway still uses deploy-time trust.
    """

    def __init__(
        self,
        config,
        *,
        tenant_root: SigningKey,
        policy_issuer: Optional[SigningKey] = None,
        **kwargs: Any,
    ) -> None:
        issuer = policy_issuer or SigningKey.generate()
        super().__init__(config, issuer_key=issuer, **kwargs)
        self._tenant_root = tenant_root
        self._policy_issuer = issuer

    def mint(
        self,
        token: str,
        body: Mapping[str, Any],
        *,
        now: Optional[int] = None,
    ) -> ExchangeResult:
        claims, holder, ttl_i, capabilities, task_context = self.validate(token, body, now=now)
        repository = str(claims["repository"])
        bound = self.bind_capabilities(capabilities, repository=repository)
        policy = self._mint_policy(bound, ttl_seconds=max(ttl_i, 60))
        builder = policy.grant_builder().holder(holder).ttl(ttl_i)
        run_id = claims.get("run_id")
        if run_id is not None and hasattr(builder, "session_id"):
            builder = builder.session_id(str(run_id))
        for tool, constraints in bound.items():
            builder = builder.capability(tool, constraints)
        run = builder.grant(self._policy_issuer)
        expires_at = run.expires_at()
        if callable(expires_at):
            expires_at = expires_at()
        return ExchangeResult(
            warrant=encode_exchange_stack([policy, run]),
            warrant_id=str(run.id),
            expires_at=str(expires_at),
            root_public_keys=[self._tenant_root.public_key.to_bytes().hex()],
            task_context=task_context,
        )

    def _mint_policy(self, bound: Mapping[str, Any], *, ttl_seconds: int):
        builder = Warrant.mint_builder().holder(self._policy_issuer.public_key).ttl(ttl_seconds)
        for tool, constraints in bound.items():
            builder = builder.capability(tool, constraints)
        return builder.mint(self._tenant_root)
