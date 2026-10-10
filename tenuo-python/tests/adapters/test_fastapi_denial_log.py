"""FastAPI denial logs carry argument names, never request values."""

import base64
import logging
import time

import pytest

pytest.importorskip("fastapi")

from fastapi import Depends, FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tenuo import Pattern, SigningKey, Warrant  # noqa: E402
from tenuo.fastapi import X_TENUO_POP, X_TENUO_WARRANT, SecurityContext, TenuoGuard, configure_tenuo  # noqa: E402

SECRET = "hunter2-secret-value"


def test_denial_log_has_arg_keys_not_values(caplog):
    key = SigningKey.generate()
    app = FastAPI()
    configure_tenuo(app, trusted_issuers=[key.public_key])

    @app.get("/search")
    def search(query: str, ctx: SecurityContext = Depends(TenuoGuard("search"))):
        return {"ok": True}

    warrant = Warrant.mint_builder().capability("search", query=Pattern("ok*")).mint(key)
    args = {"query": SECRET}
    pop = base64.b64encode(warrant.sign(key, "search", args, int(time.time()))).decode("ascii")

    with caplog.at_level(logging.WARNING, logger="tenuo.fastapi"):
        resp = TestClient(app).get(
            f"/search?query={SECRET}", headers={X_TENUO_WARRANT: warrant.to_base64(), X_TENUO_POP: pop}
        )

    assert resp.status_code == 403
    denials = [r.getMessage() for r in caplog.records if "Authorization denied" in r.getMessage()]
    assert denials
    assert "['query']" in denials[0]
    assert all(SECRET not in m for m in denials)
