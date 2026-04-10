"""
Control-plane HTTP transport.

Minimal ``urllib``-based submit helper.  Protocol-level logic (request
building, hash verification, attestation, response decoding) lives in
:mod:`tenuo.cp_approval`.

Production callers should use an async HTTP client with retries and
circuit-breaking; this module is a zero-dependency convenience.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

from .cp_approval import ControlPlaneApprovalRequestV1, ControlPlaneApprovalResponseV1

__all__ = [
    "submit_control_plane_approval_request_v1",
]


def submit_control_plane_approval_request_v1(
    url: str,
    body: ControlPlaneApprovalRequestV1,
    *,
    api_key: Optional[str] = None,
    timeout_sec: float = 120.0,
    extra_headers: Optional[Dict[str, str]] = None,
) -> ControlPlaneApprovalResponseV1:
    """POST a v1 approval request as JSON.

    *url* is the full resource URL.  Sends ``Authorization: Bearer …``
    when *api_key* is set.
    """
    payload = json.dumps(body.to_json_dict(), separators=(",", ":")).encode("utf-8")
    headers: Dict[str, str] = {"Content-Type": "application/json", "Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as r:
            raw = r.read().decode("utf-8")
            data: Dict[str, Any] = json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        try:
            data = json.loads(e.read().decode("utf-8"))
        except Exception:
            data = {"status": "error", "error": e.reason or str(e.code)}
        return ControlPlaneApprovalResponseV1.from_json_dict(data)
    except urllib.error.URLError as e:
        return ControlPlaneApprovalResponseV1(status="error", error=str(e.reason))
    return ControlPlaneApprovalResponseV1.from_json_dict(data)
