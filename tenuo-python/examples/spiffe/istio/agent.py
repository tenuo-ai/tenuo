"""An agent in the mesh asks the issuer for a warrant. Its sidecar supplies the identity.

Usage: agent.py ISSUER_HOST:PORT [TASK_ID]
"""

import sys
from pathlib import Path

from tenuo import PublicKey, SigningKey
from tenuo.spiffe import SpiffeError
from tenuo.spiffe_forwarded import request_warrant_forwarded

host = sys.argv[1]
task = sys.argv[2] if len(sys.argv) > 2 else "refund-task-123"
holder_key = SigningKey.generate()  # Never leaves this process.

try:
    warrant = request_warrant_forwarded(
        f"http://{host}/warrants",  # Plain HTTP here: the sidecar adds mutual TLS.
        audience=f"http://{host}/warrants",
        issuer_key=PublicKey.from_pem(Path("/pub/tenuo-issuer.pub").read_text()),
        holder_key=holder_key,
        task_id=task,
    )
except SpiffeError as exc:
    print(f"REFUSED {exc}")
else:
    print(
        f"WARRANT {warrant.id} tools={warrant.tools} bound_to_holder={warrant.authorized_holder == holder_key.public_key}"
    )
