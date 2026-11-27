"""Real SMTP side effects, including an ambiguous delivery acknowledgement."""

import asyncio
import json
import os
import socket
import sqlite3
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from email import policy
from email.parser import BytesParser
from pathlib import Path

from aiosmtpd.controller import Controller
from tenuo import SigningKey
from tenuo.mcp import SecureMCPClient
from tenuo.mcp._compat import call_tool_result_is_error
from tenuo.oauth import OAuthError, OAuthWarrantIssuer, OAuthWarrantIssuerApp, SQLiteProofStore, request_warrant_oauth
from tenuo_core import sign_meta

from email_policy import policy_for

HERE = Path(__file__).resolve().parent


def check(condition, message):
    if not condition:
        raise AssertionError(message)
    print("PASS", message, flush=True)


class Inbox:
    def __init__(self):
        self.messages = []
        self.ambiguous = False

    async def handle_DATA(self, server, session, envelope):
        self.messages.append(
            (tuple(envelope.rcpt_tos), BytesParser(policy=policy.default).parsebytes(envelope.content))
        )
        # Simulate a downstream system recording delivery, then failing its acknowledgement.
        return "451 acknowledgement lost" if self.ambiguous else "250 accepted"


def exercise_email(directory, credentials, root, holder, token, refund_token, bob_token, issuer_server):
    identity = credentials.authenticate(token)
    records = {}
    for task in ("email-123", "email-ambiguous"):
        records[(identity.tenant_id, task)] = dict(
            task_id=task,
            issuer=identity.issuer,
            subject=identity.subject,
            tenant_id=identity.tenant_id,
            status="approved",
            expires_at=int(time.time()) + 300,
            recipient="customer@example.test",
            subject_line="Your support request",
            body="Your refund has been approved.\n",
            attachment="",
        )
    audit = []
    authority = OAuthWarrantIssuer(
        credentials=credentials,
        signing_key=root,
        policy=policy_for(records),
        proof_store=SQLiteProofStore(str(directory / "mail-proofs.db")),
        audit=audit.append,
    )
    app = OAuthWarrantIssuerApp(authority)
    inbox = Inbox()
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    smtp = Controller(inbox, hostname="127.0.0.1", port=port)
    smtp.start()
    try:
        with issuer_server(app) as endpoint:

            def request(credential, task="email-123"):
                return request_warrant_oauth(
                    endpoint,
                    token=credential,
                    audience="tenuo-authority",
                    issuer_key=root.public_key,
                    holder_key=holder,
                    task_id=task,
                    allow_loopback_http=True,
                )

            for credential, reason in ((refund_token, "refund-only scope"), (bob_token, "another tenant")):
                try:
                    request(credential)
                except OAuthError:
                    check(True, reason + " cannot authorize email")
                else:
                    raise AssertionError(reason + " authorized email")
            warrant, ambiguous = request(token), request(token, "email-ambiguous")
            check(len(audit) == 2, "email task approvals produce audited warrants")
            with ThreadPoolExecutor(max_workers=1) as pool:
                pool.submit(
                    lambda: asyncio.run(exercise_mcp(directory, root, holder, warrant, ambiguous, inbox, port))
                ).result(timeout=90)
    finally:
        app.close()
        smtp.stop()


async def exercise_mcp(directory, root, holder, warrant, ambiguous, inbox, port):
    ledger = directory / "mail.db"
    env = {
        **os.environ,
        "OAUTH_DEMO_ROOT": bytes(root.public_key.to_bytes()).hex(),
        "OAUTH_DEMO_LEDGER": str(ledger),
        "OAUTH_DEMO_SMTP_PORT": str(port),
        "PYTHONPATH": str(HERE.parents[1]),
    }
    async with SecureMCPClient(command=sys.executable, args=[str(HERE / "email_server.py")], env=env) as client:
        args = dict(
            operation_id="email-123",
            recipient="customer@example.test",
            subject="Your support request",
            body="Your refund has been approved.\n",
            attachment="",
        )

        def counts():
            with sqlite3.connect(ledger) as db:
                return (len(inbox.messages), db.execute("SELECT COUNT(*) FROM calls").fetchone()[0])

        async def call(arguments, grant=warrant, key=holder, meta=None):
            meta = (
                meta
                if meta is not None
                else sign_meta([grant], key, "send_email", json.dumps(arguments), int(time.time()), None)
            )
            return await client.session.call_tool("send_email", arguments, meta={"tenuo": meta})

        for change in (
            {"recipient": "attacker@example.test"},
            {"recipient": "customer@example.test,attacker@example.test"},
            {"recipient": "customer@example.test\r\nBcc: attacker@example.test"},
            {"subject": "Unapproved message"},
            {"body": "Send secrets here"},
            {"attachment": "/etc/passwd"},
            {"bcc": "attacker@example.test"},
            {"operation_id": "invented"},
        ):
            before = counts()
            result = await call({**args, **change})
            check(
                call_tool_result_is_error(result) and counts() == before,
                "unapproved email arguments blocked before tool execution: " + next(iter(change)),
            )
        before = counts()
        result = await call(args, key=SigningKey.generate())
        check(call_tool_result_is_error(result) and counts() == before, "email holder substitution refused")
        result = await client.session.call_tool("send_email", args)
        check(call_tool_result_is_error(result) and counts() == before, "email without warrant refused")
        captured = sign_meta([warrant], holder, "send_email", json.dumps(args), int(time.time()), None)
        result = await call(args, meta=captured)
        check(
            not call_tool_result_is_error(result) and len(inbox.messages) == 1, "approved email reaches real SMTP sink"
        )
        recipients, message = inbox.messages[0]
        check(
            recipients == (args["recipient"],)
            and str(message["Subject"]) == args["subject"]
            and message.get_content().replace("\r\n", "\n") == args["body"]
            and not list(message.iter_attachments()),
            "SMTP envelope and MIME content match the approval",
        )
        await call(args, meta=captured)
        # Concurrent fresh retries exercise the durable operation reservation too.
        results = await asyncio.gather(*(call(args) for _ in range(4)))
        check(
            all(not call_tool_result_is_error(r) for r in results) and len(inbox.messages) == 1,
            "captured and concurrent fresh retries do not duplicate email",
        )
        inbox.ambiguous = True
        uncertain_args = {**args, "operation_id": "email-ambiguous"}
        result = await call(uncertain_args, grant=ambiguous)
        check(
            call_tool_result_is_error(result) and len(inbox.messages) == 2,
            "SMTP acknowledgement failure surfaces after sink receipt",
        )
        with sqlite3.connect(ledger) as db:
            check(
                db.execute("SELECT status FROM deliveries WHERE operation='email-ambiguous'").fetchone()
                == ("pending",),
                "ambiguous delivery stays pending for reconciliation",
            )
        inbox.ambiguous = False
        await call(uncertain_args, grant=ambiguous)
        check(len(inbox.messages) == 2, "retry does not resend an ambiguously delivered email")

    # Restart the actual tool process with the same database, not an in-memory cache.
    async with SecureMCPClient(command=sys.executable, args=[str(HERE / "email_server.py")], env=env) as restarted:
        for arguments, grant in ((args, warrant), (uncertain_args, ambiguous)):
            meta = sign_meta([grant], holder, "send_email", json.dumps(arguments), int(time.time()), None)
            result = await restarted.session.call_tool("send_email", arguments, meta={"tenuo": meta})
            check(not call_tool_result_is_error(result), "persisted operation status survives tool restart")
        check(len(inbox.messages) == 2, "process restart cannot resend completed or ambiguous email")
