#!/usr/bin/env python3
"""
Token budgets for model calls, end to end.

A lead agent holds a warrant worth 2,000 tokens and hands two workers 1,200
each. The workers call a model through the real OpenAI SDK. One line,
``tenuo.budget_http.install()``, puts a meter under every HTTP client in the
process: it counts what each worker uses, lowers each call's output cap to what
is left, and stops them when their own budget or the lead's shared one runs out.

The "provider" is a small local server speaking the Chat Completions wire
format, so this runs with no API key:

    python examples/openai/token_budget.py

Point ``base_url`` at a real provider and the rest is unchanged (known provider
hosts need no ``hosts=`` entry).
"""

import json
import logging
import os
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import openai
from openai import OpenAI

import tenuo.budget_http
from tenuo import SigningKey, Warrant, chain_scope, key_scope, warrant_scope
from tenuo.budget import BudgetStore, llm_capability

logging.getLogger("tenuo").setLevel(logging.CRITICAL)
logging.getLogger("tenuo_core").setLevel(logging.CRITICAL)

MODEL = "gpt-4o-mini"


# ---------------------------------------------------------------------------
# A stand-in provider: answers with as many tokens as the request allows, up
# to 400, and reports usage the way the real API does.
# ---------------------------------------------------------------------------


class Provider(BaseHTTPRequestHandler):
    requests_served = 0

    def log_message(self, *args):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        Provider.requests_served += 1
        prompt = sum(len(m.get("content") or "") for m in body["messages"]) // 4 + 8
        output = min(400, body.get("max_completion_tokens") or body.get("max_tokens") or 400)
        usage = {"prompt_tokens": prompt, "completion_tokens": output, "total_tokens": prompt + output}
        base = {"id": "chatcmpl-demo", "created": 0, "model": body["model"]}

        if body.get("stream"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            events = [
                {**base, "object": "chat.completion.chunk",
                 "choices": [{"index": 0, "delta": {"role": "assistant", "content": text}, "finish_reason": None}]}
                for text in ("streamed ", "answer")
            ]
            events.append({**base, "object": "chat.completion.chunk",
                           "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]})
            if (body.get("stream_options") or {}).get("include_usage"):
                events.append({**base, "object": "chat.completion.chunk", "choices": [], "usage": usage})
            for event in events:
                self.wfile.write(f"data: {json.dumps(event)}\n\n".encode())
            self.wfile.write(b"data: [DONE]\n\n")
            return

        payload = json.dumps({
            **base, "object": "chat.completion", "usage": usage,
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": "an answer"}}],
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base_url = f"http://127.0.0.1:{server.server_address[1]}/v1"

    issuer, lead = SigningKey.generate(), SigningKey.generate()
    worker_keys = {"researcher": SigningKey.generate(), "writer": SigningKey.generate()}

    # The budget is part of the warrant: signed, and only ever narrowed.
    root = (
        Warrant.mint_builder()
        .capability("llm.chat", llm_capability(total_tokens=2_000, max_tokens=500, models=[MODEL]))
        .holder(lead.public_key)
        .ttl(3600)
        .mint(issuer)
    )
    print("Lead's warrant: 2,000 tokens in total, 500 output tokens per call, model", MODEL)

    def delegate(name: str, total: int) -> Warrant:
        return (
            root.grant_builder()
            .capability("llm.chat", llm_capability(total_tokens=total, max_tokens=500, models=[MODEL]))
            .holder(worker_keys[name].public_key)
            .ttl(600)
            .grant(lead)
        )

    try:
        delegate("researcher", 2_500)
    except Exception as e:
        print(f"Handing a worker 2,500 is refused when the warrant is made: {type(e).__name__}")

    warrants = {name: delegate(name, 1_200) for name in worker_keys}
    print("Each worker is handed 1,200 tokens (2,400 on paper, against the lead's 2,000)\n")

    # One count for every process on this host that opens the file.
    store = BudgetStore(os.path.join(tempfile.mkdtemp(), "budgets.db"))
    names = {root.id: "lead", **{w.id: name for name, w in warrants.items()}}

    def audit(event) -> None:
        totals = ", ".join(
            f"{names[level['warrant_id']]} {level['used']:,}/{level['limit']:,}"
            for level in (event.usage or {}).get("budget", [])
        )
        used = (event.usage or {}).get("total_tokens")
        spent = f"used {used:>3}" if used is not None else "not sent"
        print(f"    audit: {event.decision:5} {spent} | {totals}")

    # The only wiring. The local stand-in is not a known provider, so it is named.
    tenuo.budget_http.install(
        trusted_roots=[issuer.public_key],
        budget_store=store,
        audit_callback=audit,
        hosts=[f"127.0.0.1:{server.server_address[1]}"],
    )
    client = OpenAI(base_url=base_url, api_key="not-needed-for-the-local-provider", max_retries=0)

    def ask(name: str, question: str, stream: bool = False) -> None:
        print(f"  {name}: {question!r}" + (" (streaming)" if stream else ""))
        # Each worker's calls spend from the warrant in scope.
        with warrant_scope(warrants[name]), key_scope(worker_keys[name]), chain_scope([root]):
            try:
                result = client.chat.completions.create(
                    model=MODEL, messages=[{"role": "user", "content": question}], stream=stream
                )
                if stream:
                    text = "".join(chunk.choices[0].delta.content or "" for chunk in result)
                    print(f"    got: {text!r}")
            except openai.PermissionDeniedError as e:
                if not tenuo.budget_http.is_budget_error(e):
                    raise
                print(f"    refused: {e.body['message']}")

    for name, question, stream in [
        ("researcher", "Summarise the first source.", False),
        ("researcher", "Summarise the second source.", True),
        ("researcher", "Summarise the third source.", False),
        ("researcher", "Summarise the fourth source.", False),
        ("writer", "Draft the introduction.", False),
        ("writer", "Draft the conclusion.", False),
        ("writer", "Draft the abstract.", False),
    ]:
        ask(name, question, stream)

    used = store.used(*names)
    print("\nTotals in the store:")
    for warrant_id, name in names.items():
        print(f"  {name:10} {used[warrant_id]:>5,} tokens")
    print(f"Requests that reached the provider: {Provider.requests_served} of 7")
    tenuo.budget_http.uninstall()
    server.shutdown()


if __name__ == "__main__":
    main()
