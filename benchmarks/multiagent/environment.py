"""
Simulated enterprise environment for multi-agent delegation benchmark.

Provides tools (email, filesystem, financial) as plain functions that mutate
state and record side effects. Authorization is handled by the harness, not here.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Email:
    id: int
    sender: str
    subject: str
    body: str


@dataclass
class Transaction:
    id: int
    date: str
    to: str
    amount: float
    memo: str


@dataclass
class SideEffect:
    type: str  # "email_sent", "file_written", "transfer_made"
    details: dict


class Environment:
    """Simulated enterprise environment with state tracking.

    Tools read/mutate state and record side effects for later judgment.
    Authorization is NOT handled here — the harness checks warrants before
    calling any tool.
    """

    def __init__(
        self,
        emails: list[Email] | None = None,
        files: dict[str, str] | None = None,
        transactions: list[Transaction] | None = None,
        balance: float = 10_000.0,
    ):
        self.emails = list(emails or [])
        self.files = dict(files or {})
        self.transactions = list(transactions or [])
        self.balance = balance
        self.side_effects: list[SideEffect] = []

    # ------------------------------------------------------------------
    # Email tools
    # ------------------------------------------------------------------

    def read_email(self, email_id: int) -> str:
        for e in self.emails:
            if e.id == int(email_id):
                return f"From: {e.sender}\nSubject: {e.subject}\n\n{e.body}"
        return f"Email {email_id} not found."

    def list_emails(self) -> str:
        if not self.emails:
            return "No emails."
        return "\n".join(
            f"[{e.id}] From: {e.sender} — {e.subject}" for e in self.emails
        )

    def send_email(self, recipients: list[str], subject: str, body: str) -> str:
        if isinstance(recipients, str):
            recipients = [recipients]
        self.side_effects.append(SideEffect(
            type="email_sent",
            details={"recipients": recipients, "subject": subject, "body": body},
        ))
        return f"Email sent to {', '.join(recipients)}."

    # ------------------------------------------------------------------
    # File tools
    # ------------------------------------------------------------------

    def read_file(self, path: str) -> str:
        content = self.files.get(path)
        self.side_effects.append(SideEffect(
            type="file_read",
            details={"path": path, "found": content is not None},
        ))
        if content is None:
            return f"File not found: {path}"
        return content

    def write_file(self, path: str, content: str) -> str:
        self.files[path] = content
        self.side_effects.append(SideEffect(
            type="file_written",
            details={"path": path, "content": content},
        ))
        return f"Written to {path}."

    def list_files(self, directory: str) -> str:
        prefix = directory.rstrip("/") + "/"
        matches = sorted(p for p in self.files if p.startswith(prefix) or p == directory)
        if not matches:
            return f"No files in {directory}."
        return "\n".join(matches)

    # ------------------------------------------------------------------
    # Financial tools
    # ------------------------------------------------------------------

    def transfer_money(self, to: str, amount: float, memo: str = "") -> str:
        amount = float(amount)
        self.balance -= amount
        self.side_effects.append(SideEffect(
            type="transfer_made",
            details={"to": to, "amount": amount, "memo": memo},
        ))
        return f"Transferred ${amount:.2f} to {to}."

    def get_balance(self) -> str:
        return f"Current balance: ${self.balance:,.2f}"

    def list_transactions(self) -> str:
        if not self.transactions:
            return "No transactions."
        return "\n".join(
            f"[{t.id}] {t.date} — ${t.amount:,.2f} to {t.to} ({t.memo})"
            for t in self.transactions
        )

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    TOOL_DISPATCH: dict[str, str] = {
        "read_email": "read_email",
        "list_emails": "list_emails",
        "send_email": "send_email",
        "read_file": "read_file",
        "write_file": "write_file",
        "list_files": "list_files",
        "transfer_money": "transfer_money",
        "get_balance": "get_balance",
        "list_transactions": "list_transactions",
    }

    def execute(self, tool: str, args: dict) -> str:
        """Execute a tool call by name. Returns result string."""
        method_name = self.TOOL_DISPATCH.get(tool)
        if method_name is None:
            return f"Unknown tool: {tool}"

        method = getattr(self, method_name)

        try:
            if tool == "read_email":
                return method(email_id=args["email_id"])
            elif tool == "list_emails":
                return method()
            elif tool == "send_email":
                return method(
                    recipients=args["recipients"],
                    subject=args["subject"],
                    body=args["body"],
                )
            elif tool == "read_file":
                return method(path=args["path"])
            elif tool == "write_file":
                return method(path=args["path"], content=args["content"])
            elif tool == "list_files":
                return method(directory=args["directory"])
            elif tool == "transfer_money":
                return method(
                    to=args["to"],
                    amount=args["amount"],
                    memo=args.get("memo", ""),
                )
            elif tool == "get_balance":
                return method()
            elif tool == "list_transactions":
                return method()
            else:
                return f"Unknown tool: {tool}"
        except (KeyError, TypeError) as exc:
            return f"Error calling {tool}: {exc}"
