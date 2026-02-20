"""
Human Approval with Cryptographic Signature.

This module implements multi-signature (multi-sig) human approval for warrants.
The flow requires both a System (Control Plane) and a Human to cryptographically
approve before a warrant can be used.

The Tenuo approval envelope pattern:
1. Compute a request_hash binding (warrant_id, tool, args, holder) via SHA-256
2. Create an ApprovalPayload with the hash, nonce, timestamps
3. Sign with the approver's key -> SignedApproval
4. The Rust core verifies: signature, hash, expiration, approver trust, m-of-n

Pattern demonstrated:
1. System (Control Plane) validates against policy and creates a SignedApproval
2. Human reviews the proposal and creates their own SignedApproval
3. Both are passed to the enforcement layer
4. Rust core verifies all signatures and checks the 2-of-2 threshold
"""

from typing import List, Dict, Any, Optional
from tenuo import SigningKey, PublicKey, SignedApproval, Warrant
from tenuo.approval import ApprovalRequest, sign_approval
from tenuo import compute_request_hash
import display
from rich.prompt import Confirm


class HumanApprover:
    """
    Represents a human approver with their own keypair.

    In production, this would be:
    - A hardware security module (HSM)
    - A mobile app with biometric auth
    - A secure key stored in a password manager
    """

    def __init__(self, name: str = "Security Reviewer"):
        self.name = name
        self.signing_key = SigningKey.generate()

    @property
    def public_key(self) -> PublicKey:
        return self.signing_key.public_key

    def review_and_approve(
        self,
        request: ApprovalRequest,
        task: str,
        proposed_capabilities: List[Dict[str, Any]],
        allowed_urls: List[str],
        interactive: bool = True,
        ttl_seconds: Optional[int] = None,
    ) -> Optional[SignedApproval]:
        """
        Review a capability proposal and create a cryptographic SignedApproval.

        Args:
            request: The ApprovalRequest with request_hash and context.
            task: The original user task (for display).
            proposed_capabilities: Capabilities the LLM wants (for display).
            allowed_urls: URLs extracted from the task (for display).
            interactive: Whether to prompt for approval.
            ttl_seconds: Override TTL for the approval. None uses
                request.suggested_ttl or 300s default.

        Returns:
            SignedApproval if approved, None if rejected.
        """
        display.print_human_approval_request(self.name, task, proposed_capabilities, allowed_urls)

        if interactive:
            approved = Confirm.ask(
                f"[bold yellow]{self.name}[/bold yellow]: Do you approve this warrant?", default=True
            )
        else:
            display.console.print(f"[dim]{self.name} auto-approving for demo...[/dim]")
            approved = True

        if not approved:
            display.print_human_rejection(self.name)
            return None

        approval = sign_approval(
            request,
            self.signing_key,
            external_id=f"{self.name.lower().replace(' ', '_')}@company.com",
            ttl_seconds=ttl_seconds,
        )

        display.print_human_approval_signed(self.name, self.public_key)

        return approval


class MultiSigApprovalFlow:
    """
    Orchestrates multi-signature approval for warrants.

    Requires both:
    1. System (Control Plane) approval
    2. Human approval

    Both must create cryptographic SignedApproval objects. The Rust core
    verifies the m-of-n threshold (2-of-2 in this case) along with
    signature validity, hash binding, and expiration.
    """

    def __init__(
        self,
        system_key: SigningKey,
        human_approver: HumanApprover,
    ):
        self.system_key = system_key
        self.human_approver = human_approver

    def get_required_approvers(self) -> List[PublicKey]:
        """Get the list of required approver public keys."""
        return [
            self.system_key.public_key,
            self.human_approver.public_key,
        ]

    def execute_approval_flow(
        self,
        warrant: Warrant,
        tool: str,
        args: Dict[str, Any],
        holder_key: PublicKey,
        task: str,
        proposed_capabilities: List[Dict[str, Any]],
        allowed_urls: List[str],
        interactive: bool = True,
        ttl_seconds: Optional[int] = None,
    ) -> Optional[List[SignedApproval]]:
        """
        Execute the full 2-of-2 approval flow.

        Args:
            warrant: The warrant to approve.
            tool: Tool name for the action being approved.
            args: Arguments for the tool call.
            holder_key: The warrant holder's public key (for hash binding).
            task: The original user task.
            proposed_capabilities: Capabilities being approved.
            allowed_urls: URLs extracted from task.
            interactive: Whether to prompt for human approval.
            ttl_seconds: TTL for the signed approvals.

        Returns:
            List of SignedApproval objects if both approve, None if rejected.
            Pass these to enforce_tool_call(approvals=...).
        """
        display.print_step(
            4, "Multi-Sig Approval Flow", "Both system AND human must approve for the warrant to be valid."
        )

        # Compute the request hash that binds both approvals to this exact call
        request_hash = compute_request_hash(
            warrant.id, tool, args, holder_key,
        )

        request = ApprovalRequest(
            tool=tool,
            arguments=args,
            warrant_id=warrant.id,
            request_hash=request_hash,
            suggested_ttl=ttl_seconds,
        )

        approvals = []

        # Step 1: System approval (policy check)
        display.print_system_approval(self.system_key.public_key)

        system_approval = sign_approval(
            request,
            self.system_key,
            external_id="control_plane@system",
            ttl_seconds=ttl_seconds,
        )
        approvals.append(system_approval)

        # Step 2: Human approval
        human_approval = self.human_approver.review_and_approve(
            request=request,
            task=task,
            proposed_capabilities=proposed_capabilities,
            allowed_urls=allowed_urls,
            interactive=interactive,
            ttl_seconds=ttl_seconds,
        )

        if human_approval is None:
            return None

        approvals.append(human_approval)

        display.print_approval_complete()
        return approvals
