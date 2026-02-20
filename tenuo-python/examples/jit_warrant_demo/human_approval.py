"""
Human Approval with Cryptographic Signature.

This module implements multi-signature (multi-sig) human approval for warrants.
The flow requires both a System (Control Plane) and a Human to cryptographically
approve before a warrant can be used.

The Tenuo multi-sig feature works as follows:
1. Warrants can be created with required_approvers (list of public keys)
2. When authorizing, Approval objects must be provided
3. Each Approval is cryptographically signed and bound to the specific request
4. The Authorizer verifies all required approvals before allowing the action

Pattern demonstrated:
1. System (Control Plane) validates against policy and creates an Approval
2. Human reviews the proposal and creates their own Approval
3. Both Approvals are passed to Authorizer.authorize()
4. Tenuo cryptographically verifies all signatures
"""

from typing import List, Dict, Any, Optional
from tenuo import SigningKey, PublicKey, SignedApproval, Warrant
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
        warrant: Warrant,
        tool: str,
        args: Dict[str, Any],
        task: str,
        proposed_capabilities: List[Dict[str, Any]],
        allowed_urls: List[str],
        interactive: bool = True,
    ) -> Optional[SignedApproval]:
        """
        Review a capability proposal and create a cryptographic SignedApproval.

        Args:
            warrant: The warrant being approved
            tool: The tool being approved for use
            args: The arguments for the tool call
            task: The original user task
            proposed_capabilities: Capabilities the LLM wants
            allowed_urls: URLs extracted from the task
            interactive: Whether to prompt for approval

        Returns:
            Tenuo Approval object if approved, None if rejected
        """
        display.print_human_approval_request(self.name, task, proposed_capabilities, allowed_urls)

        if interactive:
            # In a real system, this would be a secure approval flow
            # (e.g., mobile push notification, hardware token)
            approved = Confirm.ask(
                f"[bold yellow]{self.name}[/bold yellow]: Do you approve this warrant?", default=True
            )
        else:
            # Auto-approve for non-interactive demo
            display.console.print(f"[dim]{self.name} auto-approving for demo...[/dim]")
            approved = True

        if not approved:
            display.print_human_rejection(self.name)
            return None

        # Create a real Tenuo Approval object
        approval = SignedApproval.create(
            warrant=warrant,
            tool=tool,
            args=args,
            keypair=self.signing_key,
            external_id=f"{self.name.lower().replace(' ', '_')}@company.com",
            provider="human-review",
            ttl_secs=300,
            reason=f"Approved for task: {task[:50]}...",
        )

        display.print_human_approval_signed(self.name, self.public_key)

        return approval


class MultiSigApprovalFlow:
    """
    Orchestrates multi-signature approval for warrants.

    Requires both:
    1. System (Control Plane) approval
    2. Human approval

    Both must create cryptographic Approval objects that are passed to
    Authorizer.authorize() along with the warrant.
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
        task: str,
        proposed_capabilities: List[Dict[str, Any]],
        allowed_urls: List[str],
        interactive: bool = True,
    ) -> Optional[List[SignedApproval]]:
        """
        Execute the full approval flow.

        Args:
            warrant: The warrant to approve
            tool: Tool name for the first action
            args: Arguments for the first tool call
            task: The original user task
            proposed_capabilities: Capabilities being approved
            allowed_urls: URLs extracted from task
            interactive: Whether to prompt for human approval

        Returns:
            List of Approval objects if both approve, None if rejected.
            These approvals should be passed to Authorizer.authorize().
        """
        display.print_step(
            4, "Multi-Sig Approval Flow", "Both system AND human must approve for the warrant to be valid."
        )

        approvals = []

        # Step 1: System approval (policy check)
        display.print_system_approval(self.system_key.public_key)

        system_approval = SignedApproval.create(
            warrant=warrant,
            tool=tool,
            args=args,
            keypair=self.system_key,
            external_id="control_plane@system",
            provider="policy-engine",
            ttl_secs=300,
            reason="Policy check passed",
        )
        approvals.append(system_approval)

        # Step 2: Human approval
        human_approval = self.human_approver.review_and_approve(
            warrant=warrant,
            tool=tool,
            args=args,
            task=task,
            proposed_capabilities=proposed_capabilities,
            allowed_urls=allowed_urls,
            interactive=interactive,
        )

        if human_approval is None:
            return None

        approvals.append(human_approval)

        display.print_approval_complete()
        return approvals
