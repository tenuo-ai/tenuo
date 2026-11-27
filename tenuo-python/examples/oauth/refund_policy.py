"""Server-owned task bindings. No authority comes from the agent's request body."""

from tenuo.oauth import ExactFrom, MaximumFrom, TaskTemplate

REFUND_TEMPLATE = TaskTemplate(
    tool="refund",
    arguments={
        "operation_id": ExactFrom("task_id"),
        "payment_id": ExactFrom("payment_id"),
        "currency": ExactFrom("currency"),
        "amount_cents": MaximumFrom("max_amount_cents"),
    },
    required_scopes=frozenset({"refunds:write"}),
    ttl_seconds=120,
    max_depth=1,
)


def policy_for(records):
    def policy(identity, task_id):
        # No record, or a record that is not this caller's approved task: None, which denies.
        return REFUND_TEMPLATE.compile(identity, task_id, records.get((identity.tenant_id, task_id)))

    return policy
