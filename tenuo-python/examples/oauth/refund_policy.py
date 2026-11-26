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
    def policy(caller, task_id):
        record = records.get((caller.tenant_id, task_id))
        if record is None:
            return None
        return REFUND_TEMPLATE.compile(caller, task_id, record)

    return policy
