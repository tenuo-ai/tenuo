"""Approve the exact recipient and message, not merely a broad mail scope."""

from tenuo.oauth import ExactFrom, TaskTemplate

EMAIL_TEMPLATE = TaskTemplate(
    tool="send_email",
    arguments={
        name: ExactFrom(field)
        for name, field in {
            "operation_id": "task_id",
            "recipient": "recipient",
            "subject": "subject_line",
            "body": "body",
            "attachment": "attachment",
        }.items()
    },
    required_scopes=frozenset({"mail:send"}),
    ttl_seconds=120,
)


def policy_for(records):
    def policy(caller, task_id):
        record = records.get((caller.tenant_id, task_id))
        return None if record is None else EMAIL_TEMPLATE.compile(caller, task_id, record)

    return policy
