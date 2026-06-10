from app.services import policy_check


def test_policy_engine_decisions_are_safe_by_default():
    deny = policy_check("delete_resource", persist=False)
    approval = policy_check("approve_model", persist=False)
    allow = policy_check("read_resource", persist=False)

    assert deny.decision == "deny"
    assert approval.decision == "require_approval"
    assert allow.decision == "allow"
