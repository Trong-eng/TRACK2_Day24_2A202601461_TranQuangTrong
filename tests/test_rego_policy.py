"""Unit test cho OPA / Rego Adapter — Stretch Goal 1."""
from __future__ import annotations

from agent.policy import PolicyContext
from agent.rego_adapter import check_with_rego


def test_rego_restricted_with_egress_is_denied():
    ctx = PolicyContext(
        data_classification="restricted",
        request_purpose="reconciliation",
        agent_owner="run-b",
        delegation_depth=1,
        egress_enabled=True,
    )
    allow, reason = check_with_rego(ctx)
    assert allow is False
    assert "DENY" in reason
    assert reason, "reason không được để trống"


def test_rego_restricted_without_egress_is_allowed():
    ctx = PolicyContext(
        data_classification="restricted",
        request_purpose="support-reply",
        agent_owner="run-b",
        delegation_depth=1,
        egress_enabled=False,
    )
    allow, reason = check_with_rego(ctx)
    assert allow is True
    assert "ALLOW" in reason


def test_rego_public_and_internal_are_allowed():
    ctx_pub = PolicyContext(
        data_classification="public",
        request_purpose="faq",
        agent_owner="run-a",
        delegation_depth=0,
        egress_enabled=True,
    )
    allow_pub, _ = check_with_rego(ctx_pub)
    assert allow_pub is True

    ctx_int = PolicyContext(
        data_classification="internal",
        request_purpose="search_docs",
        agent_owner="run-a",
        delegation_depth=0,
        egress_enabled=False,
    )
    allow_int, _ = check_with_rego(ctx_int)
    assert allow_int is True
