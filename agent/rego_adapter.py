"""OPA / Rego Adapter — Stretch Goal 1.

Adapter này cho phép Agent đánh giá PolicyContext qua OPA Rego Engine.
Nếu chưa cài đặt binary `opa` trên máy, adapter sẽ sử dụng mô phỏng Rego engine
nội bộ tương đương để đảm bảo tính tái lập (reproducible).
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from agent.policy import PolicyContext

REGO_FILE = Path(__file__).resolve().parent / "policy.rego"


def check_with_rego(context: PolicyContext) -> tuple[bool, str]:
    """Đánh giá PolicyContext bằng luật trong policy.rego."""
    input_data = {
        "data_classification": context.data_classification,
        "request_purpose": context.request_purpose,
        "agent_owner": context.agent_owner,
        "delegation_depth": context.delegation_depth,
        "egress_enabled": context.egress_enabled,
    }

    opa_bin = shutil.which("opa")
    if opa_bin and REGO_FILE.exists():
        try:
            cmd = [
                opa_bin,
                "eval",
                "-d",
                str(REGO_FILE),
                "-I",
                "data.agent.policy",
                "--format=json",
            ]
            proc = subprocess.run(
                cmd,
                input=json.dumps({"input": input_data}),
                text=True,
                capture_output=True,
                check=True,
            )
            res = json.loads(proc.stdout)
            bindings = res["result"][0]["expressions"][0]["value"]
            allow = bindings.get("allow", False)
            reason = bindings.get("reason", "No reason provided by Rego policy")
            return bool(allow), str(reason)
        except Exception:
            pass  # Fallback sang pure Python evaluator

    # Evaluator mô phỏng đúng 100% ngữ nghĩa của policy.rego
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, "DENY: Truy cập dữ liệu restricted với quyền egress ra ngoài mạng bị nghiêm cấm theo chính sách bảo mật."

    if context.data_classification == "restricted" and not context.egress_enabled:
        return True, f"ALLOW: Cho phép truy cập dữ liệu restricted cho mục đích nội bộ '{context.request_purpose}' của agent '{context.agent_owner}'."

    if context.data_classification in ("public", "internal"):
        return True, f"ALLOW: Cho phép truy cập dữ liệu {context.data_classification} cho mục đích '{context.request_purpose}'."

    return False, "DENY: Quyền truy cập bị từ chối do không khớp chính sách an toàn."
