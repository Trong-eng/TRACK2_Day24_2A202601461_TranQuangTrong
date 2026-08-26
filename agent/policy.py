"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc Guide.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input đúng slide §3.3 (đã định nghĩa sẵn, đừng đổi field):

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool


def check(context: PolicyContext) -> tuple[bool, str]:
    """Kiểm tra quyền thực thi dựa trên PolicyContext.
    
    Quy tắc tối thiểu bắt buộc:
    - classification == 'restricted' and egress_enabled is True -> DENY
    - Mọi quyết định (allow hay deny) đều phải có lý do (reason) không được rỗng.
    """
    # Rule 1: Chặn tuyệt đối việc truy cập hoặc truyền dữ liệu restricted ra ngoài mạng (egress)
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, "DENY: Truy cập dữ liệu restricted với quyền egress ra ngoài mạng bị nghiêm cấm theo chính sách bảo mật."

    # Rule 2: Cho phép đọc dữ liệu restricted khi chạy trong môi trường cô lập nội bộ (không egress)
    if context.data_classification == "restricted" and not context.egress_enabled:
        return True, f"ALLOW: Cho phép truy cập dữ liệu restricted cho mục đích nội bộ '{context.request_purpose}' của agent '{context.agent_owner}'."

    # Rule 3: Cho phép truy cập dữ liệu public và internal
    if context.data_classification in ("public", "internal"):
        return True, f"ALLOW: Cho phép truy cập dữ liệu {context.data_classification} cho mục đích '{context.request_purpose}'."

    # Fallback mặc định
    return False, f"DENY: Phân loại dữ liệu không xác định '{context.data_classification}'."
