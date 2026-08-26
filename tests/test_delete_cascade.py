"""Unit test cho Delete Cascade & Quyền yêu cầu xoá (Luật 91/2025) — Stretch Goal 3."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from agent import ledger, tools


def test_delete_cascade_removes_subject_and_preserves_ledger_integrity(tmp_path):
    # 1. Tạo bản sao tạm của customers.json
    original_customers = Path(__file__).resolve().parent.parent / "data" / "customers.json"
    tmp_customers = tmp_path / "customers.json"
    tmp_customers.write_text(original_customers.read_text(encoding="utf-8"), encoding="utf-8")

    # 2. Tạo ledger tạm và ghi nhận một số lượt gọi tool trước đó
    tmp_ledger = tmp_path / "ledger.jsonl"
    target_id = "KH-000001"

    entry1 = {
        "ts": "2026-08-26T00:00:00Z",
        "agent_id": "lab24-agent",
        "run_id": "run-b",
        "tool": "read_customer",
        "args_hash": hashlib.sha256(target_id.encode("utf-8")).hexdigest(),
        "classification": "restricted",
        "decision": "allow",
        "reason": "ALLOW: Phục vụ khách hàng hợp lệ",
    }
    ledger.append(entry1, tmp_ledger)

    # Đảm bảo trước khi xoá, khách hàng tồn tại và ledger hợp lệ
    rec = tools.read_customer(target_id, customers_file=tmp_customers)
    assert rec["customer_id"] == target_id
    assert ledger.verify(tmp_ledger) is True

    # 3. Thực hiện Xóa chủ thể dữ liệu (Delete cascade theo Luật 91/2025)
    success = tools.delete_customer(target_id, customers_file=tmp_customers)
    assert success is True

    # 4. Kiểm tra: Khách hàng không còn tồn tại trong kho dữ liệu
    with pytest.raises(tools.ToolError, match=f"unknown customer_id: {target_id}"):
        tools.read_customer(target_id, customers_file=tmp_customers)

    # 5. Kiểm tra tính toàn vẹn của Ledger (Tamper-evident Audit Chain):
    #    Ledger VẪN PHẢI HỢP LỆ vì chỉ lưu trữ args_hash (mã băm), không lưu PII thô
    assert ledger.verify(tmp_ledger) is True, (
        "Ledger bị hỏng sau khi xoá dữ liệu cá nhân — vi phạm nguyên tắc lưu vết kiểm toán bất biến!"
    )
