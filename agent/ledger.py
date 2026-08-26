"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng. Đọc Guide.md (§3d).

Interface bắt buộc (tests/test_ledger.py và agent/runner.py gọi trực tiếp):

    append(entry: dict, path: pathlib.Path) -> dict
        `entry` phải có tối thiểu các field:
            ts, agent_id, run_id, tool, args_hash, classification,
            decision, reason
        Hàm tự thêm 2 field:
            prev_hash  = hash của dòng ngay trước trong file này, hoặc
                         "0" * 64 nếu là dòng đầu tiên
            hash       = sha256 tính từ nội dung dòng NÀY (bao gồm cả
                         prev_hash, KHÔNG bao gồm field hash) — dùng
                         json.dumps(..., sort_keys=True) trước khi hash
                         để thứ tự field không ảnh hưởng kết quả.
        Append 1 dòng JSON (utf-8, ensure_ascii=False) vào cuối `path`,
        tạo file/thư mục cha nếu chưa có. Trả về dict đầy đủ đã ghi
        (bao gồm prev_hash/hash).

    verify(path: pathlib.Path) -> bool
        Đọc toàn bộ file, trả về True nếu TẤT CẢ đều đúng:
          - mọi dòng có `reason` non-empty
          - prev_hash của dòng n == hash đã lưu của dòng n-1 (dòng đầu so
            với "0" * 64)
          - hash lưu trong dòng n khớp lại khi tính lại từ nội dung dòng đó
        Trả về False nếu bất kỳ dòng nào bị sửa/xoá/chèn giữa file, hoặc
        thiếu reason.

Sinh viên phải tự tay chứng minh được: sửa 1 ký tự trong 1 dòng giữa file
rồi gọi verify() phải trả về False.
"""
from __future__ import annotations

from pathlib import Path


import hashlib
import json


def _compute_hash(entry_without_hash: dict) -> str:
    serialized = json.dumps(entry_without_hash, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def append(entry: dict, path: Path) -> dict:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    prev_hash = "0" * 64
    if path.exists() and path.stat().st_size > 0:
        lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if lines:
            try:
                last_line = json.loads(lines[-1])
                prev_hash = last_line.get("hash", "0" * 64)
            except Exception:
                prev_hash = "0" * 64

    entry_to_write = dict(entry)
    entry_to_write["prev_hash"] = prev_hash

    # Calculate sha256 hash without the 'hash' field
    entry_to_write["hash"] = _compute_hash(entry_to_write)

    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry_to_write, ensure_ascii=False) + "\n")

    return entry_to_write


def verify(path: Path) -> bool:
    path = Path(path)
    if not path.exists() or path.stat().st_size == 0:
        return True

    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    expected_prev = "0" * 64

    for line in lines:
        try:
            entry = json.loads(line)
        except Exception:
            return False

        # 1. Reason must be non-empty
        reason = entry.get("reason")
        if not reason or not isinstance(reason, str) or not reason.strip():
            return False

        # 2. prev_hash must match expected_prev
        if entry.get("prev_hash") != expected_prev:
            return False

        # 3. hash must match recomputed hash
        stored_hash = entry.get("hash")
        if not stored_hash:
            return False

        entry_copy = {k: v for k, v in entry.items() if k != "hash"}
        recalculated_hash = _compute_hash(entry_copy)
        if recalculated_hash != stored_hash:
            return False

        expected_prev = stored_hash

    return True
