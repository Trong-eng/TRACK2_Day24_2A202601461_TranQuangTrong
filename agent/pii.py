"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc Guide.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations


import re

# Email regex: standard email format
_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b")

# Bank account: 8-16 digits preceded by STK / số tài khoản / tai khoan
_BANK_ACCOUNT_RE = re.compile(
    r"(?<=\bSTK\s)(\d{8,16})\b|(?<=\bsố tài khoản\s)(\d{8,16})\b|(?<=\bso tai khoan\s)(\d{8,16})\b",
    re.IGNORECASE,
)

# CCCD: 12 digits
_CCCD_RE = re.compile(r"\b(\d{12})\b")

# VN Phone: 10 digits starting with 0
_PHONE_RE = re.compile(r"\b(0\d{9})\b")


def detect(text: str) -> list[dict]:
    entities: list[dict] = []

    # 1. Email detection
    for m in _EMAIL_RE.finditer(text):
        entities.append({"type": "EMAIL", "start": m.start(), "end": m.end()})

    # 2. Bank account detection (8-16 digits preceded by STK indicator)
    for m in _BANK_ACCOUNT_RE.finditer(text):
        start = m.start(1) if m.group(1) else (m.start(2) if m.group(2) else m.start(3))
        end = m.end(1) if m.group(1) else (m.end(2) if m.group(2) else m.end(3))
        entities.append({"type": "VN_BANK_ACCOUNT", "start": start, "end": end})

    bank_spans = {(e["start"], e["end"]) for e in entities if e["type"] == "VN_BANK_ACCOUNT"}

    # 3. CCCD (12 digits, exclude spans already identified as bank account)
    for m in _CCCD_RE.finditer(text):
        if (m.start(), m.end()) not in bank_spans:
            entities.append({"type": "VN_CCCD", "start": m.start(), "end": m.end()})

    # 4. VN Phone (10 digits starting with 0, ensure no overlap with CCCD or bank account)
    for m in _PHONE_RE.finditer(text):
        overlap = False
        for e in entities:
            if e["start"] <= m.start() and m.end() <= e["end"]:
                overlap = True
                break
        if not overlap:
            entities.append({"type": "VN_PHONE", "start": m.start(), "end": m.end()})

    entities.sort(key=lambda x: x["start"])
    return entities


def redact(text: str) -> str:
    entities = detect(text)
    if not entities:
        return text

    # Sort in reverse order of start offset to prevent index shifts
    entities_sorted = sorted(entities, key=lambda x: x["start"], reverse=True)
    result = text
    for e in entities_sorted:
        tag = f"[REDACTED_{e['type']}]"
        result = result[: e["start"]] + tag + result[e["end"] :]
    return result
