# Compliance mapping

Điền evidence là **đường dẫn file/dòng thật** trong repo của bạn — không
phải mô tả chung. Xem `Guide.md` Bước 4 và `Rubric.md`.

| Requirement | Control | Evidence |
|---|---|---|
| Luật 91/2025 — quyền yêu cầu xoá | Quyền yêu cầu xoá dữ liệu cá nhân (Right to erasure / Delete cascade) | chưa implement, xem stretch #4 |
| NĐ 356/2025 — hồ sơ xuyên biên giới 60 ngày | Data-flow inventory cho LLM API call & đánh giá chuyển dữ liệu ra nước ngoài | `reports/dpia-lite.md` §3 |
| ASI03 — privilege abuse | Per-agent identity + Context-based Access Control + Audit Trail | `agent/policy.py:L31-L37`, `agent/ledger.py:L14-L44` (fields `agent_owner`, `run_id`, `ts`) |
| ASI01 — goal hijack | Trifecta split (cô lập Run A untrusted và Run B private data, trusted mapping) | `agent/runner.py:L63-L144`, `reports/attack-after.log` |
| ISO 42001 Clause 5-6 | Policy-as-code có review, version control và kiểm thử tự động | git log của `agent/policy.py` (commit `dfb18a3a7ab46c3a018f30377c1e4bbe0c09c7e9`), `agent/policy.py:L39-L59` |
