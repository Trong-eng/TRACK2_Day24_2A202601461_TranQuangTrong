# Ba câu hỏi chốt buổi — Trả lời

---

## Câu 1: Bạn đã bỏ chân nào của trifecta, và agent mất đi khả năng gì?

**Trả lời:** Chúng ta không bỏ hoàn toàn chân nào — nhưng **cắt đứt mối liên kết giữa ba chân** bằng kiến trúc **Trifecta Split** trong `agent/runner.py`.

| Chân trifecta | Tool | Trạng thái sau contain |
|---|---|---|
| Untrusted content | `search_docs` | Vẫn giữ — Run A được phép đọc corpus |
| Private data | `read_customer` | Vẫn giữ — Run B được phép đọc customers.json |
| Exfil vector | `http_post` | Vẫn giữ kỹ thuật, nhưng bị chặn cứng bởi Policy khi có `egress_enabled=True` kèm dữ liệu `restricted` |

**Điều Agent mất đi (có chủ đích):** Khả năng tự phán xét "nên đọc dữ liệu của ai" từ free text của attacker.

Trước đây Agent đọc nguyên văn lệnh attacker và làm theo. Sau contain, Run B **mù hoàn toàn với free text** — nó chỉ nhận `ticket_id` chắt lọc từ tên file (`ticket-014.md → 14`) rồi tra ngược qua `related_tickets` trong `data/customers.json` (nguồn tin cậy nội bộ).

Dẫn chứng: `agent/runner.py:L93-L107` — vòng lặp `matched_ticket_ids` hoàn toàn không dùng `injected.customer_ids` mà attacker nhúng trong document.

---

## Câu 2: Nếu attacker có quyền ghi vào `corpus/`, control nào của bạn còn đứng vững?

**Trả lời:**

**❌ Control bị vô hiệu hóa:**
- **PII Gate (`agent/pii.py`):** Attacker kiểm soát toàn bộ nội dung tài liệu nên không còn PII thật để redact — nguy hiểm nằm ở lệnh injection, không phải PII.

**✅ Controls VẪN ĐỨNG VỮNG:**

1. **Trifecta Split (`agent/runner.py`):** Dù attacker viết bao nhiêu `KH-000999` vào corpus, Run B vẫn chỉ tra cứu qua `related_tickets` từ `data/customers.json` — file này attacker không thể sửa. Free text không bao giờ chỉ huy được Run B.

2. **Policy Enforcement Point (`agent/policy.py`):** Vẫn chặn mọi lệnh `http_post` mang dữ liệu `restricted` + `egress_enabled=True`, bất kể lệnh đến từ nguồn nào. `PolicyContext` được truyền theo code — attacker không thể giả mạo.

3. **Audit Ledger (`agent/ledger.py`):** Vẫn ghi nhận 100% mọi deny/allow với SHA-256 hash chain — không thể xóa dấu vết.

**Bài học:** Đây chính là lý do **Containment (kiến trúc)** quan trọng hơn **Mitigation (bộ lọc)**. Filter từ ngữ luôn bị né bằng cách viết lại (biến thể 5 đã chứng minh). Nếu Run B không đọc free text, kiểm soát corpus của attacker trở nên vô nghĩa về mặt exfiltration.

---

## Câu 3: Regulator hỏi "chứng minh dữ liệu khách hàng chưa từng ra khỏi hệ thống" — bạn mở file nào ra?

**Trả lời:** Mở 3 file theo thứ tự:

### 1. `reports/ledger.jsonl` — Bằng chứng chủ chốt

- Không có dòng nào: `"tool": "http_post"` + `"decision": "allow"` → không một lần dữ liệu được phép gửi ra ngoài.
- Có dòng deny chủ động: `"decision": "deny"`, `"reason": "DENY: Truy cập dữ liệu restricted..."` → hệ thống phát hiện và chặn tấn công.
- Chạy `ledger.verify()` → `True` → cuốn sổ **không bị sửa chữa hay làm giả** (SHA-256 hash chain nguyên vẹn).

### 2. `reports/attack-after.log` — Bằng chứng trực quan

File **hoàn toàn rỗng (0 bytes)** — không có ký tự CCCD, SĐT, STK hay tên khách hàng nào gửi đến sink server.

### 3. `reports/dpia-lite.md` §3 — Bản đồ luồng dữ liệu

Xác nhận không có luồng nào ra khỏi lãnh thổ, `http_post` bị kiểm soát 100% bởi PEP.

**Tóm lại:** `reports/ledger.jsonl` là tài liệu cốt lõi vì vừa chứng minh hành vi chặn tấn công, vừa là bằng chứng kiểm toán không thể làm giả.
