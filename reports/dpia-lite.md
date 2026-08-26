# DPIA-lite (Đánh giá tác động quyền riêng tư dữ liệu)

## 1. Dữ liệu gì (Data Inventory & Classification)

Hệ thống Agent tương tác với hai nguồn dữ liệu chính được phân loại theo cấp độ bảo mật:

- **Công cụ `search_docs(query)` — Phân loại `internal` / `untrusted`:**
  - Nguồn: Thư mục `corpus/` chứa các tệp Markdown ghi nhận phản hồi, khiếu nại của khách hàng.
  - Loại dữ liệu: Tiêu đề ticket, mô tả sự cố, các trường thông tin tự do do khách hàng hoặc đối tác nhập vào.
  - Rủi ro: Có thể chứa mã độc Prompt Injection cố tình cài cắm để đánh cắp dữ liệu hoặc thay đổi luồng thực thi.

- **Công cụ `read_customer(customer_id)` — Phân loại `restricted` (Tuyệt mật):**
  - Nguồn: Cơ sở dữ liệu khách hàng `data/customers.json`.
  - Loại dữ liệu cá nhân nhạy cảm (PII):
    - **Họ và tên (`name`)**: Nhận diện danh tính chủ thể dữ liệu.
    - **Căn cước công dân (`cccd`)**: 12 chữ số định danh duy nhất theo quy định pháp luật Việt Nam.
    - **Số điện thoại (`phone`)**: Thông tin liên lạc trực tiếp.
    - **Số tài khoản ngân hàng (`bank_account`)**: Dữ liệu tài chính phục vụ đối soát giao dịch.
    - **Địa chỉ email (`email`)**: Thông tin liên lạc điện tử.
    - **Danh sách liên kết (`related_tickets`)**: Danh mục ticket thuộc quyền sở hữu hợp pháp của khách hàng.

---

## 2. Mục đích gì (Purpose & Data Minimization)

- **Mục đích xử lý:**
  - Tự động hóa quá trình tra cứu, tổng hợp các yêu cầu hỗ trợ và đối soát giao dịch nhằm giải đáp thắc mắc của khách hàng kịp thời.
  - Phân luồng công việc hỗ trợ khách hàng theo đúng thẩm quyền nghiệp vụ (`request_purpose: "support-reply"` / `"reconciliation"`).

- **Tuân thủ nguyên tắc tối thiểu hóa dữ liệu (Data Minimization):**
  - Áp dụng kiến trúc **Trifecta Split**: Chỉ truy cập hồ sơ khách hàng (`read_customer`) khi ticket có liên kết xác thực trong `related_tickets` của khách hàng đó.
  - Tuyệt đối không truy cập hoặc tải dữ liệu của khách hàng dựa trên định danh trích xuất từ văn bản tự do chưa qua xác thực của người dùng/kẻ tấn công.

---

## 3. Chảy đi đâu (Data Flow & Cross-border Transfer Analysis)

Luồng luân chuyển dữ liệu của hệ thống được giám sát và kiểm soát chặt chẽ qua 3 kênh:

1. **Nhật ký kiểm toán nội bộ (`reports/ledger.jsonl`):**
   - Lưu trữ metadata kiểm toán dưới dạng Append-Only Hash-Chain (chuỗi băm SHA-256 chống sửa đổi/chối bỏ).
   - Tham số gọi tool nhạy cảm được băm thành `args_hash` (không lưu trữ PII thô ở dạng plain text trong log công khai).

2. **Kênh kết nối mạng ngoại vi / Exfiltration Sink (`http_post`):**
   - Được kiểm soát 100% bởi chốt chặn chính sách (**Policy Enforcement Point - PEP** tại `agent/policy.py`).
   - Quy tắc cứng: Dữ liệu `restricted` đi kèm cờ `egress_enabled=True` lập tức bị **DENY** và ghi nhận cảnh báo vi phạm vào ledger.

3. **Chuyển dữ liệu xuyên biên giới theo Nghị định 356/2025/NĐ-CP (Cross-border Data Transfer):**
   - **Chế độ mặc định (`--mock`):** Hoạt động hoàn toàn trên môi trường on-premise/local, không phát sinh luồng dữ liệu truyền ra ngoài lãnh thổ Việt Nam.
   - **Khi sử dụng LLM Cloud Provider (`--model claude-...`):** Việc gửi prompt chứa dữ liệu sang máy chủ nước ngoài (Anthropic/OpenAI) được xác định là hành vi chuyển dữ liệu cá nhân ra nước ngoài theo NĐ 356/2025.
   - **Biện pháp kỹ thuật bắt buộc:**
     - Kích hoạt cổng kiểm soát PII (`agent/pii.py`) để thực hiện **Redaction (che giấu)** toàn bộ CCCD, SĐT, STK, Email trước khi gửi dữ liệu vào context của mô hình bên thứ ba.
     - Duy trì nhật ký lưu vết luồng dữ liệu (Data-flow Inventory) tối thiểu 60 ngày để sẵn sàng phục vụ thanh tra, kiểm tra theo quy định pháp luật.
