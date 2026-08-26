# Báo cáo so sánh: Python Policy vs OPA / Rego (Stretch Goal 1)

## 1. Tổng quan hai cách tiếp cận

| Tiêu chí | Python Native (`agent/policy.py`) | OPA / Rego (`agent/policy.rego`) |
|---|---|---|
| **Ngôn ngữ** | Python thuần (Imperative) | Rego (Declarative Logic) |
| **Vị trí thực thi** | In-process (chạy cùng runtime Agent) | Sidecar / Standalone Daemon / In-process Engine |
| **Độ trễ (Latency)** | Cực nhanh (< 0.05ms) | Nhanh (~0.5 - 2ms nếu qua HTTP/Sidecar) |
| **Tách biệt vai trò (SoD)** | Developer viết code quản lý luôn policy | Chuyên gia An ninh mạng/Pháp chế tự quản lý file `.rego` độc lập |
| **Kiểm toán chính sách** | Phụ thuộc vào code review Python | Chuẩn hóa, hỗ trợ OPA Unit Test (`opa test`) độc lập |
| **Khả năng mở rộng** | Giới hạn trong ứng dụng Python | Dùng chung cho toàn bộ Microservices, Kubernetes, Envoy Gateway |

---

## 2. Ưu và nhược điểm

### Cách 1: Python Native Policy (`policy.py`)
- **Ưu điểm:** Không cần cài đặt thêm phần mềm phụ trợ, hiệu năng tối đa, dễ debug với lập trình viên Python.
- **Nhược điểm:** Dễ bị sửa lén trong mã nguồn ứng dụng; khó áp dụng chính sách đồng nhất nếu hệ thống có Agent viết bằng Go, Node.js hoặc Rust.

### Cách 2: OPA / Rego Policy (`policy.rego`)
- **Ưu điểm:** Chuẩn công nghiệp (CNCF Graduated Project), ngôn ngữ khai báo logic toán học rõ ràng, cho phép cập nhật luật nóng (Hot-reload policy) mà không cần restart lại Agent.
- **Nhược điểm:** Cần học cú pháp Rego và quản lý thêm binary/container OPA trong hạ tầng.

---

## 3. Kết luận
Với quy mô lab và ứng dụng Agent độc lập, **Python Native PEP** mang lại sự gọn nhẹ và tốc độ phản hồi tức thì. Tuy nhiên, khi đưa vào môi trường doanh nghiệp quy mô lớn (Enterprise AI Gateway), **OPA / Rego** là lựa chọn vượt trội để đảm bảo tính độc lập và tuân thủ các chuẩn an ninh ISO 27001 / ISO 42001.
