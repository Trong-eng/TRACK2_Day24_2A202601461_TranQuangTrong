package agent.policy

# Default: Không cho phép nếu không khớp bất kỳ rule nào
default allow = false
default reason = "DENY: Quyền truy cập bị từ chối do không khớp chính sách an toàn."

# Rule 1: Chặn tuyệt đối Restricted data khi có Egress ra ngoài mạng
deny {
    input.data_classification == "restricted"
    input.egress_enabled == true
}

reason = "DENY: Truy cập dữ liệu restricted với quyền egress ra ngoài mạng bị nghiêm cấm theo chính sách bảo mật." {
    input.data_classification == "restricted"
    input.egress_enabled == true
}

# Rule 2: Cho phép đọc Restricted data khi chạy nội bộ (không Egress)
allow {
    input.data_classification == "restricted"
    input.egress_enabled == false
}

reason = concat("", ["ALLOW: Cho phép truy cập dữ liệu restricted cho mục đích nội bộ '", input.request_purpose, "' của agent '", input.agent_owner, "'."]) {
    input.data_classification == "restricted"
    input.egress_enabled == false
}

# Rule 3: Cho phép dữ liệu Public
allow {
    input.data_classification == "public"
}

reason = concat("", ["ALLOW: Cho phép truy cập dữ liệu public cho mục đích '", input.request_purpose, "'."]) {
    input.data_classification == "public"
}

# Rule 4: Cho phép dữ liệu Internal
allow {
    input.data_classification == "internal"
}

reason = concat("", ["ALLOW: Cho phép truy cập dữ liệu internal cho mục đích '", input.request_purpose, "'."]) {
    input.data_classification == "internal"
}
