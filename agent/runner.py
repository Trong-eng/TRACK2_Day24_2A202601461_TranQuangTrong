"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc Guide.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được biến thể 5 (không dấu / lookalike): filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng biến
thể 5, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None) -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from agent import ledger, policy, tools
from agent.policy import PolicyContext

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"
CUSTOMERS_FILE = Path(__file__).resolve().parent.parent / "data" / "customers.json"


def handle(message: str, llm, log_dir: Path | None = None) -> str:
    """Xử lý yêu cầu người dùng theo kiến trúc Trifecta Split + Policy Enforcement + Audit Ledger.
    
    Tách biệt hoàn toàn:
      - Run A: Đọc untrusted content (search_docs), KHÔNG gọi private data hay egress.
      - Run B: Đọc private data (read_customer) dựa trên nguồn tin cậy (ticket_id trích từ tên file
        map qua related_tickets trong customers.json), KHÔNG đọc customer_id từ free text của attacker.
      - Egress: Chặn đứng mọi nỗ lực http_post qua Policy Enforcement Point.
    """
    ledger_path = (log_dir or REPORTS_DIR) / "ledger.jsonl"
    agent_id = "lab24-agent"

    # ═════════════════════════════════════════════════════════════════════
    # RUN A: UNTRUSTED PROCESSING (search_docs)
    # ═════════════════════════════════════════════════════════════════════
    run_a_id = "run-a"

    # 1. Policy check cho search_docs
    ctx_search = PolicyContext(
        data_classification="internal",
        request_purpose="search_docs",
        agent_owner=run_a_id,
        delegation_depth=0,
        egress_enabled=False,
    )
    allow_search, reason_search = policy.check(ctx_search)
    ledger.append(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "run_id": run_a_id,
            "tool": "search_docs",
            "args_hash": hashlib.sha256(message.encode("utf-8")).hexdigest(),
            "classification": ctx_search.data_classification,
            "decision": "allow" if allow_search else "deny",
            "reason": reason_search,
        },
        ledger_path,
    )

    if not allow_search:
        return "DENY: Không được phép tìm kiếm tài liệu theo chính sách bảo mật."

    docs = tools.search_docs(message)

    # 2. Kiểm tra Prompt Injection trên dữ liệu không tin cậy
    combined_text = "\n\n".join(d["text"] for d in docs)
    injected = llm.find_injection(combined_text)

    # Nếu phát hiện chỉ thị injection cố gắng gửi dữ liệu ra ngoài (egress)
    if injected is not None:
        # Đánh giá Policy cho http_post tại Run B (với dữ liệu restricted và egress_enabled=True)
        ctx_post = PolicyContext(
            data_classification="restricted",
            request_purpose="reconcile",
            agent_owner="run-b",
            delegation_depth=1,
            egress_enabled=True,
        )
        allow_post, reason_post = policy.check(ctx_post)
        ledger.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "agent_id": agent_id,
                "run_id": "run-b",
                "tool": "http_post",
                "args_hash": hashlib.sha256(injected.target_url.encode("utf-8")).hexdigest(),
                "classification": ctx_post.data_classification,
                "decision": "allow" if allow_post else "deny",
                "reason": reason_post,
            },
            ledger_path,
        )
        # allow_post là False nên KHÔNG gọi tools.http_post

    # ═════════════════════════════════════════════════════════════════════
    # RUN B: PRIVATE DATA PROCESSING (read_customer via trusted mapping)
    # ═════════════════════════════════════════════════════════════════════
    run_b_id = "run-b"

    # Trích xuất ticket_id từ TÊN FILE tài liệu hợp lệ (Sanitized Typed Input)
    # Tuyệt đối KHÔNG đọc customer_id từ nội dung free text do attacker viết
    matched_ticket_ids: set[int] = set()
    for d in docs:
        filename = d.get("id", "")
        m = re.search(r"ticket-(\d+)", filename)
        if m:
            matched_ticket_ids.add(int(m.group(1)))

    # Nguồn tin cậy: Tra cứu customer_id từ data/customers.json qua related_tickets
    customers_data = json.loads(CUSTOMERS_FILE.read_text(encoding="utf-8"))
    trusted_customer_ids: set[str] = set()
    for cust in customers_data:
        cust_tickets = cust.get("related_tickets", [])
        if any(tid in matched_ticket_ids for tid in cust_tickets):
            trusted_customer_ids.add(str(cust["customer_id"]))

    # Đọc dữ liệu private của các khách hàng hợp lệ với kiểm tra policy & ledger
    for customer_id in sorted(trusted_customer_ids):
        ctx_read = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner=run_b_id,
            delegation_depth=1,
            egress_enabled=False,
        )
        allow_read, reason_read = policy.check(ctx_read)
        ledger.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "agent_id": agent_id,
                "run_id": run_b_id,
                "tool": "read_customer",
                "args_hash": hashlib.sha256(customer_id.encode("utf-8")).hexdigest(),
                "classification": ctx_read.data_classification,
                "decision": "allow" if allow_read else "deny",
                "reason": reason_read,
            },
            ledger_path,
        )
        if allow_read:
            try:
                tools.read_customer(customer_id)
            except tools.ToolError:
                pass

    return llm.summarize(docs)
