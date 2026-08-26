"""Agent Memory & Memory Poisoning Defense — Stretch Goal 4.

Module quản lý bộ nhớ dài hạn (Long-term Memory / Vector Store) của Agent,
kèm theo cổng kiểm soát an ninh (Memory Gate) chống tấn công đầu độc bộ nhớ
(Memory Poisoning Attack).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from agent import pii
from agent.llm import find_injection


@dataclass
class MemoryItem:
    id: str
    content: str
    source: str
    classification: str = "internal"
    is_poisoned: bool = False


class AgentMemoryStore:
    def __init__(self, storage_path: Path | None = None):
        self.storage_path = storage_path
        self.memories: dict[str, MemoryItem] = {}

    def add_memory(self, memory_id: str, content: str, source: str = "untrusted") -> MemoryItem:
        # Kiểm tra chỉ thị injection tiềm ẩn trong nội dung ghi nhớ
        injection = find_injection(content)
        is_poisoned = injection is not None

        item = MemoryItem(
            id=memory_id,
            content=content,
            source=source,
            classification="untrusted" if is_poisoned else "internal",
            is_poisoned=is_poisoned,
        )
        self.memories[memory_id] = item
        return item

    def retrieve_with_memory_gate(self, query: str) -> list[dict]:
        """Truy xuất bộ nhớ qua cổng phòng thủ Memory Gate.
        
        - Loại bỏ các mục bộ nhớ bị nhiễm độc (Poisoned memory).
        - Thực hiện Redact PII trước khi đưa vào context làm việc của Agent.
        """
        results = []
        terms = [t.lower() for t in query.split() if t]

        for item in self.memories.values():
            content_lower = item.content.lower()
            if not terms or any(t in content_lower for t in terms):
                # 1. Chặn bộ nhớ bị đầu độc (Poisoned Memory Filter)
                if item.is_poisoned or find_injection(item.content) is not None:
                    continue  # Bỏ qua không đưa vào context

                # 2. Làm sạch PII (Sanitization)
                sanitized_content = pii.redact(item.content)
                results.append({"id": item.id, "content": sanitized_content, "source": item.source})

        return results
