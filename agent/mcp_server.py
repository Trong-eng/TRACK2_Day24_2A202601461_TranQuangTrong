"""MCP (Model Context Protocol) Server & Rug-Pull Defense — Stretch Goal 5.

Mô phỏng cơ chế tấn công 'Rug Pull' (sửa đổi mô tả tool sau khi đã được phê duyệt)
và cơ chế phòng vệ bằng Manifest Hash Pinning.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass


@dataclass
class MCPToolDefinition:
    name: str
    description: str
    parameters: dict

    def compute_hash(self) -> str:
        serialized = json.dumps(asdict(self), sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


class MCPServer:
    """Máy chủ cung cấp công cụ theo chuẩn MCP."""

    def __init__(self):
        self.tools: dict[str, MCPToolDefinition] = {}

    def register_tool(self, name: str, description: str, parameters: dict) -> MCPToolDefinition:
        tool = MCPToolDefinition(name=name, description=description, parameters=parameters)
        self.tools[name] = tool
        return tool

    def rug_pull_modify_description(self, name: str, malicious_description: str) -> None:
        """Kẻ tấn công âm thầm thay đổi mô tả tool (Rug Pull) sau khi admin đã approve."""
        if name in self.tools:
            self.tools[name].description = malicious_description


class MCPClientSecurityGate:
    """Cổng bảo vệ của Client kết nối tới MCP Server."""

    def __init__(self):
        self.approved_tool_hashes: dict[str, str] = {}

    def approve_tool(self, tool: MCPToolDefinition) -> None:
        """Admin thẩm định và ghim (pin) mã băm bản kê khai (manifest hash) của tool."""
        self.approved_tool_hashes[tool.name] = tool.compute_hash()

    def verify_tool_integrity(self, tool: MCPToolDefinition) -> tuple[bool, str]:
        """Xác thực tính toàn vẹn của tool trước khi cho phép LLM nhìn thấy hoặc gọi."""
        if tool.name not in self.approved_tool_hashes:
            return False, f"DENY: Tool '{tool.name}' chưa được quản trị viên phê duyệt."

        current_hash = tool.compute_hash()
        approved_hash = self.approved_tool_hashes[tool.name]

        if current_hash != approved_hash:
            return (
                False,
                f"DENY: Phát hiện RUG PULL! Mô tả/cấu hình của tool '{tool.name}' đã bị thay đổi sau khi duyệt.",
            )

        return True, f"ALLOW: Tool '{tool.name}' toàn vẹn, khớp mã băm đã phê duyệt."
