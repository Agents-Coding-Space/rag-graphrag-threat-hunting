"""Prompt construction with strict grounding rules for threat hunting."""

from __future__ import annotations

import json
from typing import Any

from .schema import ThreatHuntingReport


SYSTEM_PROMPT = """Bạn là Senior SOC Threat Hunting Analyst hoạt động trong trung tâm giám sát an ninh mạng.
Nhiệm vụ của bạn là phân tích dữ liệu sự kiện an toàn thông tin dựa TRÊN DUY NHẤT VÀ TUỆT ĐỐI CÁC BẰNG CHỨNG (CONTEXT) ĐƯỢC CUNG CẤP.

[NGUYÊN TẮC BẰNG CHỨNG - BẮT BUỘC TUÂN THỦ 100%]
1. NGUYÊN TẮC ZERO-ASSUMPTION (CHỈ KẾT LUẬN KHI CÓ BẰNG CHỨNG):
   - Mọi thực thể (Process, IP, User, File) và hành vi tấn công được nêu trong báo cáo BẮT BUỘC phải trích xuất trực tiếp từ [CONTEXT PHÁP Y] được cung cấp.
   - TUYỆT ĐỐI CẤM suy đoán những gì log không ghi nhận. Ví dụ: Nếu log chỉ ghi nhận lệnh khởi tạo process, CẤM TUYỆT ĐỐI kết luận rằng payload bên trong tiến trình con đã chạy thành công hoặc dịch vụ đã bị vô hiệu hóa, trừ khi có log ghi nhận tương ứng.
2. TRÍCH DẪN MÃ BẰNG CHỨNG (EVIDENCE CITATION):
   - Mỗi bước trong `attack_chain` bắt buộc phải kèm theo trường `evidence_ref` chính xác (ví dụ ID bản ghi log, evidence ID hoặc pointer).
   - Liệt kê toàn bộ các mã tham chiếu đã sử dụng vào danh sách `evidence_refs`.
3. KHI THIẾU BẰNG CHỨNG (INSUFFICIENT EVIDENCE):
   - Nếu câu hỏi yêu cầu phân tích một khía cạnh mà Context không đủ dữ liệu, bạn BẮT BUỘC phải ghi nhận điểm đó vào trường `unverified_claims` và đặt `verdict` là "INSUFFICIENT_EVIDENCE".
4. ĐỊNH DẠNG ĐẦU RA:
   - Chỉ xuất ra định dạng JSON thuần khớp 100% với Schema quy định. Không thêm lời chào, không bao bọc bởi văn phong giải thích ngoài khối JSON."""


def format_context_for_prompt(context: dict[str, Any]) -> str:
    """Format GraphRAG context (retrieval hits + graph traversal) into clean prompt sections."""
    lines = ["=== CONTEXT PHÁP Y & TRI THỨC AN TOÀN THÔNG TIN ==="]

    # 1. Retrieval Hits
    hits = context.get("retrieval", {}).get("hits", [])
    if hits:
        lines.append(f"\n[CÁC ĐOẠN TRI THỨC TRUY XUẤT (RETRIEVAL CHUNKS: {len(hits)})]")
        for idx, hit in enumerate(hits, start=1):
            chunk = hit.get("chunk", {})
            chunk_type = chunk.get("chunk_type", "unknown")
            content = chunk.get("content", "")
            source = chunk.get("source", {})
            source_ptr = source.get("json_pointer", "")
            lines.append(f"- Chunk #{idx} [{chunk_type}] (Source: {source_ptr}):")
            lines.append(f"  {content}")

    # 2. Graph Traversal Elements
    traversal = context.get("traversal", {})
    nodes = traversal.get("nodes", [])
    edges = traversal.get("edges", [])
    if nodes or edges:
        lines.append(f"\n[ĐỒ THỊ QUAN HỆ THỰC THỂ (GRAPH TRAVERSAL: {len(nodes)} nodes, {len(edges)} edges)]")
        for node in nodes:
            node_id = node.get("node_id", "")
            node_type = node.get("node_type", "")
            label = node.get("label", "")
            status = node.get("status", "")
            lines.append(f"  * Node ({node_type}) ID: {node_id} | Label: {label} | Status: {status}")

        for edge in edges:
            src = edge.get("source", "")
            tgt = edge.get("target", "")
            edge_type = edge.get("edge_type", "")
            lines.append(f"  * Edge: {src} --[{edge_type}]--> {tgt}")

    return "\n".join(lines)


class ThreatHuntingPromptBuilder:
    """Builds grounded prompt messages for threat hunting LLM queries."""

    def __init__(self, system_prompt: str | None = None) -> None:
        self.system_prompt = system_prompt or SYSTEM_PROMPT

    def build_user_prompt(self, query: str, context: dict[str, Any]) -> str:
        """Construct user turn message containing query, forensic context, and output JSON instructions."""
        formatted_context = format_context_for_prompt(context)
        schema_sample = json.dumps(
            {
                "schema_version": "threat-hunting-report/v1",
                "verdict": "MALICIOUS",
                "executive_summary": "Tóm tắt ngắn gọn",
                "technical_analysis": "Phân tích chi tiết",
                "attack_chain": [
                    {
                        "step_number": 1,
                        "source_entity": "cmd.exe",
                        "action": "spawned_process",
                        "target_entity": "mshta.exe",
                        "evidence_ref": "evidence-b07a5ff4763e629715e6",
                        "timestamp": "2020-10-22T02:57:59.856000Z",
                    }
                ],
                "mitre_mappings": [
                    {
                        "technique_id": "T1218.005",
                        "technique_name": "Mshta",
                        "confidence": "supported_by_observed_behavior",
                        "rationale": "Lý giải dựa trên log",
                    }
                ],
                "sigma_matches": ["rule_id_1"],
                "containment_recommendations": ["Hành động 1"],
                "unverified_claims": ["Điểm nghi vấn"],
                "evidence_refs": ["evidence-b07a5ff4763e629715e6"],
            },
            ensure_ascii=False,
            indent=2,
        )

        user_content = f"""CÂU HỎI TRUY TÌM MỐI ĐE DỌA (THREAT HUNTING QUERY):
"{query}"

{formatted_context}

HÃY PHÂN TÍCH VÀ XUẤT RA BÁO CÁO DUY NHẤT Ở ĐỊNH DẠNG JSON KHỚP CẤU TRÚC SAU:
{schema_sample}
"""
        return user_content

    def build_messages(self, query: str, context: dict[str, Any]) -> list[dict[str, str]]:
        """Return complete messages list ready for LLMClient."""
        return [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": self.build_user_prompt(query, context)},
        ]
