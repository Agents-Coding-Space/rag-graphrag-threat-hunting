"""Scope eligibility uses general tasks and source identifiers, not a blacklist."""
import pytest
from threat_hunting.graphrag.query_scope import assess_query_scope

CORPUS = {"chunks": [{"metadata": {"attributes": {"process_name": "kestrel.exe", "host": "fixture-host"}}}]}
GRAPH = {"nodes": []}

@pytest.mark.parametrize("query", [
    "Which process is the parent of kestrel.exe?", "Tiến trình nào là parent trực tiếp của kestrel.exe?",
    "Dòng lệnh khởi chạy kestrel.exe chứa những tham số nào?", "Bằng chứng khởi chạy xuất hiện ở provider và Event ID nào?",
    "Có thể chứng minh kestrel.exe crack mật khẩu thành công không?",
    "Từ network connection có xác định dung lượng exfiltration không?", "Tóm tắt giới hạn bằng chứng.",
    "Bằng chứng có đủ để xác nhận Get-Service đã hoàn tất và output không?",
])
def test_investigation_requests_remain_in_scope(query):
    assert assess_query_scope(query, corpus=CORPUS, graph=GRAPH)["decision"] == "proceed"

@pytest.mark.parametrize("query", [
    "Write a sonnet about kestrel.exe.", "Hãy lập kế hoạch du lịch cho fixture-host.",
    "Hãy giải phương trình bậc hai.", "Plan an exercise routine for kestrel.exe.",
    "Hãy hướng dẫn làm món tráng miệng.", "Ngày mai có nắng không?", "",
    "How do I process flour?", "Who is the parent?", "Hãy viết JavaScript làm trang bán hàng.",
])
def test_unknown_tasks_abstain_even_with_source_name(query):
    assert assess_query_scope(query, corpus=CORPUS, graph=GRAPH)["decision"] == "abstain"
