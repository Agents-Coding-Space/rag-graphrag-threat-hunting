"""Small review-join fixture; labels are evaluation-only and inputs stay read-only."""
import csv
import hashlib
import json

from scripts import audit_rag_gate_contract as audit


def test_review_join_preserves_context_and_keeps_rubric_separate(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "ROOT", tmp_path)
    old, new = tmp_path / "before", tmp_path / "after"
    old.mkdir()
    new.mkdir()
    def put(path, value): path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
    case = {"case_id": "A1", "category": "answerable", "request": {"query": "Câu hỏi fixture"}, "required_facts_or_limits": ["Giữ nguyên tiêu chí"]}
    put(old / "cases.json", {"cases": [case]})
    old_rows, new_rows = [], []
    context = {"retrieval": {"hits": [{"chunk": {"chunk_id": "source-one", "chunk_type": "fact", "source": {"json_pointer": "/facts/0"}, "source_references": [], "content": "Factual fixture"}}]}}
    for branch in ("rag", "graphrag"):
        op, np = old / ("A1_" + branch), new / ("A1_" + branch)
        op.mkdir()
        np.mkdir()
        put(op / "context.json", context)
        put(np / "context.json", context)
        put(op / "gate.json", {"reason_codes": ["traversal_required"]})
        put(np / "gate.json", {"reason_codes": [], "stage_results": {"evidence_answerability": {"checks": []}}})
        old_rows.append({"case_id": "A1", "branch": branch, "gate_decision": "abstain"})
        new_rows.append({"case_id": "A1", "branch": branch, "gate_decision": "proceed"})
    put(old / "results.json", {"rows": old_rows, "metrics": {}})
    put(new / "results.json", {"rows": new_rows, "metrics": {}})
    review = tmp_path / "review.json"
    put(review, {"review_type": "external", "cases": {"A1": {"rag": "partial", "graphrag": "partial", "note": "Đánh giá riêng, không suy từ proceed"}}})
    sources = [p for base in (old, new) for p in base.rglob("*.json")]
    hashes = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
    result = audit.build(old, new, review, tmp_path / "report")
    assert result["runtime_uses_rubric"] is False
    assert result["all_returned_contexts_unchanged"] is True
    assert result["cases"][0]["branches"]["rag"]["rubric_sufficiency"] == "partial"
    assert result["cases"][0]["branches"]["rag"]["after"] == "proceed"
    assert hashes == {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
    with (tmp_path / "report/before_after.csv").open(encoding="utf-8-sig", newline="") as handle:
        assert len(list(csv.DictReader(handle))) == 2
