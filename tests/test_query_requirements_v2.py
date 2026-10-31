"""Synthetic development cases for clause-local requests and exact role traces."""

from copy import deepcopy
import inspect
import json
import unicodedata

import pytest

from threat_hunting.graphrag import query_requirements as old
from threat_hunting.graphrag import query_requirements_v2 as module
from threat_hunting.graphrag.query_requirements_v2 import (
    QueryRequirementsError, analyze_query_requirements_v2,
    requirements_v1_projection, validate_query_requirements_document_v2,
)


SCOPE = {"platforms": ["windows"], "mechanisms": ["process_creation"]}


def parse(query, **kwargs):
    return analyze_query_requirements_v2(query, scope_metadata=SCOPE, **kwargs)


def kind(document, name):
    return [item for item in document["requirements"] if item["kind"] == name]


@pytest.mark.parametrize("name", ["swift.exe", "renamed-child.exe", "another_23.exe"])
@pytest.mark.parametrize("template", [
    "Which process chain led to {name}?", "Show the ancestor chain ending in {name}",
    "Chuỗi tiến trình nào dẫn tới {name}?", "Truy ngược chuỗi tiến trình đến {name}",
])
def test_target_only_chain_keeps_target_without_invented_ancestor(name, template):
    result = parse(template.format(name=name))
    assert result["analysis_status"] == "supported"
    relation = kind(result, "process_relationship")[0]
    assert relation["parameters"] == {"parent": None, "child": name, "chain": True}
    assert relation["reason_codes"] == ["target_only_ancestor_request"]
    assert {span["role"] for span in relation["source_spans"]} >= {"request", "target", "object"}


@pytest.mark.parametrize("parent,child", [("falcon.exe", "wren.exe"), ("helper_2.exe", "bird-child.exe")])
@pytest.mark.parametrize("template", [
    "Show evidence supporting {parent} to {child} process creation relationship",
    "Nêu bằng chứng hỗ trợ quan hệ tạo tiến trình từ {parent} tới {child}",
    "Show evidence that {parent} spawned {child}",
    "{child} was spawned by {parent}; show source references",
])
def test_directed_creation_and_provenance_are_role_bound(parent, child, template):
    result = parse(template.format(parent=parent, child=child))
    assert result["analysis_status"] == "supported"
    assert kind(result, "process_relationship")[0]["parameters"] == {"parent": parent, "child": child, "chain": False}
    provenance = kind(result, "evidence_provenance")
    assert provenance
    if len(result["clauses"]) == 1:
        assert provenance[0]["parameters"]["process"] == child


@pytest.mark.parametrize("query,target", [
    ("What command was wren.exe launched with by falcon.exe?", "wren.exe"),
    ("Which command line was wren.exe launched with?", "wren.exe"),
    ("What command did falcon.exe use when it launched wren.exe?", "wren.exe"),
    ("wren.exe được khởi chạy với lệnh gì bởi falcon.exe?", "wren.exe"),
    ("Câu lệnh khi wren.exe được khởi chạy là gì?", "wren.exe"),
])
def test_launch_command_selects_launched_process_not_launcher(query, target):
    result = parse(query)
    assert result["analysis_status"] == "supported"
    assert kind(result, "launch_command")[0]["parameters"] == {"process": target}
    assert not kind(result, "process_relationship")
    assert not kind(result, "command_completion")


@pytest.mark.parametrize("query", [
    "In the falcon.exe chain, which URL did wren.exe download?",
    "Which URL did wren.exe download in the falcon.exe chain?",
    "Trong chuỗi falcon.exe, wren.exe tải xuống URL nào?",
    "wren.exe tải xuống URL nào trong chuỗi falcon.exe?",
])
def test_background_chain_does_not_create_an_extra_requirement_or_actor(query):
    result = parse(query)
    assert result["analysis_status"] == "supported"
    assert [item["kind"] for item in result["requirements"]] == ["network_url"]
    assert result["requirements"][0]["parameters"] == {"actor": "wren.exe", "action": "download", "field": "url"}
    assert {clause["role"] for clause in result["clauses"]} == {"request", "background"}
    assert not any(span["text"] == "falcon.exe" for span in result["requirements"][0]["source_spans"])


@pytest.mark.parametrize("query,actor,action,field", [
    ("Which URL did wren.exe download after falcon.exe?", "wren.exe", "download", "url"),
    ("Which URL was downloaded by wren.exe after falcon.exe?", "wren.exe", "download", "url"),
    ("URL nào do wren.exe tải xuống sau falcon.exe?", "wren.exe", "download", "url"),
    ("Which endpoint did wren.exe connect to after falcon.exe?", "wren.exe", "connect", "endpoint"),
    ("wren.exe kết nối endpoint nào sau falcon.exe?", "wren.exe", "connect", "endpoint"),
])
def test_main_action_binds_actor_with_multiple_process_mentions(query, actor, action, field):
    result = parse(query)
    assert result["analysis_status"] == "supported"
    requirement = kind(result, "network_url")[0]
    assert requirement["parameters"] == {"actor": actor, "action": action, "field": field}
    assert any(span["role"] == "subject" and span["text"].lower() == actor for span in requirement["source_spans"])
    assert any(span["role"] == "action" for span in requirement["source_spans"])


def test_ambiguous_related_url_does_not_guess_the_actor():
    result = parse("Which download URL is associated with falcon.exe and wren.exe?")
    assert result["analysis_status"] == "ambiguous"
    assert kind(result, "network_url")[0]["parameters"]["actor"] is None


@pytest.mark.parametrize("query", [
    "List all review limitations", "Nêu tất cả giới hạn bằng chứng trước review",
    "Which evidence limitations need further checks?", "Cần kiểm tra thêm gì trong phạm vi bằng chứng đã review?",
])
def test_general_review_and_grounded_follow_up_require_complete_limits(query):
    result = parse(query)
    assert result["analysis_status"] == "supported"
    assert kind(result, "review_limitations")[0]["parameters"] == {"facets": ["all"]}


@pytest.mark.parametrize("query,facet", [
    ("What is the timestamp evidence limitation?", "timestamp"),
    ("Giới hạn về múi giờ là gì?", "timestamp"),
    ("What is not established about command completion by the evidence scope?", "completion"),
    ("Explain only the full-dataset negative scan limitation", "negative_scan"),
    ("What is the analysis status?", "review_status"),
    ("Trạng thái phân tích là gì?", "review_status"),
])
def test_review_facet_is_not_automatically_every_limit_or_positive_claim(query, facet):
    result = parse(query)
    assert result["analysis_status"] == "supported"
    assert facet in kind(result, "review_limitations")[0]["parameters"]["facets"]
    assert not kind(result, "command_completion")


def test_status_plus_limits_are_preserved_and_projection_is_selection_only():
    result = parse("Give the analysis status and all review limitations")
    assert result["analysis_status"] == "supported"
    assert kind(result, "review_limitations")[0]["parameters"]["facets"] == ["all", "review_status"]
    before = deepcopy(result)
    projected = requirements_v1_projection(result)
    assert projected["schema_version"] == "query-requirements/v1"
    assert kind(projected, "review_limitations")[0]["parameters"]["facets"] == ["all", "scope"]
    old.validate_query_requirements_document(projected)
    assert result == before


@pytest.mark.parametrize("query", [
    "Who was the human reviewer?", "What is the human review status?",
    "Người duyệt là ai?", "What is the approval timestamp?",
])
def test_human_review_metadata_does_not_become_analysis_status(query):
    result = parse(query)
    assert result["analysis_status"] != "supported"
    assert "human_approval_metadata_outside_runtime_contract" in result["reason_codes"]
    assert not result["requirements"]


@pytest.mark.parametrize("query", ["What should I check next?", "Cần kiểm tra thêm điều gì?"])
def test_ungrounded_general_advice_is_not_fabricated_from_available_limits(query):
    result = parse(query)
    assert result["analysis_status"] == "unsupported"


def test_independent_requests_are_all_mandatory_and_have_separate_spans():
    result = parse("Show the launch command for falcon.exe and which URL did wren.exe download?")
    assert result["analysis_status"] == "supported"
    assert [item["kind"] for item in result["requirements"]] == ["launch_command", "network_url"]
    assert result["requirements"][0]["parameters"] == {"process": "falcon.exe"}
    assert result["requirements"][1]["parameters"]["actor"] == "wren.exe"
    assert all(item["mandatory"] for item in result["requirements"])
    assert len({item["source_spans"][0]["clause_id"] for item in result["requirements"]}) == 2


def test_two_separate_review_questions_are_not_collapsed_by_equal_parameters():
    result = parse("List review limitations and what should we check next in the reviewed evidence?")
    assert result["analysis_status"] == "supported"
    assert len(kind(result, "review_limitations")) == 2
    assert result["requirements"][1]["reason_codes"] == ["requested_follow_up_review"]


def test_launch_and_completion_cannot_be_collapsed_to_launch_only():
    result = parse("Show the command line for falcon.exe and did wren.exe complete successfully?")
    assert result["analysis_status"] == "supported"
    assert [item["kind"] for item in result["requirements"]] == ["launch_command", "command_completion"]
    assert result["requirements"][1]["parameters"]["process"] == "wren.exe"


@pytest.mark.parametrize("query", [
    "Show falcon.exe -> wren.exe and the launch command for wren.exe",
    "Nêu falcon.exe -> wren.exe và dòng lệnh của wren.exe",
])
def test_coordinated_request_nouns_preserve_relationship_and_launch(query):
    result = parse(query)
    assert result["analysis_status"] == "supported"
    assert [item["kind"] for item in result["requirements"]] == ["process_relationship", "launch_command"]


def test_two_explicit_network_actions_keep_separate_role_bound_requirements():
    result = parse("Which URL did falcon.exe download and wren.exe connect to?")
    assert result["analysis_status"] == "supported"
    assert [item["parameters"] for item in kind(result, "network_url")] == [
        {"actor": "falcon.exe", "action": "download", "field": "url"},
        {"actor": "wren.exe", "action": "connect", "field": "url"},
    ]


def test_completion_limit_mentioning_command_does_not_require_launch_evidence():
    result = parse("Explain the command completion limitation in the evidence scope")
    assert result["analysis_status"] == "supported"
    assert [item["kind"] for item in result["requirements"]] == ["review_limitations"]


@pytest.mark.parametrize("query", [
    "Show falcon.exe command line and explain tomorrow weather",
    "Cho biết dòng lệnh falcon.exe và cho biết giá nhà ngày mai",
    "Show falcon.exe command line; explain quantum gravity",
    "Show the falcon.exe launch command and which URL did it download?",
])
def test_supported_clause_does_not_hide_unknown_clause_or_pronoun(query):
    assert parse(query)["analysis_status"] == "ambiguous"


@pytest.mark.parametrize("query", [
    "Did falcon.exe not spawn wren.exe?", "Prove falcon.exe never downloaded a URL",
    "Không có bằng chứng falcon.exe sinh wren.exe đúng không?",
    "Compare falcon.exe and wren.exe launch commands",
    "So sánh chuỗi falcon.exe với wren.exe",
])
def test_negation_and_comparison_remain_unresolved(query):
    assert parse(query)["analysis_status"] == "ambiguous"


@pytest.mark.parametrize("query", [
    "falcon.exe đã hoàn tất thành công chưa?",
    "falcon.exe sinh ra wren.exe phải không?",
])
def test_vietnamese_trailing_question_particles_are_not_unsupported_negations(query):
    assert parse(query)["analysis_status"] == "supported"


@pytest.mark.parametrize("query", [
    "Show evidence that falcon.exe encrypted documents",
    "Có bằng chứng falcon.exe mã hóa hồ sơ không?",
    "Who is the attacker according to the evidence?",
    "Can we conclude the falcon.exe chain was malicious?",
])
def test_unsupported_assertions_do_not_collapse_to_broad_provenance(query):
    assert parse(query)["analysis_status"] != "supported"


@pytest.mark.parametrize("query", [
    "Not Linux cron; show Windows command line for falcon.exe",
    "Không xét Linux cron; cho biết dòng lệnh Windows của falcon.exe",
])
def test_explicit_scope_exclusion_remains_supported(query):
    result = parse(query)
    assert result["analysis_status"] == "supported"
    assert result["scope"]["status"] == "in_scope"
    assert result["scope"]["excluded_platforms"] == ["linux"]


def test_scope_unspecified_is_distinct_from_mismatch():
    assert parse("Show the launch command for falcon.exe")["scope"]["status"] == "unspecified"
    assert parse("Show Linux cron process evidence")["scope"]["status"] == "mismatch"


@pytest.mark.parametrize("normalization", ["NFC", "NFD"])
def test_every_trace_resolves_to_exact_original_unicode(normalization):
    query = unicodedata.normalize(normalization, "Trong chuỗi falcon.exe, wren.exe tải xuống URL nào?")
    result = parse(query)
    clauses = {clause["clause_id"]: clause for clause in result["clauses"]}
    for clause in result["clauses"]:
        assert query[clause["start"]:clause["end"]] == clause["text"]
    for requirement in result["requirements"]:
        for span in requirement["source_spans"]:
            assert query[span["start"]:span["end"]] == span["text"]
            clause = clauses[span["clause_id"]]
            assert clause["start"] <= span["start"] < span["end"] <= clause["end"]


def test_public_aliases_and_inputs_are_detached_and_deterministic():
    vocabulary = {"entity_aliases": {"the bird": "tern.exe"}}
    before = deepcopy(vocabulary)
    first = parse("Which process chain led to the bird?", vocabulary=vocabulary)
    assert first == parse("Which process chain led to the bird?", vocabulary=vocabulary)
    assert vocabulary == before
    assert kind(first, "process_relationship")[0]["parameters"]["child"] == "tern.exe"
    assert json.loads(json.dumps(first)) == first


@pytest.mark.parametrize("mutate", [
    lambda doc: doc.update(schema_version="query-requirements/v99"),
    lambda doc: doc.update(extra="annotation"),
    lambda doc: doc["clauses"][0].update(text="not query"),
    lambda doc: doc["clauses"][0].update(start=True),
    lambda doc: doc["requirements"][0].update(source_spans=[]),
    lambda doc: doc["requirements"][0]["source_spans"][0].update(clause_id="c999"),
    lambda doc: doc["requirements"][0]["source_spans"][0].update(role="unrecognized"),
    lambda doc: doc["requirements"][0]["source_spans"][0].update(text="different"),
    lambda doc: doc["requirements"][0].update(kind=[]),
    lambda doc: doc["requirements"][0].update(parameters=[]),
])
def test_strict_finite_validator_rejects_inconsistent_document(mutate):
    document = parse("Show falcon.exe command line")
    mutate(document)
    with pytest.raises(QueryRequirementsError):
        validate_query_requirements_document_v2(document)


@pytest.mark.parametrize("query", [None, "", " ", 1, []])
def test_invalid_query_inputs(query):
    with pytest.raises(QueryRequirementsError):
        analyze_query_requirements_v2(query)


def test_legacy_parser_and_projection_validation_stay_separate():
    query = "Which process chain led to swift.exe?"
    assert old.analyze_query_requirements(query)["analysis_status"] == "ambiguous"
    new = parse(query)
    with pytest.raises(QueryRequirementsError):
        old.validate_query_requirements_document(new)
    with pytest.raises(QueryRequirementsError):
        validate_query_requirements_document_v2(old.analyze_query_requirements(query))


def test_runtime_module_has_no_io_or_evaluation_inputs():
    source = inspect.getsource(module)
    for token in ("from ..evaluation", "read_text(", "open(", "case_id", "expected_decision", "reference_answers", "expected_evidence"):
        assert token not in source
    with pytest.raises(TypeError):
        analyze_query_requirements_v2("Show command line", expected_decision="proceed")
    with pytest.raises(QueryRequirementsError):
        analyze_query_requirements_v2("Show command line", scope_metadata={**SCOPE, "category": "annotation"})
