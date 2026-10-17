"""Development tests for the declared parser subset, without benchmark readers."""

from copy import deepcopy
import inspect
import json

import pytest

from threat_hunting.graphrag import query_requirements as module
from threat_hunting.graphrag.query_requirements import (
    QueryRequirementsError,
    analyze_query_requirements,
    validate_query_requirements_document,
)


SCOPE = {"platforms": ["windows"], "mechanisms": ["process_creation"]}


def parse(query, **kwargs):
    return analyze_query_requirements(query, scope_metadata=SCOPE, **kwargs)


def of_kind(document, kind):
    return [item for item in document["requirements"] if item["kind"] == kind]


@pytest.mark.parametrize("parent,child", [("falcon.exe", "wren.exe"), ("renamed_1.exe", "generic-child.exe"), ("alpha.exe", "beta.exe")])
@pytest.mark.parametrize("template", [
    "Did {parent} spawn {child}?", "Explain how {parent} spawned {child}.",
    "{child} was spawned by {parent}; show the evidence.",
    "{parent} là tiến trình cha của {child} phải không?", "{parent} sinh ra {child}.",
])
def test_directed_roles_apply_to_arbitrary_executable_names(parent, child, template):
    document = parse(template.format(parent=parent, child=child))
    assert document["analysis_status"] == "supported"
    assert of_kind(document, "process_relationship")[0]["parameters"] == {"parent": parent, "child": child, "chain": False}
    assert all(item["mandatory"] for item in document["requirements"])


@pytest.mark.parametrize("query,parent,child", [
    ("Which process spawned swift.exe?", None, "swift.exe"),
    ("Which child did swift.exe spawn?", "swift.exe", None),
    ("Tiến trình cha của swift.exe là gì?", None, "swift.exe"),
    ("Which child process of swift.exe is observed?", "swift.exe", None),
])
def test_single_endpoint_roles(query, parent, child):
    assert of_kind(parse(query), "process_relationship")[0]["parameters"] == {"parent": parent, "child": child, "chain": False}


def test_arrows_produce_individual_mandatory_edges_and_preserve_roles():
    result = parse("Explain parent chain a.exe -> b.exe → c.exe")
    assert result["analysis_status"] == "supported"
    assert [item["parameters"] for item in of_kind(result, "process_relationship")] == [
        {"parent": "a.exe", "child": "b.exe", "chain": False},
        {"parent": "b.exe", "child": "c.exe", "chain": False},
    ]
    assert result["entities"][1] == {"name": "b.exe", "roles": ["child", "parent"]}


def test_names_without_direction_do_not_establish_relationship_roles():
    result = parse("Explain the parent-child relationship between a.exe and b.exe")
    assert result["analysis_status"] == "ambiguous"
    assert of_kind(result, "process_relationship")[0]["analysis_status"] == "ambiguous"


def test_arrow_does_not_imply_an_unmarked_second_edge():
    result = parse("a.exe -> b.exe and evidence for c.exe")
    assert result["analysis_status"] == "ambiguous"
    assert len(of_kind(result, "process_relationship")) == 1


def test_three_named_process_constraints_cannot_be_replaced_by_wildcard_chain():
    result = parse("Describe the chain between tern.exe, finch.exe and swift.exe")
    assert result["analysis_status"] == "ambiguous"
    assert {item["name"] for item in result["entities"]} == {"tern.exe", "finch.exe", "swift.exe"}
    assert of_kind(result, "process_relationship")[0]["analysis_status"] == "ambiguous"


@pytest.mark.parametrize("query", [
    "Explain the chain zxq_random_identifier", "Chuỗi văn bản zxq_random_identifier nghĩa là gì?",
    "Show the chain of custody for the evidence",
])
def test_unanchored_chain_or_string_is_not_a_supported_process_relationship(query):
    result = parse(query)
    assert result["analysis_status"] == "ambiguous"
    assert of_kind(result, "process_relationship")[0]["analysis_status"] == "ambiguous"


def test_generic_process_chain_without_names_still_has_a_process_anchor():
    result = parse("Show the observed process chain")
    assert result["analysis_status"] == "supported"
    assert of_kind(result, "process_relationship")[0]["parameters"]["chain"] is True


@pytest.mark.parametrize("query", [
    "Show the command line for falcon.exe", "Câu lệnh khởi chạy falcon.exe là gì?",
    "Which commandline launched FALCON.EXE?", "Cho biết dòng lệnh của falcon.exe",
])
def test_launch_command_paraphrases_en_vi(query):
    result = parse(query)
    assert result["analysis_status"] == "supported"
    assert of_kind(result, "launch_command")[0]["parameters"] == {"process": "falcon.exe"}
    assert not of_kind(result, "command_completion")


def test_public_alias_vocabulary_is_dynamic_and_detached():
    vocabulary = {"entity_aliases": {"the bird": "kestrel.exe"}}
    before = deepcopy(vocabulary)
    result = parse("Show the command line of the bird", vocabulary=vocabulary)
    assert vocabulary == before
    assert result["entities"][0]["name"] == "kestrel.exe"
    assert of_kind(result, "launch_command")[0]["parameters"]["process"] == "kestrel.exe"


def test_multiple_launch_subjects_remain_ambiguous():
    result = parse("Show the command lines for a.exe and b.exe")
    assert result["analysis_status"] == "ambiguous"


@pytest.mark.parametrize("query", [
    "Did falcon.exe complete successfully?", "Did falcon.exe produce output?",
    "falcon.exe đã hoàn tất thành công chưa?", "Kết quả của falcon.exe là gì?",
])
def test_completion_is_distinct_from_launch(query):
    result = parse(query)
    assert of_kind(result, "command_completion")
    assert not of_kind(result, "launch_command")


@pytest.mark.parametrize("query", ["What was the service state after falcon.exe?", "Trạng thái dịch vụ sau falcon.exe là gì?"])
def test_service_state_is_a_separate_requirement(query):
    assert of_kind(parse(query), "service_state")[0]["parameters"] == {"process": "falcon.exe"}


@pytest.mark.parametrize("query,action,field", [
    ("Which URL did falcon.exe download?", "download", "url"),
    ("falcon.exe tải xuống URL nào?", "download", "url"),
    ("Which endpoint did falcon.exe connect to?", "connect", "endpoint"),
    ("falcon.exe kết nối địa chỉ IP nào?", "connect", "endpoint"),
    ("What network endpoint is associated with falcon.exe?", "network", "endpoint"),
])
def test_network_actor_action_and_requested_field_are_explicit(query, action, field):
    result = parse(query)
    assert result["analysis_status"] == "supported"
    assert of_kind(result, "network_url")[0]["parameters"] == {"actor": "falcon.exe", "action": action, "field": field}


def test_multiple_potential_download_actors_are_ambiguous():
    result = parse("Which download URL is related to a.exe and b.exe?")
    assert result["analysis_status"] == "ambiguous"
    assert of_kind(result, "network_url")[0]["parameters"]["actor"] is None


@pytest.mark.parametrize("query,facet", [
    ("List all review limitations", "all"),
    ("Nêu tất cả giới hạn của phạm vi review", "all"),
    ("Explain the timestamp scope limitation", "timestamp"),
    ("Giới hạn về múi giờ là gì?", "timestamp"),
    ("What is the completion limitation?", "completion"),
    ("What is the limitation of a full dataset negative scan?", "negative_scan"),
    ("Describe limitations outside the process core", "core_boundaries"),
])
def test_limitation_facets_are_generic_concepts(query, facet):
    result = parse(query)
    assert result["analysis_status"] == "supported"
    assert facet in of_kind(result, "review_limitations")[0]["parameters"]["facets"]


@pytest.mark.parametrize("query,certainty", [
    ("Is T9999.001 confirmed?", "assessment"),
    ("T9999.001 có được xác nhận không?", "assessment"),
    ("Give proof of confirmed technique T9999.001", "confirmed"),
    ("Chứng minh kỹ thuật T9999.001 đã được xác nhận", "confirmed"),
])
def test_candidate_status_inquiry_differs_from_affirmative_confirmation_proof(query, certainty):
    result = parse(query)
    assert of_kind(result, "technique_assessment")[0]["parameters"] == {"technique_id": "T9999.001", "certainty": certainty}


def test_multiple_intents_are_all_mandatory_and_not_collapsed_to_one():
    result = parse("Show the command line for falcon.exe and provide source references")
    assert result["analysis_status"] == "supported"
    assert {item["kind"] for item in result["requirements"]} == {"launch_command", "evidence_provenance"}
    assert [item["requirement_id"] for item in result["requirements"]] == ["r1", "r2"]


@pytest.mark.parametrize("query", [
    "Show the launch command for falcon.exe and tell me tomorrow weather",
    "Cho biết dòng lệnh của falcon.exe và cho biết giá nhà ngày mai",
    "Show the launch command for falcon.exe; explain quantum gravity",
])
def test_known_first_clause_does_not_hide_an_unknown_requested_clause(query):
    result = parse(query)
    assert result["analysis_status"] == "ambiguous"
    assert "unrecognized_conjoined_request" in result["reason_codes"]


@pytest.mark.parametrize("query", [
    "Who was the attacker according to the evidence?",
    "Identify the threat actor using these source records",
    "Nhóm tấn công nào được xác định từ bằng chứng?",
])
def test_evidence_qualifier_does_not_turn_unknown_attribution_into_provenance_only(query):
    result = parse(query)
    assert result["analysis_status"] == "ambiguous"
    assert "unsupported_attribution_or_identity_requirement" in result["reason_codes"]


@pytest.mark.parametrize("query", [
    "Show evidence that kestrel.exe encrypted records",
    "Give proof of kestrel.exe erasing invoices",
    "Có bằng chứng cho thấy kestrel.exe mã hóa hồ sơ không?",
    "Nêu bằng chứng về việc kestrel.exe sửa hóa đơn",
])
def test_positive_unsupported_predicate_cannot_collapse_to_provenance(query):
    result = parse(query)
    assert result["analysis_status"] == "ambiguous"
    assert "requested_assertion_predicate_not_supported" in result["reason_codes"]


@pytest.mark.parametrize("query", [
    "Show raw event evidence for kestrel.exe",
    "Nêu bằng chứng bản ghi gốc của kestrel.exe",
    "Show evidence that kestrel.exe spawned finch.exe",
])
def test_provenance_itself_or_a_declared_predicate_remains_supported(query):
    result = parse(query)
    assert result["analysis_status"] == "supported"
    assert of_kind(result, "evidence_provenance")


@pytest.mark.parametrize("query", [
    "Can we conclude a malicious attack from worker.exe chain?",
    "Does the process chain establish malicious intent?",
    "Có thể khẳng định chuỗi tiến trình worker.exe là tấn công không?",
])
def test_final_security_conclusion_is_not_reduced_to_process_relationship(query):
    result = parse(query)
    assert result["analysis_status"] == "ambiguous"
    assert "requested_security_conclusion_not_supported" in result["reason_codes"]


def test_mentioning_attack_in_review_limits_is_not_scope_mismatch_or_positive_conclusion():
    result = parse("Explain the limitations before concluding a malicious attack")
    assert result["analysis_status"] == "supported"
    assert result["scope"]["status"] == "unspecified"
    assert of_kind(result, "review_limitations")


@pytest.mark.parametrize("query", [
    "Show Linux cron process evidence", "Nêu bằng chứng tiến trình cron trên Linux",
    "Show the Unix command line", "What is the cron command line?",
])
def test_clear_out_of_source_scope_is_not_a_full_query_blacklist(query):
    result = parse(query)
    assert result["scope"]["status"] == "mismatch"
    assert result["analysis_status"] == "supported"


@pytest.mark.parametrize("query", [
    "Not Linux cron; show Windows command line for falcon.exe",
    "Ignore Linux cron; show Windows command line for falcon.exe",
    "Không xét Linux cron; cho biết dòng lệnh Windows của falcon.exe",
])
def test_explicit_excluded_scope_mention_does_not_make_active_request_out_of_scope(query):
    result = parse(query)
    assert result["analysis_status"] == "supported"
    assert result["scope"]["requested_platforms"] == ["windows"]
    assert result["scope"]["excluded_platforms"] == ["linux"]
    assert result["scope"]["mechanisms"] == []
    assert result["scope"]["status"] == "in_scope"


@pytest.mark.parametrize("query", [
    "Compare Linux cron evidence with Windows process evidence",
    "So sánh dòng lệnh Linux và Windows",
    "Describe Linux evidence and Windows command lines",
    "Unlike Linux cron, what is the Windows command line?",
])
def test_comparisons_and_mixed_active_scopes_are_explicitly_ambiguous(query):
    result = parse(query)
    assert result["analysis_status"] == "ambiguous"
    assert result["scope"]["status"] == "ambiguous"


@pytest.mark.parametrize("query", [
    "Did falcon.exe not spawn wren.exe?", "Prove falcon.exe never downloaded a URL",
    "Không có bằng chứng falcon.exe sinh wren.exe đúng không?",
])
def test_unresolved_negation_is_not_an_absence_claim(query):
    result = parse(query)
    assert result["analysis_status"] == "ambiguous"
    assert "negation_scope_not_resolved" in result["reason_codes"]


@pytest.mark.parametrize("query", [
    "Show the command line for kestrel.exe without using Linux",
    "Không dùng Linux; cho biết dòng lệnh của kestrel.exe",
])
def test_unresolved_outside_platform_negation_is_scope_ambiguous_not_mismatch(query):
    result = parse(query)
    assert result["analysis_status"] == "ambiguous"
    assert result["scope"]["status"] == "ambiguous"
    assert result["scope"]["reason_codes"] == ["negated_scope_unresolved"]
    assert "scope_analysis_ambiguous" in result["reason_codes"]


def test_unknown_information_is_explicit_and_scope_unknown_is_not_mismatch():
    result = parse("Explain tomorrow's weather")
    assert result["analysis_status"] == "unsupported"
    assert result["scope"]["status"] == "unspecified"
    assert result["requirements"] == []


def test_public_scope_vocabulary_extends_systematically():
    vocabulary = {"platforms": {"testos": ["Test OS"]}}
    result = parse("Show Test OS command line for falcon.exe", vocabulary=vocabulary)
    assert result["scope"]["requested_platforms"] == ["testos"]
    assert result["scope"]["status"] == "mismatch"


@pytest.mark.parametrize("name", ["linux.exe", "cron.exe", "windows-helper.exe"])
def test_platform_or_scheduler_substring_in_executable_is_not_a_scope_request(name):
    result = parse(f"Show the command line for {name}")
    assert result["analysis_status"] == "supported"
    assert result["scope"]["status"] == "unspecified"
    assert result["scope"]["mechanisms"] == []


def test_parser_inputs_and_return_values_are_detached_and_deterministic():
    scope = deepcopy(SCOPE)
    before = deepcopy(scope)
    first = analyze_query_requirements("Show falcon.exe command line", scope_metadata=scope)
    second = analyze_query_requirements("Show falcon.exe command line", scope_metadata=scope)
    assert first == second
    first["scope"]["requested_platforms"].append("sentinel")
    assert second["scope"]["requested_platforms"] == []
    assert scope == before
    assert json.loads(json.dumps(second)) == second


@pytest.mark.parametrize("query", [None, "", "   ", 3, ["command"]])
def test_invalid_query_inputs_rejected(query):
    with pytest.raises(QueryRequirementsError):
        analyze_query_requirements(query)


@pytest.mark.parametrize("kwargs", [
    {"scope_metadata": []}, {"scope_metadata": {"platforms": "windows"}},
    {"scope_metadata": {"mechanisms": [3]}}, {"scope_metadata": {"platforms": [float("nan")]}},
    {"vocabulary": {"case_id": "forbidden"}}, {"vocabulary": {"concepts": {"command": []}}},
    {"vocabulary": {"entity_aliases": {"bird": 1}}},
])
def test_invalid_public_config_inputs_rejected(kwargs):
    with pytest.raises(QueryRequirementsError):
        analyze_query_requirements("Show command line", **kwargs)


@pytest.mark.parametrize("field,value", [("case_id", "sentinel"), ("expected_decision", "proceed")])
def test_evaluation_annotations_cannot_enter_through_scope_metadata(field, value):
    metadata = {**SCOPE, field: value}
    with pytest.raises(QueryRequirementsError, match="scope_metadata has unsupported fields"):
        analyze_query_requirements("Show command line", scope_metadata=metadata)


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(case_id="not-a-runtime-field"),
    lambda d: d.update(analysis_status=[]),
    lambda d: d["scope"].update(status=[]),
    lambda d: d["entities"][0].update(roles=[{}]),
    lambda d: d["requirements"][0].update(kind=[]),
    lambda d: d["requirements"][0].update(mandatory=1),
    lambda d: d["requirements"][0]["parameters"].update(reference_answer="forbidden"),
    lambda d: d["requirements"].append(deepcopy(d["requirements"][0])),
    lambda d: d.update(requirements=[]),
])
def test_validator_rejects_bad_structure_without_python_type_errors(mutate):
    document = parse("Show falcon.exe command line")
    mutate(document)
    with pytest.raises(QueryRequirementsError):
        validate_query_requirements_document(document)


def test_parser_has_no_file_io_or_evaluation_dependencies():
    source = inspect.getsource(module)
    assert "from ..evaluation" not in source
    assert "reference_answers" not in source
    assert "read_text(" not in source
    assert "open(" not in source
    assert "case_id" not in source
    assert "expected_decision" not in source
    assert "expected_evidence" not in source


def test_runtime_api_cannot_accept_labels_or_answers():
    with pytest.raises(TypeError):
        analyze_query_requirements("Show command line", case_id="sentinel")
    with pytest.raises(TypeError):
        analyze_query_requirements("Show command line", reference_answer="sentinel")
