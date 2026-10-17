# FIX3 — Toàn bộ 32 development cases

Các labels/rubric sau đây chỉ được evaluator đọc ngoài runtime. A=abstain, P=proceed. Quotes chi tiết cho mọi case thay đổi ở `changed_cases.md`.

| Case | Label | E0 | E1 | E2 | E3 | E4 | Parser E4 | Support E4 | External context E4 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| rd-en-process-chain | proceed | abstain | proceed | abstain | proceed | proceed | supported | supported | True |
| rd-en-shell-parent | proceed | proceed | proceed | proceed | proceed | proceed | supported | supported | True |
| rd-en-initial-spawn-evidence | proceed | abstain | proceed | abstain | proceed | proceed | supported | supported | True |
| rd-en-final-spawn-evidence | proceed | abstain | proceed | abstain | proceed | proceed | supported | supported | True |
| rd-vi-proxy-technique-assessment | proceed | abstain | abstain | proceed | abstain | proceed | supported | supported | True |
| rd-vi-scripting-technique-status | proceed | abstain | abstain | abstain | abstain | abstain | ambiguous | unknown | True |
| rd-vi-reviewed-scope-limitations | proceed | abstain | abstain | proceed | proceed | proceed | supported | supported | True |
| rd-vi-initial-relation-provenance | proceed | abstain | abstain | proceed | proceed | proceed | supported | supported | True |
| rp-en-intermediate-utility | proceed | abstain | abstain | abstain | abstain | abstain | unsupported | unknown | True |
| rp-en-shell-creator | proceed | abstain | abstain | abstain | abstain | abstain | ambiguous | unknown | True |
| rp-en-technique-review | proceed | abstain | abstain | abstain | abstain | abstain | ambiguous | unknown | True |
| rp-en-retained-scripting-label | proceed | proceed | proceed | proceed | proceed | proceed | supported | supported | True |
| rp-vi-launch-order | proceed | abstain | abstain | abstain | abstain | abstain | supported | unknown | True |
| rp-vi-observation-provenance | proceed | abstain | abstain | abstain | abstain | abstain | supported | unknown | True |
| rp-vi-final-review-limits | proceed | abstain | abstain | abstain | abstain | abstain | unsupported | unknown | False |
| rp-vi-service-action | proceed | abstain | abstain | proceed | proceed | proceed | supported | supported | None |
| ie-en-payload-download-url | abstain | abstain | abstain | abstain | abstain | abstain | supported | missing | False |
| ie-en-c2-address | abstain | abstain | abstain | abstain | abstain | abstain | supported | missing | False |
| ie-en-attacker-identity | abstain | abstain | abstain | abstain | abstain | abstain | ambiguous | unknown | False |
| ie-en-stolen-credentials | abstain | abstain | abstain | abstain | abstain | abstain | unsupported | unknown | False |
| ie-vi-destructive-files | abstain | abstain | abstain | abstain | abstain | abstain | ambiguous | unknown | False |
| ie-vi-decoded-content | abstain | abstain | abstain | abstain | abstain | abstain | unsupported | unknown | False |
| ie-vi-decoding-proof | abstain | abstain | abstain | abstain | abstain | abstain | ambiguous | unknown | False |
| ie-vi-certain-attack-determination | abstain | abstain | abstain | abstain | abstain | abstain | ambiguous | unknown | False |
| ur-en-weather | abstain | abstain | abstain | abstain | abstain | abstain | unsupported | unknown | None |
| ur-en-product-price | abstain | abstain | abstain | abstain | abstain | abstain | unsupported | unknown | None |
| ur-en-linux-cron | abstain | abstain | abstain | abstain | abstain | abstain | unsupported | unknown | None |
| ur-en-sql-injection | abstain | abstain | abstain | abstain | abstain | abstain | unsupported | unknown | None |
| ur-vi-ransomware-encryption | abstain | abstain | abstain | abstain | abstain | abstain | unsupported | unknown | None |
| ur-vi-kubernetes-configuration | abstain | abstain | abstain | abstain | abstain | abstain | unsupported | unknown | None |
| ur-vi-literature-learning | abstain | abstain | abstain | abstain | abstain | abstain | unsupported | unknown | None |
| ur-vi-opaque-token | abstain | abstain | abstain | abstain | abstain | abstain | ambiguous | unknown | None |

## rd-en-process-chain

Which process chain led to powershell.exe in the reviewed evidence?

Expected: `proceed`; category `relevant_direct`; language `en`.

| Arm | Scope | Parser/support | Decision | Reason codes |
| --- | --- | --- | --- | --- |
| E0 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown |
| E1 | unspecified | supported/supported | proceed | — |
| E2 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown, independent_evidence_guard_unknown, mandatory_support_trace_empty, required_evidence_identity_or_source_anchor_missing |
| E3 | unspecified | supported/supported | proceed | — |
| E4 | unspecified | supported/supported | proceed | — |

E4 requirements: `[{"analysis_status":"supported","kind":"process_relationship","parameters":{"chain":true,"child":"powershell.exe","parent":null},"requirement_id":"r1"},{"analysis_status":"supported","kind":"evidence_provenance","parameters":{"process":"powershell.exe"},"requirement_id":"r2"}]`.

E4 support detail: `[{"completeness":{"reason_codes":["authenticated_source_boundary_reached"],"status":"complete"},"contradiction":{"reason_codes":[],"status":"none_detected"},"reason_codes":["source_bounded_ancestor_chain_supported"],"requirement_id":"r1","status":"supported"},{"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"reason_codes":["associated_original_observation_provenance_supported"],"requirement_id":"r2","status":"supported"}]`.

External context: `True`; basis `all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation`.

## rd-en-shell-parent

Which process is the observed parent of powershell.exe?

Expected: `proceed`; category `relevant_direct`; language `en`.

| Arm | Scope | Parser/support | Decision | Reason codes |
| --- | --- | --- | --- | --- |
| E0 | unspecified | supported/supported | proceed | — |
| E1 | unspecified | supported/supported | proceed | — |
| E2 | unspecified | supported/supported | proceed | — |
| E3 | unspecified | supported/supported | proceed | — |
| E4 | unspecified | supported/supported | proceed | — |

E4 requirements: `[{"analysis_status":"supported","kind":"process_relationship","parameters":{"chain":false,"child":"powershell.exe","parent":null},"requirement_id":"r1"}]`.

E4 support detail: `[{"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"reason_codes":["directed_process_creation_supported"],"requirement_id":"r1","status":"supported"}]`.

External context: `True`; basis `all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation`.

## rd-en-initial-spawn-evidence

What evidence supports the cmd.exe to mshta.exe process creation relationship?

Expected: `proceed`; category `relevant_direct`; language `en`.

| Arm | Scope | Parser/support | Decision | Reason codes |
| --- | --- | --- | --- | --- |
| E0 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown |
| E1 | unspecified | supported/supported | proceed | — |
| E2 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown, independent_evidence_guard_unknown, mandatory_support_trace_empty, required_evidence_identity_or_source_anchor_missing |
| E3 | unspecified | supported/supported | proceed | — |
| E4 | unspecified | supported/supported | proceed | — |

E4 requirements: `[{"analysis_status":"supported","kind":"process_relationship","parameters":{"chain":false,"child":"mshta.exe","parent":"cmd.exe"},"requirement_id":"r1"},{"analysis_status":"supported","kind":"evidence_provenance","parameters":{"process":"mshta.exe"},"requirement_id":"r2"}]`.

E4 support detail: `[{"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"reason_codes":["directed_process_creation_supported"],"requirement_id":"r1","status":"supported"},{"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"reason_codes":["associated_original_observation_provenance_supported"],"requirement_id":"r2","status":"supported"}]`.

External context: `True`; basis `all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation`.

## rd-en-final-spawn-evidence

What evidence supports the mshta.exe to powershell.exe process creation relationship?

Expected: `proceed`; category `relevant_direct`; language `en`.

| Arm | Scope | Parser/support | Decision | Reason codes |
| --- | --- | --- | --- | --- |
| E0 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown |
| E1 | unspecified | supported/supported | proceed | — |
| E2 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown, independent_evidence_guard_unknown, mandatory_support_trace_empty, required_evidence_identity_or_source_anchor_missing |
| E3 | unspecified | supported/supported | proceed | — |
| E4 | unspecified | supported/supported | proceed | — |

E4 requirements: `[{"analysis_status":"supported","kind":"process_relationship","parameters":{"chain":false,"child":"powershell.exe","parent":"mshta.exe"},"requirement_id":"r1"},{"analysis_status":"supported","kind":"evidence_provenance","parameters":{"process":"powershell.exe"},"requirement_id":"r2"}]`.

E4 support detail: `[{"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"reason_codes":["directed_process_creation_supported"],"requirement_id":"r1","status":"supported"},{"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"reason_codes":["associated_original_observation_provenance_supported"],"requirement_id":"r2","status":"supported"}]`.

External context: `True`; basis `all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation`.

## rd-vi-proxy-technique-assessment

Đánh giá hiện tại đối với ATT&CK T1218.005 có mức hỗ trợ bằng chứng và trạng thái review nào?

Expected: `proceed`; category `relevant_direct`; language `vi`.

| Arm | Scope | Parser/support | Decision | Reason codes |
| --- | --- | --- | --- | --- |
| E0 | unspecified | supported/supported | abstain | legacy_quality_gate_abstained |
| E1 | unspecified | supported/missing | abstain | required_evidence_missing, legacy_quality_gate_abstained |
| E2 | unspecified | supported/supported | proceed | — |
| E3 | unspecified | supported/missing | abstain | required_evidence_missing, independent_evidence_guard_missing, mandatory_support_trace_empty, required_evidence_identity_or_source_anchor_missing, required_completeness_incomplete |
| E4 | unspecified | supported/supported | proceed | — |

E4 requirements: `[{"analysis_status":"supported","kind":"evidence_provenance","parameters":{"process":null},"requirement_id":"r1"},{"analysis_status":"supported","kind":"technique_assessment","parameters":{"certainty":"assessment","technique_id":"T1218.005"},"requirement_id":"r2"},{"analysis_status":"supported","kind":"review_limitations","parameters":{"facets":["review_status"]},"requirement_id":"r3"}]`.

E4 support detail: `[{"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"reason_codes":["associated_original_observation_provenance_supported"],"requirement_id":"r1","status":"supported"},{"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"reason_codes":["technique_assessment_status_preserved"],"requirement_id":"r2","status":"supported"},{"completeness":{"reason_codes":["requested_source_identity_set_present"],"status":"complete"},"contradiction":{"reason_codes":[],"status":"none_detected"},"reason_codes":["exact_requested_review_source_identities_supported"],"requirement_id":"r3","status":"supported"}]`.

External context: `True`; basis `all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation`.

## rd-vi-scripting-technique-status

T1059.007 có được hỗ trợ bởi command line đã quan sát không, và trạng thái đánh giá là gì?

Expected: `proceed`; category `relevant_direct`; language `vi`.

| Arm | Scope | Parser/support | Decision | Reason codes |
| --- | --- | --- | --- | --- |
| E0 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown, legacy_quality_gate_abstained |
| E1 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown, legacy_quality_gate_abstained |
| E2 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown, independent_evidence_guard_unknown, mandatory_support_trace_empty, required_evidence_identity_or_source_anchor_missing |
| E3 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown, independent_evidence_guard_unknown, mandatory_support_trace_empty, required_evidence_identity_or_source_anchor_missing |
| E4 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown, independent_evidence_guard_unknown, mandatory_support_trace_empty, required_evidence_identity_or_source_anchor_missing |

E4 requirements: `[{"analysis_status":"supported","kind":"launch_command","parameters":{"process":null},"requirement_id":"r1"},{"analysis_status":"supported","kind":"technique_assessment","parameters":{"certainty":"assessment","technique_id":"T1059.007"},"requirement_id":"r2"}]`.

E4 support detail: `[{"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"reason_codes":["query_requirement_analysis_not_supported"],"requirement_id":"r1","status":"unknown"},{"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"reason_codes":["query_requirement_analysis_not_supported"],"requirement_id":"r2","status":"unknown"}]`.

External context: `True`; basis `all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation`.

## rd-vi-reviewed-scope-limitations

Ground Truth ghi nhận những giới hạn nào đối với phạm vi bằng chứng đã review?

Expected: `proceed`; category `relevant_direct`; language `vi`.

| Arm | Scope | Parser/support | Decision | Reason codes |
| --- | --- | --- | --- | --- |
| E0 | unspecified | supported/supported | abstain | legacy_quality_gate_abstained |
| E1 | unspecified | supported/supported | abstain | legacy_quality_gate_abstained |
| E2 | unspecified | supported/supported | proceed | — |
| E3 | unspecified | supported/supported | proceed | — |
| E4 | unspecified | supported/supported | proceed | — |

E4 requirements: `[{"analysis_status":"supported","kind":"review_limitations","parameters":{"facets":["all"]},"requirement_id":"r1"}]`.

E4 support detail: `[{"completeness":{"reason_codes":["requested_source_identity_set_present"],"status":"complete"},"contradiction":{"reason_codes":[],"status":"none_detected"},"reason_codes":["exact_requested_review_source_identities_supported"],"requirement_id":"r1","status":"supported"}]`.

External context: `True`; basis `all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation`.

## rd-vi-initial-relation-provenance

Nguồn log và raw record references nào hỗ trợ quan hệ cmd.exe tạo mshta.exe?

Expected: `proceed`; category `relevant_direct`; language `vi`.

| Arm | Scope | Parser/support | Decision | Reason codes |
| --- | --- | --- | --- | --- |
| E0 | unspecified | supported/supported | abstain | legacy_quality_gate_abstained |
| E1 | unspecified | supported/supported | abstain | legacy_quality_gate_abstained |
| E2 | unspecified | supported/supported | proceed | — |
| E3 | unspecified | supported/supported | proceed | — |
| E4 | unspecified | supported/supported | proceed | — |

E4 requirements: `[{"analysis_status":"supported","kind":"process_relationship","parameters":{"chain":false,"child":"mshta.exe","parent":"cmd.exe"},"requirement_id":"r1"},{"analysis_status":"supported","kind":"evidence_provenance","parameters":{"process":"mshta.exe"},"requirement_id":"r2"}]`.

E4 support detail: `[{"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"reason_codes":["directed_process_creation_supported"],"requirement_id":"r1","status":"supported"},{"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"reason_codes":["associated_original_observation_provenance_supported"],"requirement_id":"r2","status":"supported"}]`.

External context: `True`; basis `all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation`.

## rp-en-intermediate-utility

Which Windows utility sits between the initial command interpreter and the final shell?

Expected: `proceed`; category `relevant_paraphrase`; language `en`.

| Arm | Scope | Parser/support | Decision | Reason codes |
| --- | --- | --- | --- | --- |
| E0 | in_scope | unsupported/unknown | abstain | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained |
| E1 | in_scope | unsupported/unknown | abstain | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained |
| E2 | in_scope | unsupported/unknown | abstain | query_requirements_unsupported, mandatory_requirements_empty |
| E3 | in_scope | unsupported/unknown | abstain | query_requirements_unsupported, mandatory_requirements_empty |
| E4 | in_scope | unsupported/unknown | abstain | query_requirements_unsupported, mandatory_requirements_empty |

E4 requirements: `[]`.

E4 support detail: `[]`.

External context: `True`; basis `all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation`.

## rp-en-shell-creator

How can I trace the launch of the final shell back to its creator?

Expected: `proceed`; category `relevant_paraphrase`; language `en`.

| Arm | Scope | Parser/support | Decision | Reason codes |
| --- | --- | --- | --- | --- |
| E0 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained |
| E1 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown, legacy_quality_gate_abstained |
| E2 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, mandatory_requirements_empty |
| E3 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, mandatory_requirements_empty |
| E4 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, mandatory_requirements_empty |

E4 requirements: `[]`.

E4 support detail: `[]`.

External context: `True`; basis `all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation`.

## rp-en-technique-review

Why is the proxy execution technique still awaiting analyst approval even though its behavior has supporting records?

Expected: `proceed`; category `relevant_paraphrase`; language `en`.

| Arm | Scope | Parser/support | Decision | Reason codes |
| --- | --- | --- | --- | --- |
| E0 | unspecified | supported/supported | abstain | legacy_quality_gate_abstained |
| E1 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown, legacy_quality_gate_abstained |
| E2 | unspecified | supported/supported | abstain | independent_evidence_guard_unknown, required_completeness_unknown, bound_evidence_contradiction_unknown |
| E3 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown, independent_evidence_guard_unknown, mandatory_support_trace_empty, required_evidence_identity_or_source_anchor_missing |
| E4 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown, independent_evidence_guard_unknown, mandatory_support_trace_empty, required_evidence_identity_or_source_anchor_missing |

E4 requirements: `[{"analysis_status":"supported","kind":"process_relationship","parameters":{"chain":true,"child":null,"parent":null},"requirement_id":"r1"},{"analysis_status":"supported","kind":"evidence_provenance","parameters":{"process":null},"requirement_id":"r2"},{"analysis_status":"supported","kind":"technique_assessment","parameters":{"certainty":"assessment","technique_id":null},"requirement_id":"r3"}]`.

E4 support detail: `[{"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"reason_codes":["query_requirement_analysis_not_supported"],"requirement_id":"r1","status":"unknown"},{"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"reason_codes":["query_requirement_analysis_not_supported"],"requirement_id":"r2","status":"unknown"},{"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"reason_codes":["query_requirement_analysis_not_supported"],"requirement_id":"r3","status":"unknown"}]`.

External context: `True`; basis `all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation`.

## rp-en-retained-scripting-label

Why does a scripting technique label remain in the record when the reviewed inline command uses a different scripting language?

Expected: `proceed`; category `relevant_paraphrase`; language `en`.

| Arm | Scope | Parser/support | Decision | Reason codes |
| --- | --- | --- | --- | --- |
| E0 | unspecified | supported/supported | proceed | — |
| E1 | unspecified | supported/supported | proceed | — |
| E2 | unspecified | supported/supported | proceed | — |
| E3 | unspecified | supported/supported | proceed | — |
| E4 | unspecified | supported/supported | proceed | — |

E4 requirements: `[{"analysis_status":"supported","kind":"evidence_provenance","parameters":{"process":null},"requirement_id":"r1"},{"analysis_status":"supported","kind":"technique_assessment","parameters":{"certainty":"assessment","technique_id":null},"requirement_id":"r2"}]`.

E4 support detail: `[{"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"reason_codes":["associated_original_observation_provenance_supported"],"requirement_id":"r1","status":"supported"},{"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"reason_codes":["technique_assessment_status_preserved"],"requirement_id":"r2","status":"supported"}]`.

External context: `True`; basis `all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation`.

## rp-vi-launch-order

Nhìn các quan hệ cha-con đã lưu, làm thế nào dựng lại thứ tự khởi chạy ba tiến trình?

Expected: `proceed`; category `relevant_paraphrase`; language `vi`.

| Arm | Scope | Parser/support | Decision | Reason codes |
| --- | --- | --- | --- | --- |
| E0 | unspecified | supported/supported | abstain | legacy_quality_gate_abstained |
| E1 | unspecified | supported/unknown | abstain | required_evidence_unknown, legacy_quality_gate_abstained |
| E2 | unspecified | supported/supported | abstain | independent_evidence_guard_unknown, required_completeness_unknown, bound_evidence_contradiction_unknown |
| E3 | unspecified | supported/unknown | abstain | required_evidence_unknown, independent_evidence_guard_unknown, mandatory_support_trace_empty, required_evidence_identity_or_source_anchor_missing, required_completeness_unknown, bound_evidence_contradiction_unknown |
| E4 | unspecified | supported/unknown | abstain | required_evidence_unknown, independent_evidence_guard_unknown, mandatory_support_trace_empty, required_evidence_identity_or_source_anchor_missing, required_completeness_unknown, bound_evidence_contradiction_unknown |

E4 requirements: `[{"analysis_status":"supported","kind":"process_relationship","parameters":{"chain":true,"child":null,"parent":null},"requirement_id":"r1"}]`.

E4 support detail: `[{"completeness":{"reason_codes":["chain_target_not_bound"],"status":"unknown"},"contradiction":{"reason_codes":[],"status":"unknown"},"reason_codes":["chain_target_not_bound"],"requirement_id":"r1","status":"unknown"}]`.

External context: `True`; basis `all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation`.

## rp-vi-observation-provenance

Những bản ghi telemetry nào cùng làm căn cứ cho mỗi lần tạo tiến trình trong hai nhóm bằng chứng?

Expected: `proceed`; category `relevant_paraphrase`; language `vi`.

| Arm | Scope | Parser/support | Decision | Reason codes |
| --- | --- | --- | --- | --- |
| E0 | unspecified | supported/supported | abstain | legacy_quality_gate_abstained |
| E1 | unspecified | supported/unknown | abstain | required_evidence_unknown, legacy_quality_gate_abstained |
| E2 | unspecified | supported/supported | abstain | independent_evidence_guard_unknown, required_completeness_unknown, bound_evidence_contradiction_unknown |
| E3 | unspecified | supported/unknown | abstain | required_evidence_unknown, independent_evidence_guard_unknown, mandatory_support_trace_empty, required_evidence_identity_or_source_anchor_missing, required_completeness_unknown, bound_evidence_contradiction_unknown |
| E4 | unspecified | supported/unknown | abstain | required_evidence_unknown, independent_evidence_guard_unknown, mandatory_support_trace_empty, required_evidence_identity_or_source_anchor_missing, required_completeness_unknown, bound_evidence_contradiction_unknown |

E4 requirements: `[{"analysis_status":"supported","kind":"process_relationship","parameters":{"chain":true,"child":null,"parent":null},"requirement_id":"r1"},{"analysis_status":"supported","kind":"evidence_provenance","parameters":{"process":null},"requirement_id":"r2"}]`.

E4 support detail: `[{"completeness":{"reason_codes":["chain_target_not_bound"],"status":"unknown"},"contradiction":{"reason_codes":[],"status":"unknown"},"reason_codes":["chain_target_not_bound"],"requirement_id":"r1","status":"unknown"},{"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"reason_codes":["associated_original_observation_provenance_supported"],"requirement_id":"r2","status":"supported"}]`.

External context: `True`; basis `all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation`.

## rp-vi-final-review-limits

Người phân tích còn phải xem lại điều gì trước khi đưa ra nhận định cuối cùng?

Expected: `proceed`; category `relevant_paraphrase`; language `vi`.

| Arm | Scope | Parser/support | Decision | Reason codes |
| --- | --- | --- | --- | --- |
| E0 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained |
| E1 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained |
| E2 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, mandatory_requirements_empty |
| E3 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, mandatory_requirements_empty |
| E4 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, mandatory_requirements_empty |

E4 requirements: `[]`.

E4 support detail: `[]`.

External context: `False`; basis `known_required_information_missing_from_actual_returned_context`.

## rp-vi-service-action

Lệnh liên quan đến dịch vụ được ghi nhận trên command line khi PowerShell được khởi chạy là gì?

Expected: `proceed`; category `relevant_paraphrase`; language `vi`.

| Arm | Scope | Parser/support | Decision | Reason codes |
| --- | --- | --- | --- | --- |
| E0 | unspecified | supported/supported | abstain | legacy_quality_gate_abstained |
| E1 | unspecified | supported/supported | abstain | legacy_quality_gate_abstained |
| E2 | unspecified | supported/supported | proceed | — |
| E3 | unspecified | supported/supported | proceed | — |
| E4 | unspecified | supported/supported | proceed | — |

E4 requirements: `[{"analysis_status":"supported","kind":"launch_command","parameters":{"process":"powershell.exe"},"requirement_id":"r1"}]`.

E4 support detail: `[{"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"reason_codes":["original_launch_command_supported_only"],"requirement_id":"r1","status":"supported"}]`.

External context: `None`; basis `semantic_context_sufficiency_unassessed_conservative_screen_incomplete`.

## ie-en-payload-download-url

Which URL did PowerShell use to download the payload in this MSHTA chain?

Expected: `abstain`; category `insufficient_evidence`; language `en`.

| Arm | Scope | Parser/support | Decision | Reason codes |
| --- | --- | --- | --- | --- |
| E0 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown |
| E1 | unspecified | supported/missing | abstain | required_evidence_missing |
| E2 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown, independent_evidence_guard_unknown, mandatory_support_trace_empty, required_evidence_identity_or_source_anchor_missing |
| E3 | unspecified | supported/missing | abstain | required_evidence_missing, independent_evidence_guard_missing, mandatory_support_trace_empty, required_evidence_identity_or_source_anchor_missing |
| E4 | unspecified | supported/missing | abstain | required_evidence_missing, independent_evidence_guard_missing, mandatory_support_trace_empty, required_evidence_identity_or_source_anchor_missing |

E4 requirements: `[{"analysis_status":"supported","kind":"network_url","parameters":{"action":"download","actor":"powershell.exe","field":"url"},"requirement_id":"r1"}]`.

E4 support detail: `[{"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"reason_codes":["bound_actor_action_endpoint_not_returned"],"requirement_id":"r1","status":"missing"}]`.

External context: `False`; basis `approved_category_marks_requested_assertion_unsupported_not_scope_explanation`.

## ie-en-c2-address

What IP address acted as the C2 server for the PowerShell process?

Expected: `abstain`; category `insufficient_evidence`; language `en`.

| Arm | Scope | Parser/support | Decision | Reason codes |
| --- | --- | --- | --- | --- |
| E0 | unspecified | supported/missing | abstain | required_evidence_missing, legacy_quality_gate_abstained |
| E1 | unspecified | supported/missing | abstain | required_evidence_missing, legacy_quality_gate_abstained |
| E2 | unspecified | supported/missing | abstain | required_evidence_missing, independent_evidence_guard_missing, mandatory_support_trace_empty, required_evidence_identity_or_source_anchor_missing |
| E3 | unspecified | supported/missing | abstain | required_evidence_missing, independent_evidence_guard_missing, mandatory_support_trace_empty, required_evidence_identity_or_source_anchor_missing |
| E4 | unspecified | supported/missing | abstain | required_evidence_missing, independent_evidence_guard_missing, mandatory_support_trace_empty, required_evidence_identity_or_source_anchor_missing |

E4 requirements: `[{"analysis_status":"supported","kind":"network_url","parameters":{"action":"network","actor":"powershell.exe","field":"endpoint"},"requirement_id":"r1"}]`.

E4 support detail: `[{"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"reason_codes":["bound_actor_action_endpoint_not_returned"],"requirement_id":"r1","status":"missing"}]`.

External context: `False`; basis `approved_category_marks_requested_assertion_unsupported_not_scope_explanation`.

## ie-en-attacker-identity

Who was the attacker responsible for the reviewed MSHTA execution?

Expected: `abstain`; category `insufficient_evidence`; language `en`.

| Arm | Scope | Parser/support | Decision | Reason codes |
| --- | --- | --- | --- | --- |
| E0 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown, legacy_quality_gate_abstained |
| E1 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown, legacy_quality_gate_abstained |
| E2 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, mandatory_requirements_empty |
| E3 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, mandatory_requirements_empty |
| E4 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, mandatory_requirements_empty |

E4 requirements: `[]`.

E4 support detail: `[]`.

External context: `False`; basis `approved_category_marks_requested_assertion_unsupported_not_scope_explanation`.

## ie-en-stolen-credentials

Which credentials did PowerShell steal during this activity?

Expected: `abstain`; category `insufficient_evidence`; language `en`.

| Arm | Scope | Parser/support | Decision | Reason codes |
| --- | --- | --- | --- | --- |
| E0 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained |
| E1 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained |
| E2 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, mandatory_requirements_empty |
| E3 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, mandatory_requirements_empty |
| E4 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, mandatory_requirements_empty |

E4 requirements: `[]`.

E4 support detail: `[]`.

External context: `False`; basis `approved_category_marks_requested_assertion_unsupported_not_scope_explanation`.

## ie-vi-destructive-files

Trong hai nhóm process-creation evidence của ground truth, có bằng chứng nào cho thấy payload PowerShell cố ý phá hoại tệp không?

Expected: `abstain`; category `insufficient_evidence`; language `vi`.

| Arm | Scope | Parser/support | Decision | Reason codes |
| --- | --- | --- | --- | --- |
| E0 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown, legacy_quality_gate_abstained |
| E1 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown, legacy_quality_gate_abstained |
| E2 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown, independent_evidence_guard_unknown, mandatory_support_trace_empty, required_evidence_identity_or_source_anchor_missing |
| E3 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown, independent_evidence_guard_unknown, mandatory_support_trace_empty, required_evidence_identity_or_source_anchor_missing |
| E4 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown, independent_evidence_guard_unknown, mandatory_support_trace_empty, required_evidence_identity_or_source_anchor_missing |

E4 requirements: `[{"analysis_status":"supported","kind":"evidence_provenance","parameters":{"process":"powershell.exe"},"requirement_id":"r1"}]`.

E4 support detail: `[{"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"reason_codes":["query_requirement_analysis_not_supported"],"requirement_id":"r1","status":"unknown"}]`.

External context: `False`; basis `approved_category_marks_requested_assertion_unsupported_not_scope_explanation`.

## ie-vi-decoded-content

Nội dung payload đã được MSHTA hoặc PowerShell giải mã là gì?

Expected: `abstain`; category `insufficient_evidence`; language `vi`.

| Arm | Scope | Parser/support | Decision | Reason codes |
| --- | --- | --- | --- | --- |
| E0 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained |
| E1 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained |
| E2 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, mandatory_requirements_empty |
| E3 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, mandatory_requirements_empty |
| E4 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, mandatory_requirements_empty |

E4 requirements: `[]`.

E4 support detail: `[]`.

External context: `False`; basis `approved_category_marks_requested_assertion_unsupported_not_scope_explanation`.

## ie-vi-decoding-proof

Bằng chứng nào chứng minh T1140 đã xảy ra trong chuỗi MSHTA?

Expected: `abstain`; category `insufficient_evidence`; language `vi`.

| Arm | Scope | Parser/support | Decision | Reason codes |
| --- | --- | --- | --- | --- |
| E0 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown, legacy_quality_gate_abstained |
| E1 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown, legacy_quality_gate_abstained |
| E2 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown, independent_evidence_guard_unknown, mandatory_support_trace_empty, required_evidence_identity_or_source_anchor_missing |
| E3 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown, independent_evidence_guard_unknown, mandatory_support_trace_empty, required_evidence_identity_or_source_anchor_missing |
| E4 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown, independent_evidence_guard_unknown, mandatory_support_trace_empty, required_evidence_identity_or_source_anchor_missing |

E4 requirements: `[{"analysis_status":"ambiguous","kind":"process_relationship","parameters":{"chain":true,"child":null,"parent":null},"requirement_id":"r1"},{"analysis_status":"supported","kind":"evidence_provenance","parameters":{"process":null},"requirement_id":"r2"},{"analysis_status":"supported","kind":"technique_assessment","parameters":{"certainty":"assessment","technique_id":"T1140"},"requirement_id":"r3"}]`.

E4 support detail: `[{"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"reason_codes":["query_requirement_analysis_not_supported"],"requirement_id":"r1","status":"unknown"},{"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"reason_codes":["query_requirement_analysis_not_supported"],"requirement_id":"r2","status":"unknown"},{"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"reason_codes":["query_requirement_analysis_not_supported"],"requirement_id":"r3","status":"unknown"}]`.

External context: `False`; basis `approved_category_marks_requested_assertion_unsupported_not_scope_explanation`.

## ie-vi-certain-attack-determination

Có thể khẳng định chắc chắn toàn bộ chuỗi cmd.exe, mshta.exe và powershell.exe là một cuộc tấn công không?

Expected: `abstain`; category `insufficient_evidence`; language `vi`.

| Arm | Scope | Parser/support | Decision | Reason codes |
| --- | --- | --- | --- | --- |
| E0 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown, legacy_quality_gate_abstained |
| E1 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown, legacy_quality_gate_abstained |
| E2 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown, independent_evidence_guard_unknown, mandatory_support_trace_empty, required_evidence_identity_or_source_anchor_missing |
| E3 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown, independent_evidence_guard_unknown, mandatory_support_trace_empty, required_evidence_identity_or_source_anchor_missing |
| E4 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown, independent_evidence_guard_unknown, mandatory_support_trace_empty, required_evidence_identity_or_source_anchor_missing |

E4 requirements: `[{"analysis_status":"ambiguous","kind":"process_relationship","parameters":{"chain":true,"child":null,"parent":null},"requirement_id":"r1"}]`.

E4 support detail: `[{"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"reason_codes":["query_requirement_analysis_not_supported"],"requirement_id":"r1","status":"unknown"}]`.

External context: `False`; basis `approved_category_marks_requested_assertion_unsupported_not_scope_explanation`.

## ur-en-weather

What will the weather be in Hanoi tomorrow?

Expected: `abstain`; category `unrelated`; language `en`.

| Arm | Scope | Parser/support | Decision | Reason codes |
| --- | --- | --- | --- | --- |
| E0 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained |
| E1 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained |
| E2 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, mandatory_requirements_empty |
| E3 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, mandatory_requirements_empty |
| E4 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, mandatory_requirements_empty |

E4 requirements: `[]`.

E4 support detail: `[]`.

External context: `None`; basis `outside_scope_answerability_not_applicable`.

## ur-en-product-price

What is the current price of a gaming laptop?

Expected: `abstain`; category `unrelated`; language `en`.

| Arm | Scope | Parser/support | Decision | Reason codes |
| --- | --- | --- | --- | --- |
| E0 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained |
| E1 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained |
| E2 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, mandatory_requirements_empty |
| E3 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, mandatory_requirements_empty |
| E4 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, mandatory_requirements_empty |

E4 requirements: `[]`.

E4 support detail: `[]`.

External context: `None`; basis `outside_scope_answerability_not_applicable`.

## ur-en-linux-cron

How do I schedule a Linux cron job to run every ten minutes?

Expected: `abstain`; category `unrelated`; language `en`.

| Arm | Scope | Parser/support | Decision | Reason codes |
| --- | --- | --- | --- | --- |
| E0 | mismatch | unsupported/unknown | abstain | requested_scope_mismatch, query_requirements_unsupported, required_evidence_unknown |
| E1 | mismatch | unsupported/unknown | abstain | requested_scope_mismatch, query_requirements_unsupported, required_evidence_unknown |
| E2 | mismatch | unsupported/unknown | abstain | requested_scope_mismatch, query_requirements_unsupported, mandatory_requirements_empty |
| E3 | mismatch | unsupported/unknown | abstain | requested_scope_mismatch, query_requirements_unsupported, mandatory_requirements_empty |
| E4 | mismatch | unsupported/unknown | abstain | requested_scope_mismatch, query_requirements_unsupported, mandatory_requirements_empty |

E4 requirements: `[]`.

E4 support detail: `[]`.

External context: `None`; basis `outside_scope_answerability_not_applicable`.

## ur-en-sql-injection

How can I prevent SQL injection in a web application's database queries?

Expected: `abstain`; category `unrelated`; language `en`.

| Arm | Scope | Parser/support | Decision | Reason codes |
| --- | --- | --- | --- | --- |
| E0 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained |
| E1 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained |
| E2 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, mandatory_requirements_empty |
| E3 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, mandatory_requirements_empty |
| E4 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, mandatory_requirements_empty |

E4 requirements: `[]`.

E4 support detail: `[]`.

External context: `None`; basis `outside_scope_answerability_not_applicable`.

## ur-vi-ransomware-encryption

Mã hóa ransomware xử lý các khóa mật mã như thế nào?

Expected: `abstain`; category `unrelated`; language `vi`.

| Arm | Scope | Parser/support | Decision | Reason codes |
| --- | --- | --- | --- | --- |
| E0 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained |
| E1 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained |
| E2 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, mandatory_requirements_empty |
| E3 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, mandatory_requirements_empty |
| E4 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, mandatory_requirements_empty |

E4 requirements: `[]`.

E4 support detail: `[]`.

External context: `None`; basis `outside_scope_answerability_not_applicable`.

## ur-vi-kubernetes-configuration

Cần cấu hình Kubernetes thế nào để tự động mở rộng một Deployment?

Expected: `abstain`; category `unrelated`; language `vi`.

| Arm | Scope | Parser/support | Decision | Reason codes |
| --- | --- | --- | --- | --- |
| E0 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained |
| E1 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained |
| E2 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, mandatory_requirements_empty |
| E3 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, mandatory_requirements_empty |
| E4 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, mandatory_requirements_empty |

E4 requirements: `[]`.

E4 support detail: `[]`.

External context: `None`; basis `outside_scope_answerability_not_applicable`.

## ur-vi-literature-learning

Làm thế nào phân biệt hình ảnh ẩn dụ và hoán dụ trong một bài thơ?

Expected: `abstain`; category `unrelated`; language `vi`.

| Arm | Scope | Parser/support | Decision | Reason codes |
| --- | --- | --- | --- | --- |
| E0 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained |
| E1 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained |
| E2 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, mandatory_requirements_empty |
| E3 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, mandatory_requirements_empty |
| E4 | unspecified | unsupported/unknown | abstain | query_requirements_unsupported, mandatory_requirements_empty |

E4 requirements: `[]`.

E4 support detail: `[]`.

External context: `None`; basis `outside_scope_answerability_not_applicable`.

## ur-vi-opaque-token

Chuỗi velora_quartz_token_483920761 có ý nghĩa gì?

Expected: `abstain`; category `unrelated`; language `vi`.

| Arm | Scope | Parser/support | Decision | Reason codes |
| --- | --- | --- | --- | --- |
| E0 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown, legacy_quality_gate_abstained |
| E1 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown, legacy_quality_gate_abstained |
| E2 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown, independent_evidence_guard_unknown, mandatory_support_trace_empty, required_evidence_identity_or_source_anchor_missing |
| E3 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown, independent_evidence_guard_unknown, mandatory_support_trace_empty, required_evidence_identity_or_source_anchor_missing |
| E4 | unspecified | ambiguous/unknown | abstain | query_requirements_ambiguous, required_evidence_unknown, independent_evidence_guard_unknown, mandatory_support_trace_empty, required_evidence_identity_or_source_anchor_missing |

E4 requirements: `[{"analysis_status":"ambiguous","kind":"process_relationship","parameters":{"chain":true,"child":null,"parent":null},"requirement_id":"r1"}]`.

E4 support detail: `[{"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"reason_codes":["query_requirement_analysis_not_supported"],"requirement_id":"r1","status":"unknown"}]`.

External context: `None`; basis `outside_scope_answerability_not_applicable`.
