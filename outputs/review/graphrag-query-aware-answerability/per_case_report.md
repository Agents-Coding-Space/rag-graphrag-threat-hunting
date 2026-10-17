# FIX2 — Per-case review

Report này đọc artifacts đánh giá sau runtime; case IDs, dataset labels, categories và answer units chỉ dùng ở phần review này. Support trace là diagnostic của checker mới, không phải Ground Truth hoặc semantic evaluator độc lập. Trace dưới đây hiển thị tối đa ba trường đầu cho mỗi requirement; toàn bộ traces nằm trong decisions.json.

Artifacts đầy đủ: [requirements](../../experiments/graphrag-2d3-fix2/query_requirements.json), [base contexts](../../experiments/graphrag-2d3-fix2/base_evidence_contexts.json), [enriched contexts](../../experiments/graphrag-2d3-fix2/enriched_contexts.json), [signals](../../experiments/graphrag-2d3-fix2/signals.json), [decisions và support traces](../../experiments/graphrag-2d3-fix2/decisions.json), [external adjudication](../../experiments/graphrag-2d3-fix2/external_context_adjudication.json).

Ranked retrieval/context và fixed policy giống nhau cho A/B/C/D. B/D tính lại ranked signals từ initial_context, bổ sung diagnostics riêng; supplementary items không nhận retrieval scores hoặc traversal paths. C/D giữ điều kiện AND với legacy proceed. 32 cases là development cases, không phải held-out.

| Case | Dataset | A/B | C/D | Context ngoài A→D | Parser / scope / support D | Supplement items |
| --- | --- | --- | --- | --- | --- | ---: |
| `rd-en-process-chain` | proceed | proceed | abstain | True → True | ambiguous / unspecified / unknown | 0 |
| `rd-en-shell-parent` | proceed | proceed | proceed | True → True | supported / unspecified / supported | 0 |
| `rd-en-initial-spawn-evidence` | proceed | proceed | abstain | True → True | ambiguous / unspecified / unknown | 0 |
| `rd-en-final-spawn-evidence` | proceed | proceed | abstain | True → True | ambiguous / unspecified / unknown | 0 |
| `rd-vi-proxy-technique-assessment` | proceed | abstain | abstain | True → True | supported / unspecified / supported | 0 |
| `rd-vi-scripting-technique-status` | proceed | abstain | abstain | True → True | ambiguous / unspecified / unknown | 1 |
| `rd-vi-reviewed-scope-limitations` | proceed | abstain | abstain | None (unknown/N/A) → True | supported / unspecified / supported | 6 |
| `rd-vi-initial-relation-provenance` | proceed | abstain | abstain | True → True | supported / unspecified / supported | 0 |
| `rp-en-intermediate-utility` | proceed | abstain | abstain | True → True | unsupported / in_scope / unknown | 0 |
| `rp-en-shell-creator` | proceed | abstain | abstain | True → True | unsupported / unspecified / unknown | 0 |
| `rp-en-technique-review` | proceed | abstain | abstain | True → True | supported / unspecified / supported | 3 |
| `rp-en-retained-scripting-label` | proceed | proceed | proceed | True → True | supported / unspecified / supported | 1 |
| `rp-vi-launch-order` | proceed | abstain | abstain | True → True | supported / unspecified / supported | 0 |
| `rp-vi-observation-provenance` | proceed | abstain | abstain | True → True | supported / unspecified / supported | 2 |
| `rp-vi-final-review-limits` | proceed | abstain | abstain | False → False | unsupported / unspecified / unknown | 0 |
| `rp-vi-service-action` | proceed | abstain | abstain | None (unknown/N/A) → None (unknown/N/A) | supported / unspecified / supported | 0 |
| `ie-en-payload-download-url` | abstain | proceed | abstain | False → False | ambiguous / unspecified / unknown | 2 |
| `ie-en-c2-address` | abstain | abstain | abstain | False → False | supported / unspecified / missing | 0 |
| `ie-en-attacker-identity` | abstain | abstain | abstain | False → False | ambiguous / unspecified / unknown | 0 |
| `ie-en-stolen-credentials` | abstain | abstain | abstain | False → False | unsupported / unspecified / unknown | 0 |
| `ie-vi-destructive-files` | abstain | abstain | abstain | False → False | ambiguous / unspecified / unknown | 0 |
| `ie-vi-decoded-content` | abstain | abstain | abstain | False → False | unsupported / unspecified / unknown | 0 |
| `ie-vi-decoding-proof` | abstain | abstain | abstain | False → False | ambiguous / unspecified / unknown | 1 |
| `ie-vi-certain-attack-determination` | abstain | abstain | abstain | False → False | ambiguous / unspecified / unknown | 0 |
| `ur-en-weather` | abstain | abstain | abstain | None (unknown/N/A) → None (unknown/N/A) | unsupported / unspecified / unknown | 0 |
| `ur-en-product-price` | abstain | abstain | abstain | None (unknown/N/A) → None (unknown/N/A) | unsupported / unspecified / unknown | 0 |
| `ur-en-linux-cron` | abstain | proceed | abstain | None (unknown/N/A) → None (unknown/N/A) | unsupported / mismatch / unknown | 0 |
| `ur-en-sql-injection` | abstain | abstain | abstain | None (unknown/N/A) → None (unknown/N/A) | unsupported / unspecified / unknown | 0 |
| `ur-vi-ransomware-encryption` | abstain | abstain | abstain | None (unknown/N/A) → None (unknown/N/A) | unsupported / unspecified / unknown | 0 |
| `ur-vi-kubernetes-configuration` | abstain | abstain | abstain | None (unknown/N/A) → None (unknown/N/A) | unsupported / unspecified / unknown | 0 |
| `ur-vi-literature-learning` | abstain | abstain | abstain | None (unknown/N/A) → None (unknown/N/A) | unsupported / unspecified / unknown | 0 |
| `ur-vi-opaque-token` | abstain | abstain | abstain | None (unknown/N/A) → None (unknown/N/A) | ambiguous / unspecified / unknown | 0 |

## rd-en-process-chain

Query: Which process chain led to powershell.exe in the reviewed evidence?

Dataset: `relevant_direct`, language `en`, expected `proceed`. Parser `ambiguous`; scope `unspecified`; support D `unknown`.

| Arm | Decision | Stage | Reason codes | External context sufficient |
| --- | --- | --- | --- | --- |
| A | proceed | — | — | True |
| B | proceed | — | — | True |
| C | abstain | query_requirements | query_requirements_ambiguous, required_evidence_unknown | True |
| D | abstain | query_requirements | query_requirements_ambiguous, required_evidence_unknown | True |

Requirements: `[{"analysis": "ambiguous", "id": "r1", "kind": "process_relationship", "parameters": {"chain": true, "child": null, "parent": null}}, {"analysis": "supported", "id": "r2", "kind": "evidence_provenance", "parameters": {"process": "powershell.exe"}}]`.

Evidence context A/C → B/D: 38 → 38 items; 50635 → 50635 canonical serialized UTF-8 bytes. Supplementary 0; incomplete False → False. A/C incomplete có thể do enrichment tắt; xem cut reason, không suy thành budget failure.

Không có supplementary item.

Rubric ngoài A: satisfied `["initial_spawn", "final_spawn"]`; missing/unassessed `[]`.

Rubric ngoài D: satisfied `["initial_spawn", "final_spawn"]`; missing/unassessed `[]`.

Returned evidence IDs (D): `["evidence-b07a5ff4763e629715e6", "evidence-b31714b888d1489a380c"]`. Các IDs xuất hiện trong context không tự bảo đảm đủ đáp án.

| Requirement | Support | Reason codes | Trace fields |
| --- | --- | --- | ---: |
| r1 / process_relationship | unknown | query_requirement_analysis_not_supported | 0 |
| r2 / evidence_provenance | unknown | query_requirement_analysis_not_supported | 0 |

Legacy quality diagnostic D: `[]`. Support diagnostics D: `["mandatory_requirement_support_unknown"]`.

Full trace JSON pointer: `/D/rd-en-process-chain/trace/support_assessment` trong decisions.json. Final decision chỉ là context eligibility; không tạo kết luận an ninh.

## rd-en-shell-parent

Query: Which process is the observed parent of powershell.exe?

Dataset: `relevant_direct`, language `en`, expected `proceed`. Parser `supported`; scope `unspecified`; support D `supported`.

| Arm | Decision | Stage | Reason codes | External context sufficient |
| --- | --- | --- | --- | --- |
| A | proceed | — | — | True |
| B | proceed | — | — | True |
| C | proceed | — | — | True |
| D | proceed | — | — | True |

Requirements: `[{"analysis": "supported", "id": "r1", "kind": "process_relationship", "parameters": {"chain": false, "child": "powershell.exe", "parent": null}}]`.

Evidence context A/C → B/D: 39 → 39 items; 52999 → 52999 canonical serialized UTF-8 bytes. Supplementary 0; incomplete False → False. A/C incomplete có thể do enrichment tắt; xem cut reason, không suy thành budget failure.

Không có supplementary item.

Rubric ngoài A: satisfied `["final_spawn"]`; missing/unassessed `[]`.

Rubric ngoài D: satisfied `["final_spawn"]`; missing/unassessed `[]`.

Returned evidence IDs (D): `["evidence-b07a5ff4763e629715e6", "evidence-b31714b888d1489a380c"]`. Các IDs xuất hiện trong context không tự bảo đảm đủ đáp án.

| Requirement | Support | Reason codes | Trace fields |
| --- | --- | --- | ---: |
| r1 / process_relationship | supported | directed_process_creation_supported | 6 |

Trace mẫu `r1` (tối đa 3 fields):

- `graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` / `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/ParentProcessName`; source `/facts/1`; quote `C:\Windows\System32\mshta.exe`.

  Binding: `{"action": "process_spawn", "object": "powershell.exe", "object_identity": "0x2564", "subject": "mshta.exe", "subject_identity": "0x2ae4"}`.

- `graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` / `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/NewProcessName`; source `/facts/1`; quote `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`.

  Binding: `{"action": "process_spawn", "object": "powershell.exe", "object_identity": "0x2564", "subject": "mshta.exe", "subject_identity": "0x2ae4"}`.

- `graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` / `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/ProcessId`; source `/facts/1`; quote `0x2ae4`.

  Binding: `{"action": "process_spawn", "object": "powershell.exe", "object_identity": "0x2564", "subject": "mshta.exe", "subject_identity": "0x2ae4"}`.

Legacy quality diagnostic D: `[]`. Support diagnostics D: `["all_mandatory_requirements_supported"]`.

Full trace JSON pointer: `/D/rd-en-shell-parent/trace/support_assessment` trong decisions.json. Final decision chỉ là context eligibility; không tạo kết luận an ninh.

## rd-en-initial-spawn-evidence

Query: What evidence supports the cmd.exe to mshta.exe process creation relationship?

Dataset: `relevant_direct`, language `en`, expected `proceed`. Parser `ambiguous`; scope `unspecified`; support D `unknown`.

| Arm | Decision | Stage | Reason codes | External context sufficient |
| --- | --- | --- | --- | --- |
| A | proceed | — | — | True |
| B | proceed | — | — | True |
| C | abstain | query_requirements | query_requirements_ambiguous, required_evidence_unknown | True |
| D | abstain | query_requirements | query_requirements_ambiguous, required_evidence_unknown | True |

Requirements: `[{"analysis": "ambiguous", "id": "r1", "kind": "evidence_provenance", "parameters": {"process": null}}]`.

Evidence context A/C → B/D: 39 → 39 items; 52818 → 52818 canonical serialized UTF-8 bytes. Supplementary 0; incomplete False → False. A/C incomplete có thể do enrichment tắt; xem cut reason, không suy thành budget failure.

Không có supplementary item.

Rubric ngoài A: satisfied `["initial_spawn", "initial_observations"]`; missing/unassessed `[]`.

Rubric ngoài D: satisfied `["initial_spawn", "initial_observations"]`; missing/unassessed `[]`.

Returned evidence IDs (D): `["evidence-b07a5ff4763e629715e6", "evidence-b31714b888d1489a380c"]`. Các IDs xuất hiện trong context không tự bảo đảm đủ đáp án.

| Requirement | Support | Reason codes | Trace fields |
| --- | --- | --- | ---: |
| r1 / evidence_provenance | unknown | query_requirement_analysis_not_supported | 0 |

Legacy quality diagnostic D: `[]`. Support diagnostics D: `["mandatory_requirement_support_unknown"]`.

Full trace JSON pointer: `/D/rd-en-initial-spawn-evidence/trace/support_assessment` trong decisions.json. Final decision chỉ là context eligibility; không tạo kết luận an ninh.

## rd-en-final-spawn-evidence

Query: What evidence supports the mshta.exe to powershell.exe process creation relationship?

Dataset: `relevant_direct`, language `en`, expected `proceed`. Parser `ambiguous`; scope `unspecified`; support D `unknown`.

| Arm | Decision | Stage | Reason codes | External context sufficient |
| --- | --- | --- | --- | --- |
| A | proceed | — | — | True |
| B | proceed | — | — | True |
| C | abstain | query_requirements | query_requirements_ambiguous, required_evidence_unknown | True |
| D | abstain | query_requirements | query_requirements_ambiguous, required_evidence_unknown | True |

Requirements: `[{"analysis": "ambiguous", "id": "r1", "kind": "evidence_provenance", "parameters": {"process": null}}]`.

Evidence context A/C → B/D: 39 → 39 items; 52828 → 52828 canonical serialized UTF-8 bytes. Supplementary 0; incomplete False → False. A/C incomplete có thể do enrichment tắt; xem cut reason, không suy thành budget failure.

Không có supplementary item.

Rubric ngoài A: satisfied `["final_spawn", "final_observations"]`; missing/unassessed `[]`.

Rubric ngoài D: satisfied `["final_spawn", "final_observations"]`; missing/unassessed `[]`.

Returned evidence IDs (D): `["evidence-b07a5ff4763e629715e6", "evidence-b31714b888d1489a380c"]`. Các IDs xuất hiện trong context không tự bảo đảm đủ đáp án.

| Requirement | Support | Reason codes | Trace fields |
| --- | --- | --- | ---: |
| r1 / evidence_provenance | unknown | query_requirement_analysis_not_supported | 0 |

Legacy quality diagnostic D: `[]`. Support diagnostics D: `["mandatory_requirement_support_unknown"]`.

Full trace JSON pointer: `/D/rd-en-final-spawn-evidence/trace/support_assessment` trong decisions.json. Final decision chỉ là context eligibility; không tạo kết luận an ninh.

## rd-vi-proxy-technique-assessment

Query: Đánh giá hiện tại đối với ATT&CK T1218.005 có mức hỗ trợ bằng chứng và trạng thái review nào?

Dataset: `relevant_direct`, language `vi`, expected `proceed`. Parser `supported`; scope `unspecified`; support D `supported`.

| Arm | Decision | Stage | Reason codes | External context sufficient |
| --- | --- | --- | --- | --- |
| A | abstain | topical_relevance | query_token_coverage_below_threshold, returned_top_cosine_score_below_threshold | True |
| B | abstain | topical_relevance | query_token_coverage_below_threshold, returned_top_cosine_score_below_threshold | True |
| C | abstain | topical_relevance | legacy_quality_gate_abstained | True |
| D | abstain | topical_relevance | legacy_quality_gate_abstained | True |

Requirements: `[{"analysis": "supported", "id": "r1", "kind": "evidence_provenance", "parameters": {"process": null}}, {"analysis": "supported", "id": "r2", "kind": "technique_assessment", "parameters": {"certainty": "assessment", "technique_id": "T1218.005"}}]`.

Evidence context A/C → B/D: 34 → 34 items; 38364 → 38364 canonical serialized UTF-8 bytes. Supplementary 0; incomplete False → False. A/C incomplete có thể do enrichment tắt; xem cut reason, không suy thành budget failure.

Không có supplementary item.

Rubric ngoài A: satisfied `["proxy_assessment"]`; missing/unassessed `[]`.

Rubric ngoài D: satisfied `["proxy_assessment"]`; missing/unassessed `[]`.

Returned evidence IDs (D): `["evidence-b07a5ff4763e629715e6", "evidence-b31714b888d1489a380c"]`. Các IDs xuất hiện trong context không tự bảo đảm đủ đáp án.

| Requirement | Support | Reason codes | Trace fields |
| --- | --- | --- | ---: |
| r1 / evidence_provenance | supported | associated_original_observation_provenance_supported | 7 |
| r2 / technique_assessment | supported | technique_assessment_status_preserved | 5 |

Trace mẫu `r1` (tối đa 3 fields):

- `graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` / `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/Image`; source `/facts/0`; quote `C:\Windows\System32\mshta.exe`.

- `graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` / `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/SourceName`; source `/facts/0`; quote `Microsoft-Windows-Sysmon`.

- `graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` / `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/Channel`; source `/facts/0`; quote `Microsoft-Windows-Sysmon/Operational`.

Trace mẫu `r2` (tối đa 3 fields):

- `retrieval-chunk--8a73d544afa5a8a974c12b905a13224e95e58a8dc73c3a6141ca02c3e2b731e8` / `/final_items/0/payload/mitre_external_ids`; source `/mitre_assessments/2`; quote `["T1218.005"]`.

- `retrieval-chunk--8a73d544afa5a8a974c12b905a13224e95e58a8dc73c3a6141ca02c3e2b731e8` / `/final_items/0/payload/status`; source `/mitre_assessments/2`; quote `candidate`.

- `retrieval-chunk--8a73d544afa5a8a974c12b905a13224e95e58a8dc73c3a6141ca02c3e2b731e8` / `/final_items/0/payload/metadata/evidence_support`; source `/mitre_assessments/2`; quote `supported_by_observed_behavior`.

Legacy quality diagnostic D: `["query_token_coverage_below_threshold", "returned_top_cosine_score_below_threshold"]`. Support diagnostics D: `["all_mandatory_requirements_supported"]`.

Full trace JSON pointer: `/D/rd-vi-proxy-technique-assessment/trace/support_assessment` trong decisions.json. Final decision chỉ là context eligibility; không tạo kết luận an ninh.

## rd-vi-scripting-technique-status

Query: T1059.007 có được hỗ trợ bởi command line đã quan sát không, và trạng thái đánh giá là gì?

Dataset: `relevant_direct`, language `vi`, expected `proceed`. Parser `ambiguous`; scope `unspecified`; support D `unknown`.

| Arm | Decision | Stage | Reason codes | External context sufficient |
| --- | --- | --- | --- | --- |
| A | abstain | topical_relevance | query_token_coverage_below_threshold, returned_top_cosine_score_below_threshold | True |
| B | abstain | topical_relevance | query_token_coverage_below_threshold, returned_top_cosine_score_below_threshold | True |
| C | abstain | query_requirements | query_requirements_ambiguous, required_evidence_unknown, legacy_quality_gate_abstained | True |
| D | abstain | query_requirements | query_requirements_ambiguous, required_evidence_unknown, legacy_quality_gate_abstained | True |

Requirements: `[{"analysis": "supported", "id": "r1", "kind": "launch_command", "parameters": {"process": null}}, {"analysis": "supported", "id": "r2", "kind": "technique_assessment", "parameters": {"certainty": "assessment", "technique_id": "T1059.007"}}]`.

Evidence context A/C → B/D: 39 → 40 items; 60108 → 60995 canonical serialized UTF-8 bytes. Supplementary 1; incomplete True → False. A/C incomplete có thể do enrichment tắt; xem cut reason, không suy thành budget failure.

| Item thêm | Kind / source pointer | Lý do |
| --- | --- | --- |
| `retrieval-chunk--69e16e4937a131ad5d4712b725f21116ae3c14c49b4d72f124980e9c3d90bbaf` | chunk `/summary/limitations/3` | assessment_certainty_limitation |

Rubric ngoài A: satisfied `["scripting_assessment"]`; missing/unassessed `[]`.

Rubric ngoài D: satisfied `["scripting_assessment"]`; missing/unassessed `[]`.

Returned evidence IDs (D): `["evidence-b07a5ff4763e629715e6", "evidence-b31714b888d1489a380c"]`. Các IDs xuất hiện trong context không tự bảo đảm đủ đáp án.

| Requirement | Support | Reason codes | Trace fields |
| --- | --- | --- | ---: |
| r1 / launch_command | unknown | query_requirement_analysis_not_supported | 0 |
| r2 / technique_assessment | unknown | query_requirement_analysis_not_supported | 0 |

Legacy quality diagnostic D: `["query_token_coverage_below_threshold", "returned_top_cosine_score_below_threshold"]`. Support diagnostics D: `["mandatory_requirement_support_unknown"]`.

Full trace JSON pointer: `/D/rd-vi-scripting-technique-status/trace/support_assessment` trong decisions.json. Final decision chỉ là context eligibility; không tạo kết luận an ninh.

## rd-vi-reviewed-scope-limitations

Query: Ground Truth ghi nhận những giới hạn nào đối với phạm vi bằng chứng đã review?

Dataset: `relevant_direct`, language `vi`, expected `proceed`. Parser `supported`; scope `unspecified`; support D `supported`.

| Arm | Decision | Stage | Reason codes | External context sufficient |
| --- | --- | --- | --- | --- |
| A | abstain | topical_relevance | returned_top_cosine_score_below_threshold | None (unknown/N/A) |
| B | abstain | topical_relevance | returned_top_cosine_score_below_threshold | True |
| C | abstain | topical_relevance | legacy_quality_gate_abstained | None (unknown/N/A) |
| D | abstain | topical_relevance | legacy_quality_gate_abstained | True |

Requirements: `[{"analysis": "supported", "id": "r1", "kind": "evidence_provenance", "parameters": {"process": null}}, {"analysis": "supported", "id": "r2", "kind": "review_limitations", "parameters": {"facets": ["scope"]}}]`.

Evidence context A/C → B/D: 34 → 40 items; 38376 → 45272 canonical serialized UTF-8 bytes. Supplementary 6; incomplete True → False. A/C incomplete có thể do enrichment tắt; xem cut reason, không suy thành budget failure.

| Item thêm | Kind / source pointer | Lý do |
| --- | --- | --- |
| `retrieval-chunk--86dd89fe0cfd03c1505a8534ce63dfb9f72221fe32c23d7a0341a66fa98d48ad` | chunk `/scenario` | requested_review_scope_metadata |
| `retrieval-chunk--82de3946302e7f785eef02295ff593ae743fe8820b352255edd7688fde42479c` | chunk `/summary/limitations/1` | requested_limitation_facet |
| `retrieval-chunk--7c8854204807c39fe6d6da4ea799f643abe73976e973f1b6677fd130020af72a` | chunk `/summary/limitations/2` | requested_limitation_facet |
| `retrieval-chunk--df3b8e31f96555994c35b133bba1cc21a226769503fd0a214bef7d3c16d7a1f3` | chunk `/summary/limitations/4` | requested_limitation_facet |
| `retrieval-chunk--81558baf58ca7b808ffd023be3ed3f7bc806f9c12b608733a849786d0a09e571` | chunk `/summary/limitations/5` | requested_limitation_facet |
| `retrieval-chunk--7c3e4f2632332dda121602b7919f6c7f5c6310e4347a0d24a0a9e1c823c4f030` | chunk `/summary/limitations/6` | requested_limitation_facet |

Rubric ngoài A: satisfied `["limitation_0", "limitation_3"]`; missing/unassessed `["limitation_1", "limitation_2", "limitation_4", "limitation_5", "limitation_6"]`.

Rubric ngoài D: satisfied `["limitation_0", "limitation_1", "limitation_2", "limitation_3", "limitation_4", "limitation_5", "limitation_6"]`; missing/unassessed `[]`.

Returned evidence IDs (D): `["evidence-b07a5ff4763e629715e6", "evidence-b31714b888d1489a380c"]`. Các IDs xuất hiện trong context không tự bảo đảm đủ đáp án.

| Requirement | Support | Reason codes | Trace fields |
| --- | --- | --- | ---: |
| r1 / evidence_provenance | supported | associated_original_observation_provenance_supported | 7 |
| r2 / review_limitations | supported | requested_limitation_evidence_supported | 1 |

Trace mẫu `r1` (tối đa 3 fields):

- `graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` / `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/Image`; source `/facts/0`; quote `C:\Windows\System32\mshta.exe`.

- `graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` / `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/SourceName`; source `/facts/0`; quote `Microsoft-Windows-Sysmon`.

- `graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` / `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/Channel`; source `/facts/0`; quote `Microsoft-Windows-Sysmon/Operational`.

Trace mẫu `r2` (tối đa 3 fields):

- `retrieval-chunk--21d69e9c7ff2d03d44ac6d53e1fa234e961f1c743e59c6ffa11289ddcd5e715c` / `/final_items/0/payload/content`; source `/summary/limitations/0`; quote `This ground truth scope covers only the two reviewed behavior and evidence groups.`.

Legacy quality diagnostic D: `["returned_top_cosine_score_below_threshold"]`. Support diagnostics D: `["all_mandatory_requirements_supported"]`.

Full trace JSON pointer: `/D/rd-vi-reviewed-scope-limitations/trace/support_assessment` trong decisions.json. Final decision chỉ là context eligibility; không tạo kết luận an ninh.

## rd-vi-initial-relation-provenance

Query: Nguồn log và raw record references nào hỗ trợ quan hệ cmd.exe tạo mshta.exe?

Dataset: `relevant_direct`, language `vi`, expected `proceed`. Parser `supported`; scope `unspecified`; support D `supported`.

| Arm | Decision | Stage | Reason codes | External context sufficient |
| --- | --- | --- | --- | --- |
| A | abstain | topical_relevance | query_token_coverage_below_threshold | True |
| B | abstain | topical_relevance | query_token_coverage_below_threshold | True |
| C | abstain | topical_relevance | legacy_quality_gate_abstained | True |
| D | abstain | topical_relevance | legacy_quality_gate_abstained | True |

Requirements: `[{"analysis": "supported", "id": "r1", "kind": "process_relationship", "parameters": {"chain": false, "child": "mshta.exe", "parent": "cmd.exe"}}, {"analysis": "supported", "id": "r2", "kind": "evidence_provenance", "parameters": {"process": null}}]`.

Evidence context A/C → B/D: 39 → 39 items; 52625 → 52625 canonical serialized UTF-8 bytes. Supplementary 0; incomplete False → False. A/C incomplete có thể do enrichment tắt; xem cut reason, không suy thành budget failure.

Không có supplementary item.

Rubric ngoài A: satisfied `["initial_observations"]`; missing/unassessed `[]`.

Rubric ngoài D: satisfied `["initial_observations"]`; missing/unassessed `[]`.

Returned evidence IDs (D): `["evidence-b07a5ff4763e629715e6", "evidence-b31714b888d1489a380c"]`. Các IDs xuất hiện trong context không tự bảo đảm đủ đáp án.

| Requirement | Support | Reason codes | Trace fields |
| --- | --- | --- | ---: |
| r1 / process_relationship | supported | directed_process_creation_supported | 6 |
| r2 / evidence_provenance | supported | associated_original_observation_provenance_supported | 7 |

Trace mẫu `r1` (tối đa 3 fields):

- `graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` / `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/ParentImage`; source `/facts/0`; quote `C:\Windows\System32\cmd.exe`.

  Binding: `{"action": "process_spawn", "object": "mshta.exe", "object_identity": "{39e4a257-2d77-5f91-6b13-000000000700}", "subject": "cmd.exe", "subject_identity": "{39e4a257-2d59-5f91-6813-000000000700}"}`.

- `graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` / `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/Image`; source `/facts/0`; quote `C:\Windows\System32\mshta.exe`.

  Binding: `{"action": "process_spawn", "object": "mshta.exe", "object_identity": "{39e4a257-2d77-5f91-6b13-000000000700}", "subject": "cmd.exe", "subject_identity": "{39e4a257-2d59-5f91-6813-000000000700}"}`.

- `graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` / `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/ParentProcessGuid`; source `/facts/0`; quote `{39e4a257-2d59-5f91-6813-000000000700}`.

  Binding: `{"action": "process_spawn", "object": "mshta.exe", "object_identity": "{39e4a257-2d77-5f91-6b13-000000000700}", "subject": "cmd.exe", "subject_identity": "{39e4a257-2d59-5f91-6813-000000000700}"}`.

Trace mẫu `r2` (tối đa 3 fields):

- `graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` / `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/Image`; source `/facts/0`; quote `C:\Windows\System32\mshta.exe`.

- `graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` / `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/SourceName`; source `/facts/0`; quote `Microsoft-Windows-Sysmon`.

- `graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` / `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/Channel`; source `/facts/0`; quote `Microsoft-Windows-Sysmon/Operational`.

Legacy quality diagnostic D: `["query_token_coverage_below_threshold"]`. Support diagnostics D: `["all_mandatory_requirements_supported"]`.

Full trace JSON pointer: `/D/rd-vi-initial-relation-provenance/trace/support_assessment` trong decisions.json. Final decision chỉ là context eligibility; không tạo kết luận an ninh.

## rp-en-intermediate-utility

Query: Which Windows utility sits between the initial command interpreter and the final shell?

Dataset: `relevant_paraphrase`, language `en`, expected `proceed`. Parser `unsupported`; scope `in_scope`; support D `unknown`.

| Arm | Decision | Stage | Reason codes | External context sufficient |
| --- | --- | --- | --- | --- |
| A | abstain | topical_relevance | returned_top_cosine_score_below_threshold | True |
| B | abstain | topical_relevance | returned_top_cosine_score_below_threshold | True |
| C | abstain | query_requirements | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained | True |
| D | abstain | query_requirements | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained | True |

Requirements: `[]`.

Evidence context A/C → B/D: 39 → 39 items; 60108 → 60108 canonical serialized UTF-8 bytes. Supplementary 0; incomplete False → False. A/C incomplete có thể do enrichment tắt; xem cut reason, không suy thành budget failure.

Không có supplementary item.

Rubric ngoài A: satisfied `["initial_spawn", "final_spawn"]`; missing/unassessed `[]`.

Rubric ngoài D: satisfied `["initial_spawn", "final_spawn"]`; missing/unassessed `[]`.

Returned evidence IDs (D): `["evidence-b07a5ff4763e629715e6", "evidence-b31714b888d1489a380c"]`. Các IDs xuất hiện trong context không tự bảo đảm đủ đáp án.

| Requirement | Support | Reason codes | Trace fields |
| --- | --- | --- | ---: |
| — | unknown | Không có mandatory requirement đã phân giải | 0 |

Legacy quality diagnostic D: `["returned_top_cosine_score_below_threshold"]`. Support diagnostics D: `["mandatory_requirement_support_unknown"]`.

Full trace JSON pointer: `/D/rp-en-intermediate-utility/trace/support_assessment` trong decisions.json. Final decision chỉ là context eligibility; không tạo kết luận an ninh.

## rp-en-shell-creator

Query: How can I trace the launch of the final shell back to its creator?

Dataset: `relevant_paraphrase`, language `en`, expected `proceed`. Parser `unsupported`; scope `unspecified`; support D `unknown`.

| Arm | Decision | Stage | Reason codes | External context sufficient |
| --- | --- | --- | --- | --- |
| A | abstain | topical_relevance | returned_top_cosine_score_below_threshold | True |
| B | abstain | topical_relevance | returned_top_cosine_score_below_threshold | True |
| C | abstain | query_requirements | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained | True |
| D | abstain | query_requirements | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained | True |

Requirements: `[]`.

Evidence context A/C → B/D: 34 → 34 items; 40075 → 40075 canonical serialized UTF-8 bytes. Supplementary 0; incomplete False → False. A/C incomplete có thể do enrichment tắt; xem cut reason, không suy thành budget failure.

Không có supplementary item.

Rubric ngoài A: satisfied `["final_spawn", "final_observations"]`; missing/unassessed `[]`.

Rubric ngoài D: satisfied `["final_spawn", "final_observations"]`; missing/unassessed `[]`.

Returned evidence IDs (D): `["evidence-b07a5ff4763e629715e6", "evidence-b31714b888d1489a380c"]`. Các IDs xuất hiện trong context không tự bảo đảm đủ đáp án.

| Requirement | Support | Reason codes | Trace fields |
| --- | --- | --- | ---: |
| — | unknown | Không có mandatory requirement đã phân giải | 0 |

Legacy quality diagnostic D: `["returned_top_cosine_score_below_threshold"]`. Support diagnostics D: `["mandatory_requirement_support_unknown"]`.

Full trace JSON pointer: `/D/rp-en-shell-creator/trace/support_assessment` trong decisions.json. Final decision chỉ là context eligibility; không tạo kết luận an ninh.

## rp-en-technique-review

Query: Why is the proxy execution technique still awaiting analyst approval even though its behavior has supporting records?

Dataset: `relevant_paraphrase`, language `en`, expected `proceed`. Parser `supported`; scope `unspecified`; support D `supported`.

| Arm | Decision | Stage | Reason codes | External context sufficient |
| --- | --- | --- | --- | --- |
| A | abstain | topical_relevance | returned_top_cosine_score_below_threshold | True |
| B | abstain | topical_relevance | returned_top_cosine_score_below_threshold | True |
| C | abstain | topical_relevance | legacy_quality_gate_abstained | True |
| D | abstain | topical_relevance | legacy_quality_gate_abstained | True |

Requirements: `[{"analysis": "supported", "id": "r1", "kind": "process_relationship", "parameters": {"chain": true, "child": null, "parent": null}}, {"analysis": "supported", "id": "r2", "kind": "evidence_provenance", "parameters": {"process": null}}, {"analysis": "supported", "id": "r3", "kind": "technique_assessment", "parameters": {"certainty": "assessment", "technique_id": null}}]`.

Evidence context A/C → B/D: 34 → 37 items; 38530 → 42161 canonical serialized UTF-8 bytes. Supplementary 3; incomplete True → False. A/C incomplete có thể do enrichment tắt; xem cut reason, không suy thành budget failure.

| Item thêm | Kind / source pointer | Lý do |
| --- | --- | --- |
| `retrieval-chunk--ef21f2bc7758f90ce3097c824ea9cfcf382e6fbefcaf03a8cc2c2f2cfa34534f` | chunk `/relationships/0` | requested_process_relationship_evidence |
| `retrieval-chunk--6c81131b41dbfbf7554df2341edc55b3ffeb9da99282a8cde4492bd3a1107365` | chunk `/relationships/1` | requested_process_relationship_evidence |
| `retrieval-chunk--69e16e4937a131ad5d4712b725f21116ae3c14c49b4d72f124980e9c3d90bbaf` | chunk `/summary/limitations/3` | assessment_certainty_limitation |

Rubric ngoài A: satisfied `["proxy_assessment"]`; missing/unassessed `[]`.

Rubric ngoài D: satisfied `["proxy_assessment"]`; missing/unassessed `[]`.

Returned evidence IDs (D): `["evidence-b07a5ff4763e629715e6", "evidence-b31714b888d1489a380c"]`. Các IDs xuất hiện trong context không tự bảo đảm đủ đáp án.

| Requirement | Support | Reason codes | Trace fields |
| --- | --- | --- | ---: |
| r1 / process_relationship | supported | identity_linked_process_chain_supported | 12 |
| r2 / evidence_provenance | supported | associated_original_observation_provenance_supported | 7 |
| r3 / technique_assessment | supported | technique_assessment_status_preserved | 5 |

Trace mẫu `r1` (tối đa 3 fields):

- `graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` / `/final_items/7/payload/attributes/attributes/source_observations/1/original_fields/ParentProcessName`; source `/facts/0`; quote `C:\Windows\System32\cmd.exe`.

  Binding: `{"action": "process_spawn", "object": "mshta.exe", "object_identity": "0x2ae4", "subject": "cmd.exe", "subject_identity": "0x1700"}`.

- `graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` / `/final_items/7/payload/attributes/attributes/source_observations/1/original_fields/NewProcessName`; source `/facts/0`; quote `C:\Windows\System32\mshta.exe`.

  Binding: `{"action": "process_spawn", "object": "mshta.exe", "object_identity": "0x2ae4", "subject": "cmd.exe", "subject_identity": "0x1700"}`.

- `graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` / `/final_items/7/payload/attributes/attributes/source_observations/1/original_fields/ProcessId`; source `/facts/0`; quote `0x1700`.

  Binding: `{"action": "process_spawn", "object": "mshta.exe", "object_identity": "0x2ae4", "subject": "cmd.exe", "subject_identity": "0x1700"}`.

Trace mẫu `r2` (tối đa 3 fields):

- `graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` / `/final_items/7/payload/attributes/attributes/source_observations/0/original_fields/Image`; source `/facts/0`; quote `C:\Windows\System32\mshta.exe`.

- `graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` / `/final_items/7/payload/attributes/attributes/source_observations/0/original_fields/SourceName`; source `/facts/0`; quote `Microsoft-Windows-Sysmon`.

- `graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` / `/final_items/7/payload/attributes/attributes/source_observations/0/original_fields/Channel`; source `/facts/0`; quote `Microsoft-Windows-Sysmon/Operational`.

Trace mẫu `r3` (tối đa 3 fields):

- `retrieval-chunk--8a73d544afa5a8a974c12b905a13224e95e58a8dc73c3a6141ca02c3e2b731e8` / `/final_items/0/payload/mitre_external_ids`; source `/mitre_assessments/2`; quote `["T1218.005"]`.

- `retrieval-chunk--8a73d544afa5a8a974c12b905a13224e95e58a8dc73c3a6141ca02c3e2b731e8` / `/final_items/0/payload/status`; source `/mitre_assessments/2`; quote `candidate`.

- `retrieval-chunk--8a73d544afa5a8a974c12b905a13224e95e58a8dc73c3a6141ca02c3e2b731e8` / `/final_items/0/payload/metadata/evidence_support`; source `/mitre_assessments/2`; quote `supported_by_observed_behavior`.

Legacy quality diagnostic D: `["returned_top_cosine_score_below_threshold"]`. Support diagnostics D: `["all_mandatory_requirements_supported"]`.

Full trace JSON pointer: `/D/rp-en-technique-review/trace/support_assessment` trong decisions.json. Final decision chỉ là context eligibility; không tạo kết luận an ninh.

## rp-en-retained-scripting-label

Query: Why does a scripting technique label remain in the record when the reviewed inline command uses a different scripting language?

Dataset: `relevant_paraphrase`, language `en`, expected `proceed`. Parser `supported`; scope `unspecified`; support D `supported`.

| Arm | Decision | Stage | Reason codes | External context sufficient |
| --- | --- | --- | --- | --- |
| A | proceed | — | — | True |
| B | proceed | — | — | True |
| C | proceed | — | — | True |
| D | proceed | — | — | True |

Requirements: `[{"analysis": "supported", "id": "r1", "kind": "evidence_provenance", "parameters": {"process": null}}, {"analysis": "supported", "id": "r2", "kind": "technique_assessment", "parameters": {"certainty": "assessment", "technique_id": null}}]`.

Evidence context A/C → B/D: 38 → 39 items; 54119 → 55006 canonical serialized UTF-8 bytes. Supplementary 1; incomplete True → False. A/C incomplete có thể do enrichment tắt; xem cut reason, không suy thành budget failure.

| Item thêm | Kind / source pointer | Lý do |
| --- | --- | --- |
| `retrieval-chunk--69e16e4937a131ad5d4712b725f21116ae3c14c49b4d72f124980e9c3d90bbaf` | chunk `/summary/limitations/3` | assessment_certainty_limitation |

Rubric ngoài A: satisfied `["scripting_assessment", "scripting_origin"]`; missing/unassessed `[]`.

Rubric ngoài D: satisfied `["scripting_assessment", "scripting_origin"]`; missing/unassessed `[]`.

Returned evidence IDs (D): `["evidence-b07a5ff4763e629715e6", "evidence-b31714b888d1489a380c"]`. Các IDs xuất hiện trong context không tự bảo đảm đủ đáp án.

| Requirement | Support | Reason codes | Trace fields |
| --- | --- | --- | ---: |
| r1 / evidence_provenance | supported | associated_original_observation_provenance_supported | 7 |
| r2 / technique_assessment | supported | technique_assessment_status_preserved | 5 |

Trace mẫu `r1` (tối đa 3 fields):

- `retrieval-chunk--135ad46ae0c56b905d31ab531d5d565a01412b61f3600ad6b4d9dda6e2eef860` / `/final_items/3/payload/metadata/attributes/source_observations/0/original_fields/NewProcessName`; source `/facts/1`; quote `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`.

- `retrieval-chunk--135ad46ae0c56b905d31ab531d5d565a01412b61f3600ad6b4d9dda6e2eef860` / `/final_items/3/payload/metadata/attributes/source_observations/0/original_fields/SourceName`; source `/facts/1`; quote `Microsoft-Windows-Security-Auditing`.

- `retrieval-chunk--135ad46ae0c56b905d31ab531d5d565a01412b61f3600ad6b4d9dda6e2eef860` / `/final_items/3/payload/metadata/attributes/source_observations/0/original_fields/Channel`; source `/facts/1`; quote `Security`.

Trace mẫu `r2` (tối đa 3 fields):

- `retrieval-chunk--3422a1d86fc13212f395af0f4089875227b0780e91899c42c13023f3a6ff55d8` / `/final_items/0/payload/mitre_external_ids`; source `/mitre_assessments/0`; quote `["T1059.007"]`.

- `retrieval-chunk--3422a1d86fc13212f395af0f4089875227b0780e91899c42c13023f3a6ff55d8` / `/final_items/0/payload/status`; source `/mitre_assessments/0`; quote `candidate`.

- `retrieval-chunk--3422a1d86fc13212f395af0f4089875227b0780e91899c42c13023f3a6ff55d8` / `/final_items/0/payload/metadata/evidence_support`; source `/mitre_assessments/0`; quote `not_supported_by_observed_command`.

Legacy quality diagnostic D: `[]`. Support diagnostics D: `["all_mandatory_requirements_supported"]`.

Full trace JSON pointer: `/D/rp-en-retained-scripting-label/trace/support_assessment` trong decisions.json. Final decision chỉ là context eligibility; không tạo kết luận an ninh.

## rp-vi-launch-order

Query: Nhìn các quan hệ cha-con đã lưu, làm thế nào dựng lại thứ tự khởi chạy ba tiến trình?

Dataset: `relevant_paraphrase`, language `vi`, expected `proceed`. Parser `supported`; scope `unspecified`; support D `supported`.

| Arm | Decision | Stage | Reason codes | External context sufficient |
| --- | --- | --- | --- | --- |
| A | abstain | topical_relevance | query_token_coverage_below_threshold, returned_top_cosine_score_below_threshold | True |
| B | abstain | topical_relevance | query_token_coverage_below_threshold, returned_top_cosine_score_below_threshold | True |
| C | abstain | topical_relevance | legacy_quality_gate_abstained | True |
| D | abstain | topical_relevance | legacy_quality_gate_abstained | True |

Requirements: `[{"analysis": "supported", "id": "r1", "kind": "process_relationship", "parameters": {"chain": true, "child": null, "parent": null}}]`.

Evidence context A/C → B/D: 34 → 34 items; 52516 → 52516 canonical serialized UTF-8 bytes. Supplementary 0; incomplete False → False. A/C incomplete có thể do enrichment tắt; xem cut reason, không suy thành budget failure.

Không có supplementary item.

Rubric ngoài A: satisfied `["initial_spawn", "final_spawn"]`; missing/unassessed `[]`.

Rubric ngoài D: satisfied `["initial_spawn", "final_spawn"]`; missing/unassessed `[]`.

Returned evidence IDs (D): `["evidence-b07a5ff4763e629715e6", "evidence-b31714b888d1489a380c"]`. Các IDs xuất hiện trong context không tự bảo đảm đủ đáp án.

| Requirement | Support | Reason codes | Trace fields |
| --- | --- | --- | ---: |
| r1 / process_relationship | supported | identity_linked_process_chain_supported | 12 |

Trace mẫu `r1` (tối đa 3 fields):

- `retrieval-chunk--bffd78d6601e01f3de6be978d5d7357c1f4d6e90be38b07509bb800d0f23ed5b` / `/final_items/0/payload/metadata/attributes/source_observations/1/original_fields/ParentProcessName`; source `/facts/0`; quote `C:\Windows\System32\cmd.exe`.

  Binding: `{"action": "process_spawn", "object": "mshta.exe", "object_identity": "0x2ae4", "subject": "cmd.exe", "subject_identity": "0x1700"}`.

- `retrieval-chunk--bffd78d6601e01f3de6be978d5d7357c1f4d6e90be38b07509bb800d0f23ed5b` / `/final_items/0/payload/metadata/attributes/source_observations/1/original_fields/NewProcessName`; source `/facts/0`; quote `C:\Windows\System32\mshta.exe`.

  Binding: `{"action": "process_spawn", "object": "mshta.exe", "object_identity": "0x2ae4", "subject": "cmd.exe", "subject_identity": "0x1700"}`.

- `retrieval-chunk--bffd78d6601e01f3de6be978d5d7357c1f4d6e90be38b07509bb800d0f23ed5b` / `/final_items/0/payload/metadata/attributes/source_observations/1/original_fields/ProcessId`; source `/facts/0`; quote `0x1700`.

  Binding: `{"action": "process_spawn", "object": "mshta.exe", "object_identity": "0x2ae4", "subject": "cmd.exe", "subject_identity": "0x1700"}`.

Legacy quality diagnostic D: `["query_token_coverage_below_threshold", "returned_top_cosine_score_below_threshold"]`. Support diagnostics D: `["all_mandatory_requirements_supported"]`.

Full trace JSON pointer: `/D/rp-vi-launch-order/trace/support_assessment` trong decisions.json. Final decision chỉ là context eligibility; không tạo kết luận an ninh.

## rp-vi-observation-provenance

Query: Những bản ghi telemetry nào cùng làm căn cứ cho mỗi lần tạo tiến trình trong hai nhóm bằng chứng?

Dataset: `relevant_paraphrase`, language `vi`, expected `proceed`. Parser `supported`; scope `unspecified`; support D `supported`.

| Arm | Decision | Stage | Reason codes | External context sufficient |
| --- | --- | --- | --- | --- |
| A | abstain | topical_relevance | query_token_coverage_below_threshold, returned_top_cosine_score_below_threshold | True |
| B | abstain | topical_relevance | query_token_coverage_below_threshold, returned_top_cosine_score_below_threshold | True |
| C | abstain | topical_relevance | legacy_quality_gate_abstained | True |
| D | abstain | topical_relevance | legacy_quality_gate_abstained | True |

Requirements: `[{"analysis": "supported", "id": "r1", "kind": "process_relationship", "parameters": {"chain": true, "child": null, "parent": null}}, {"analysis": "supported", "id": "r2", "kind": "evidence_provenance", "parameters": {"process": null}}]`.

Evidence context A/C → B/D: 39 → 41 items; 52299 → 55043 canonical serialized UTF-8 bytes. Supplementary 2; incomplete True → False. A/C incomplete có thể do enrichment tắt; xem cut reason, không suy thành budget failure.

| Item thêm | Kind / source pointer | Lý do |
| --- | --- | --- |
| `retrieval-chunk--ef21f2bc7758f90ce3097c824ea9cfcf382e6fbefcaf03a8cc2c2f2cfa34534f` | chunk `/relationships/0` | requested_process_relationship_evidence |
| `retrieval-chunk--6c81131b41dbfbf7554df2341edc55b3ffeb9da99282a8cde4492bd3a1107365` | chunk `/relationships/1` | requested_process_relationship_evidence |

Rubric ngoài A: satisfied `["initial_observations", "final_observations"]`; missing/unassessed `[]`.

Rubric ngoài D: satisfied `["initial_observations", "final_observations"]`; missing/unassessed `[]`.

Returned evidence IDs (D): `["evidence-b07a5ff4763e629715e6", "evidence-b31714b888d1489a380c"]`. Các IDs xuất hiện trong context không tự bảo đảm đủ đáp án.

| Requirement | Support | Reason codes | Trace fields |
| --- | --- | --- | ---: |
| r1 / process_relationship | supported | identity_linked_process_chain_supported | 12 |
| r2 / evidence_provenance | supported | associated_original_observation_provenance_supported | 7 |

Trace mẫu `r1` (tối đa 3 fields):

- `retrieval-chunk--bffd78d6601e01f3de6be978d5d7357c1f4d6e90be38b07509bb800d0f23ed5b` / `/final_items/4/payload/metadata/attributes/source_observations/1/original_fields/ParentProcessName`; source `/facts/0`; quote `C:\Windows\System32\cmd.exe`.

  Binding: `{"action": "process_spawn", "object": "mshta.exe", "object_identity": "0x2ae4", "subject": "cmd.exe", "subject_identity": "0x1700"}`.

- `retrieval-chunk--bffd78d6601e01f3de6be978d5d7357c1f4d6e90be38b07509bb800d0f23ed5b` / `/final_items/4/payload/metadata/attributes/source_observations/1/original_fields/NewProcessName`; source `/facts/0`; quote `C:\Windows\System32\mshta.exe`.

  Binding: `{"action": "process_spawn", "object": "mshta.exe", "object_identity": "0x2ae4", "subject": "cmd.exe", "subject_identity": "0x1700"}`.

- `retrieval-chunk--bffd78d6601e01f3de6be978d5d7357c1f4d6e90be38b07509bb800d0f23ed5b` / `/final_items/4/payload/metadata/attributes/source_observations/1/original_fields/ProcessId`; source `/facts/0`; quote `0x1700`.

  Binding: `{"action": "process_spawn", "object": "mshta.exe", "object_identity": "0x2ae4", "subject": "cmd.exe", "subject_identity": "0x1700"}`.

Trace mẫu `r2` (tối đa 3 fields):

- `retrieval-chunk--bffd78d6601e01f3de6be978d5d7357c1f4d6e90be38b07509bb800d0f23ed5b` / `/final_items/4/payload/metadata/attributes/source_observations/0/original_fields/Image`; source `/facts/0`; quote `C:\Windows\System32\mshta.exe`.

- `retrieval-chunk--bffd78d6601e01f3de6be978d5d7357c1f4d6e90be38b07509bb800d0f23ed5b` / `/final_items/4/payload/metadata/attributes/source_observations/0/original_fields/SourceName`; source `/facts/0`; quote `Microsoft-Windows-Sysmon`.

- `retrieval-chunk--bffd78d6601e01f3de6be978d5d7357c1f4d6e90be38b07509bb800d0f23ed5b` / `/final_items/4/payload/metadata/attributes/source_observations/0/original_fields/Channel`; source `/facts/0`; quote `Microsoft-Windows-Sysmon/Operational`.

Legacy quality diagnostic D: `["query_token_coverage_below_threshold", "returned_top_cosine_score_below_threshold"]`. Support diagnostics D: `["all_mandatory_requirements_supported"]`.

Full trace JSON pointer: `/D/rp-vi-observation-provenance/trace/support_assessment` trong decisions.json. Final decision chỉ là context eligibility; không tạo kết luận an ninh.

## rp-vi-final-review-limits

Query: Người phân tích còn phải xem lại điều gì trước khi đưa ra nhận định cuối cùng?

Dataset: `relevant_paraphrase`, language `vi`, expected `proceed`. Parser `unsupported`; scope `unspecified`; support D `unknown`.

| Arm | Decision | Stage | Reason codes | External context sufficient |
| --- | --- | --- | --- | --- |
| A | abstain | topical_relevance | query_token_coverage_below_threshold, returned_top_cosine_score_below_threshold | False |
| B | abstain | topical_relevance | query_token_coverage_below_threshold, returned_top_cosine_score_below_threshold | False |
| C | abstain | query_requirements | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained | False |
| D | abstain | query_requirements | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained | False |

Requirements: `[]`.

Evidence context A/C → B/D: 38 → 38 items; 58577 → 58577 canonical serialized UTF-8 bytes. Supplementary 0; incomplete False → False. A/C incomplete có thể do enrichment tắt; xem cut reason, không suy thành budget failure.

Không có supplementary item.

Rubric ngoài A: satisfied `[]`; missing/unassessed `["analysis_status", "limitation_0", "limitation_1", "limitation_2", "limitation_3", "limitation_4"]`.

Rubric ngoài D: satisfied `[]`; missing/unassessed `["analysis_status", "limitation_0", "limitation_1", "limitation_2", "limitation_3", "limitation_4"]`.

- External diagnostic `analysis_status`, `/scenario`: `known_missing` / `required_source_associated_structured_fields_not_returned`.

- External diagnostic `limitation_0`, `/summary/limitations/0`: `unassessed` / `no_exact_limitation_support_semantic_sufficiency_not_established`.

- External diagnostic `limitation_1`, `/summary/limitations/1`: `unassessed` / `no_exact_limitation_support_semantic_sufficiency_not_established`.

- External diagnostic `limitation_2`, `/summary/limitations/2`: `unassessed` / `no_exact_limitation_support_semantic_sufficiency_not_established`.

- External diagnostic `limitation_3`, `/summary/limitations/3`: `unassessed` / `no_exact_limitation_support_semantic_sufficiency_not_established`.

- External diagnostic `limitation_4`, `/summary/limitations/4`: `unassessed` / `no_exact_limitation_support_semantic_sufficiency_not_established`.

Returned evidence IDs (D): `["evidence-b07a5ff4763e629715e6", "evidence-b31714b888d1489a380c"]`. Các IDs xuất hiện trong context không tự bảo đảm đủ đáp án.

| Requirement | Support | Reason codes | Trace fields |
| --- | --- | --- | ---: |
| — | unknown | Không có mandatory requirement đã phân giải | 0 |

Legacy quality diagnostic D: `["query_token_coverage_below_threshold", "returned_top_cosine_score_below_threshold"]`. Support diagnostics D: `["mandatory_requirement_support_unknown"]`.

Full trace JSON pointer: `/D/rp-vi-final-review-limits/trace/support_assessment` trong decisions.json. Final decision chỉ là context eligibility; không tạo kết luận an ninh.

## rp-vi-service-action

Query: Lệnh liên quan đến dịch vụ được ghi nhận trên command line khi PowerShell được khởi chạy là gì?

Dataset: `relevant_paraphrase`, language `vi`, expected `proceed`. Parser `supported`; scope `unspecified`; support D `supported`.

| Arm | Decision | Stage | Reason codes | External context sufficient |
| --- | --- | --- | --- | --- |
| A | abstain | topical_relevance | query_token_coverage_below_threshold, returned_top_cosine_score_below_threshold | None (unknown/N/A) |
| B | abstain | topical_relevance | query_token_coverage_below_threshold, returned_top_cosine_score_below_threshold | None (unknown/N/A) |
| C | abstain | topical_relevance | legacy_quality_gate_abstained | None (unknown/N/A) |
| D | abstain | topical_relevance | legacy_quality_gate_abstained | None (unknown/N/A) |

Requirements: `[{"analysis": "supported", "id": "r1", "kind": "launch_command", "parameters": {"process": "powershell.exe"}}]`.

Evidence context A/C → B/D: 39 → 39 items; 60108 → 60108 canonical serialized UTF-8 bytes. Supplementary 0; incomplete False → False. A/C incomplete có thể do enrichment tắt; xem cut reason, không suy thành budget failure.

Không có supplementary item.

Rubric ngoài A: satisfied `["launch_command"]`; missing/unassessed `["limitation_4"]`.

Rubric ngoài D: satisfied `["launch_command"]`; missing/unassessed `["limitation_4"]`.

- External diagnostic `limitation_4`, `/summary/limitations/4`: `unassessed` / `no_exact_limitation_support_semantic_sufficiency_not_established`.

Returned evidence IDs (D): `["evidence-b07a5ff4763e629715e6", "evidence-b31714b888d1489a380c"]`. Các IDs xuất hiện trong context không tự bảo đảm đủ đáp án.

| Requirement | Support | Reason codes | Trace fields |
| --- | --- | --- | ---: |
| r1 / launch_command | supported | original_launch_command_supported_only | 5 |

Trace mẫu `r1` (tối đa 3 fields):

- `retrieval-chunk--135ad46ae0c56b905d31ab531d5d565a01412b61f3600ad6b4d9dda6e2eef860` / `/final_items/1/payload/metadata/attributes/source_observations/0/original_fields/NewProcessName`; source `/facts/1`; quote `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`.

  Binding: `{"action": "launched_with_command_line", "object": "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -noexit -command Get-Service sysmon", "subject": "powershell.exe", "subject_identity": "0x2564"}`.

- `retrieval-chunk--135ad46ae0c56b905d31ab531d5d565a01412b61f3600ad6b4d9dda6e2eef860` / `/final_items/1/payload/metadata/attributes/source_observations/0/original_fields/NewProcessId`; source `/facts/1`; quote `0x2564`.

  Binding: `{"action": "launched_with_command_line", "object": "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -noexit -command Get-Service sysmon", "subject": "powershell.exe", "subject_identity": "0x2564"}`.

- `retrieval-chunk--135ad46ae0c56b905d31ab531d5d565a01412b61f3600ad6b4d9dda6e2eef860` / `/final_items/1/payload/metadata/attributes/source_observations/0/original_fields/CommandLine`; source `/facts/1`; quote `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -noexit -command Get-Service sysmon`.

  Binding: `{"action": "launched_with_command_line", "object": "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -noexit -command Get-Service sysmon", "subject": "powershell.exe", "subject_identity": "0x2564"}`.

Legacy quality diagnostic D: `["query_token_coverage_below_threshold", "returned_top_cosine_score_below_threshold"]`. Support diagnostics D: `["all_mandatory_requirements_supported"]`.

Full trace JSON pointer: `/D/rp-vi-service-action/trace/support_assessment` trong decisions.json. Final decision chỉ là context eligibility; không tạo kết luận an ninh.

## ie-en-payload-download-url

Query: Which URL did PowerShell use to download the payload in this MSHTA chain?

Dataset: `insufficient_evidence`, language `en`, expected `abstain`. Parser `ambiguous`; scope `unspecified`; support D `unknown`.

| Arm | Decision | Stage | Reason codes | External context sufficient |
| --- | --- | --- | --- | --- |
| A | proceed | — | — | False |
| B | proceed | — | — | False |
| C | abstain | query_requirements | query_requirements_ambiguous, required_evidence_unknown | False |
| D | abstain | query_requirements | query_requirements_ambiguous, required_evidence_unknown | False |

Requirements: `[{"analysis": "supported", "id": "r1", "kind": "process_relationship", "parameters": {"chain": true, "child": "mshta.exe", "parent": "powershell.exe"}}, {"analysis": "ambiguous", "id": "r2", "kind": "network_url", "parameters": {"action": "download", "actor": null, "field": "url"}}]`.

Evidence context A/C → B/D: 40 → 42 items; 60183 → 62927 canonical serialized UTF-8 bytes. Supplementary 2; incomplete True → False. A/C incomplete có thể do enrichment tắt; xem cut reason, không suy thành budget failure.

| Item thêm | Kind / source pointer | Lý do |
| --- | --- | --- |
| `retrieval-chunk--ef21f2bc7758f90ce3097c824ea9cfcf382e6fbefcaf03a8cc2c2f2cfa34534f` | chunk `/relationships/0` | requested_process_relationship_evidence |
| `retrieval-chunk--6c81131b41dbfbf7554df2341edc55b3ffeb9da99282a8cde4492bd3a1107365` | chunk `/relationships/1` | requested_process_relationship_evidence |

Rubric ngoài A: satisfied `[]`; missing/unassessed `[]`.

Rubric ngoài D: satisfied `[]`; missing/unassessed `[]`.

Returned evidence IDs (D): `["evidence-b07a5ff4763e629715e6", "evidence-b31714b888d1489a380c"]`. Các IDs xuất hiện trong context không tự bảo đảm đủ đáp án.

| Requirement | Support | Reason codes | Trace fields |
| --- | --- | --- | ---: |
| r1 / process_relationship | unknown | query_requirement_analysis_not_supported | 0 |
| r2 / network_url | unknown | query_requirement_analysis_not_supported | 0 |

Legacy quality diagnostic D: `[]`. Support diagnostics D: `["mandatory_requirement_support_unknown"]`.

Full trace JSON pointer: `/D/ie-en-payload-download-url/trace/support_assessment` trong decisions.json. Final decision chỉ là context eligibility; không tạo kết luận an ninh.

## ie-en-c2-address

Query: What IP address acted as the C2 server for the PowerShell process?

Dataset: `insufficient_evidence`, language `en`, expected `abstain`. Parser `supported`; scope `unspecified`; support D `missing`.

| Arm | Decision | Stage | Reason codes | External context sufficient |
| --- | --- | --- | --- | --- |
| A | abstain | topical_relevance | returned_top_cosine_score_below_threshold | False |
| B | abstain | topical_relevance | returned_top_cosine_score_below_threshold | False |
| C | abstain | evidence_answerability | required_evidence_missing, legacy_quality_gate_abstained | False |
| D | abstain | evidence_answerability | required_evidence_missing, legacy_quality_gate_abstained | False |

Requirements: `[{"analysis": "supported", "id": "r1", "kind": "network_url", "parameters": {"action": "network", "actor": "powershell.exe", "field": "endpoint"}}]`.

Evidence context A/C → B/D: 39 → 39 items; 55232 → 55232 canonical serialized UTF-8 bytes. Supplementary 0; incomplete False → False. A/C incomplete có thể do enrichment tắt; xem cut reason, không suy thành budget failure.

Không có supplementary item.

Rubric ngoài A: satisfied `[]`; missing/unassessed `[]`.

Rubric ngoài D: satisfied `[]`; missing/unassessed `[]`.

Returned evidence IDs (D): `["evidence-b07a5ff4763e629715e6", "evidence-b31714b888d1489a380c"]`. Các IDs xuất hiện trong context không tự bảo đảm đủ đáp án.

| Requirement | Support | Reason codes | Trace fields |
| --- | --- | --- | ---: |
| r1 / network_url | missing | bound_actor_action_endpoint_not_returned | 0 |

Legacy quality diagnostic D: `["returned_top_cosine_score_below_threshold"]`. Support diagnostics D: `["mandatory_evidence_missing"]`.

Full trace JSON pointer: `/D/ie-en-c2-address/trace/support_assessment` trong decisions.json. Final decision chỉ là context eligibility; không tạo kết luận an ninh.

## ie-en-attacker-identity

Query: Who was the attacker responsible for the reviewed MSHTA execution?

Dataset: `insufficient_evidence`, language `en`, expected `abstain`. Parser `ambiguous`; scope `unspecified`; support D `unknown`.

| Arm | Decision | Stage | Reason codes | External context sufficient |
| --- | --- | --- | --- | --- |
| A | abstain | topical_relevance | returned_top_cosine_score_below_threshold | False |
| B | abstain | topical_relevance | returned_top_cosine_score_below_threshold | False |
| C | abstain | query_requirements | query_requirements_ambiguous, required_evidence_unknown, legacy_quality_gate_abstained | False |
| D | abstain | query_requirements | query_requirements_ambiguous, required_evidence_unknown, legacy_quality_gate_abstained | False |

Requirements: `[]`.

Evidence context A/C → B/D: 33 → 33 items; 40442 → 40442 canonical serialized UTF-8 bytes. Supplementary 0; incomplete False → False. A/C incomplete có thể do enrichment tắt; xem cut reason, không suy thành budget failure.

Không có supplementary item.

Rubric ngoài A: satisfied `[]`; missing/unassessed `[]`.

Rubric ngoài D: satisfied `[]`; missing/unassessed `[]`.

Returned evidence IDs (D): `["evidence-b07a5ff4763e629715e6", "evidence-b31714b888d1489a380c"]`. Các IDs xuất hiện trong context không tự bảo đảm đủ đáp án.

| Requirement | Support | Reason codes | Trace fields |
| --- | --- | --- | ---: |
| — | unknown | Không có mandatory requirement đã phân giải | 0 |

Legacy quality diagnostic D: `["returned_top_cosine_score_below_threshold"]`. Support diagnostics D: `["mandatory_requirement_support_unknown"]`.

Full trace JSON pointer: `/D/ie-en-attacker-identity/trace/support_assessment` trong decisions.json. Final decision chỉ là context eligibility; không tạo kết luận an ninh.

## ie-en-stolen-credentials

Query: Which credentials did PowerShell steal during this activity?

Dataset: `insufficient_evidence`, language `en`, expected `abstain`. Parser `unsupported`; scope `unspecified`; support D `unknown`.

| Arm | Decision | Stage | Reason codes | External context sufficient |
| --- | --- | --- | --- | --- |
| A | abstain | topical_relevance | returned_top_cosine_score_below_threshold | False |
| B | abstain | topical_relevance | returned_top_cosine_score_below_threshold | False |
| C | abstain | query_requirements | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained | False |
| D | abstain | query_requirements | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained | False |

Requirements: `[]`.

Evidence context A/C → B/D: 40 → 40 items; 60183 → 60183 canonical serialized UTF-8 bytes. Supplementary 0; incomplete False → False. A/C incomplete có thể do enrichment tắt; xem cut reason, không suy thành budget failure.

Không có supplementary item.

Rubric ngoài A: satisfied `[]`; missing/unassessed `[]`.

Rubric ngoài D: satisfied `[]`; missing/unassessed `[]`.

Returned evidence IDs (D): `["evidence-b07a5ff4763e629715e6", "evidence-b31714b888d1489a380c"]`. Các IDs xuất hiện trong context không tự bảo đảm đủ đáp án.

| Requirement | Support | Reason codes | Trace fields |
| --- | --- | --- | ---: |
| — | unknown | Không có mandatory requirement đã phân giải | 0 |

Legacy quality diagnostic D: `["returned_top_cosine_score_below_threshold"]`. Support diagnostics D: `["mandatory_requirement_support_unknown"]`.

Full trace JSON pointer: `/D/ie-en-stolen-credentials/trace/support_assessment` trong decisions.json. Final decision chỉ là context eligibility; không tạo kết luận an ninh.

## ie-vi-destructive-files

Query: Trong hai nhóm process-creation evidence của ground truth, có bằng chứng nào cho thấy payload PowerShell cố ý phá hoại tệp không?

Dataset: `insufficient_evidence`, language `vi`, expected `abstain`. Parser `ambiguous`; scope `unspecified`; support D `unknown`.

| Arm | Decision | Stage | Reason codes | External context sufficient |
| --- | --- | --- | --- | --- |
| A | abstain | topical_relevance | returned_top_cosine_score_below_threshold | False |
| B | abstain | topical_relevance | returned_top_cosine_score_below_threshold | False |
| C | abstain | query_requirements | query_requirements_ambiguous, required_evidence_unknown, legacy_quality_gate_abstained | False |
| D | abstain | query_requirements | query_requirements_ambiguous, required_evidence_unknown, legacy_quality_gate_abstained | False |

Requirements: `[{"analysis": "supported", "id": "r1", "kind": "evidence_provenance", "parameters": {"process": "powershell.exe"}}]`.

Evidence context A/C → B/D: 38 → 38 items; 51565 → 51565 canonical serialized UTF-8 bytes. Supplementary 0; incomplete False → False. A/C incomplete có thể do enrichment tắt; xem cut reason, không suy thành budget failure.

Không có supplementary item.

Rubric ngoài A: satisfied `[]`; missing/unassessed `[]`.

Rubric ngoài D: satisfied `[]`; missing/unassessed `[]`.

Returned evidence IDs (D): `["evidence-b07a5ff4763e629715e6", "evidence-b31714b888d1489a380c"]`. Các IDs xuất hiện trong context không tự bảo đảm đủ đáp án.

| Requirement | Support | Reason codes | Trace fields |
| --- | --- | --- | ---: |
| r1 / evidence_provenance | unknown | query_requirement_analysis_not_supported | 0 |

Legacy quality diagnostic D: `["returned_top_cosine_score_below_threshold"]`. Support diagnostics D: `["mandatory_requirement_support_unknown"]`.

Full trace JSON pointer: `/D/ie-vi-destructive-files/trace/support_assessment` trong decisions.json. Final decision chỉ là context eligibility; không tạo kết luận an ninh.

## ie-vi-decoded-content

Query: Nội dung payload đã được MSHTA hoặc PowerShell giải mã là gì?

Dataset: `insufficient_evidence`, language `vi`, expected `abstain`. Parser `unsupported`; scope `unspecified`; support D `unknown`.

| Arm | Decision | Stage | Reason codes | External context sufficient |
| --- | --- | --- | --- | --- |
| A | abstain | topical_relevance | returned_top_cosine_score_below_threshold | False |
| B | abstain | topical_relevance | returned_top_cosine_score_below_threshold | False |
| C | abstain | query_requirements | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained | False |
| D | abstain | query_requirements | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained | False |

Requirements: `[]`.

Evidence context A/C → B/D: 40 → 40 items; 60183 → 60183 canonical serialized UTF-8 bytes. Supplementary 0; incomplete False → False. A/C incomplete có thể do enrichment tắt; xem cut reason, không suy thành budget failure.

Không có supplementary item.

Rubric ngoài A: satisfied `[]`; missing/unassessed `[]`.

Rubric ngoài D: satisfied `[]`; missing/unassessed `[]`.

Returned evidence IDs (D): `["evidence-b07a5ff4763e629715e6", "evidence-b31714b888d1489a380c"]`. Các IDs xuất hiện trong context không tự bảo đảm đủ đáp án.

| Requirement | Support | Reason codes | Trace fields |
| --- | --- | --- | ---: |
| — | unknown | Không có mandatory requirement đã phân giải | 0 |

Legacy quality diagnostic D: `["returned_top_cosine_score_below_threshold"]`. Support diagnostics D: `["mandatory_requirement_support_unknown"]`.

Full trace JSON pointer: `/D/ie-vi-decoded-content/trace/support_assessment` trong decisions.json. Final decision chỉ là context eligibility; không tạo kết luận an ninh.

## ie-vi-decoding-proof

Query: Bằng chứng nào chứng minh T1140 đã xảy ra trong chuỗi MSHTA?

Dataset: `insufficient_evidence`, language `vi`, expected `abstain`. Parser `ambiguous`; scope `unspecified`; support D `unknown`.

| Arm | Decision | Stage | Reason codes | External context sufficient |
| --- | --- | --- | --- | --- |
| A | abstain | topical_relevance | returned_top_cosine_score_below_threshold | False |
| B | abstain | topical_relevance | returned_top_cosine_score_below_threshold | False |
| C | abstain | query_requirements | query_requirements_ambiguous, required_evidence_unknown, legacy_quality_gate_abstained | False |
| D | abstain | query_requirements | query_requirements_ambiguous, required_evidence_unknown, legacy_quality_gate_abstained | False |

Requirements: `[{"analysis": "ambiguous", "id": "r1", "kind": "process_relationship", "parameters": {"chain": true, "child": null, "parent": null}}, {"analysis": "supported", "id": "r2", "kind": "evidence_provenance", "parameters": {"process": "mshta.exe"}}, {"analysis": "supported", "id": "r3", "kind": "technique_assessment", "parameters": {"certainty": "assessment", "technique_id": "T1140"}}]`.

Evidence context A/C → B/D: 38 → 39 items; 58339 → 59226 canonical serialized UTF-8 bytes. Supplementary 1; incomplete True → False. A/C incomplete có thể do enrichment tắt; xem cut reason, không suy thành budget failure.

| Item thêm | Kind / source pointer | Lý do |
| --- | --- | --- |
| `retrieval-chunk--69e16e4937a131ad5d4712b725f21116ae3c14c49b4d72f124980e9c3d90bbaf` | chunk `/summary/limitations/3` | assessment_certainty_limitation |

Rubric ngoài A: satisfied `[]`; missing/unassessed `[]`.

Rubric ngoài D: satisfied `[]`; missing/unassessed `[]`.

Returned evidence IDs (D): `["evidence-b07a5ff4763e629715e6", "evidence-b31714b888d1489a380c"]`. Các IDs xuất hiện trong context không tự bảo đảm đủ đáp án.

| Requirement | Support | Reason codes | Trace fields |
| --- | --- | --- | ---: |
| r1 / process_relationship | unknown | query_requirement_analysis_not_supported | 0 |
| r2 / evidence_provenance | unknown | query_requirement_analysis_not_supported | 0 |
| r3 / technique_assessment | unknown | query_requirement_analysis_not_supported | 0 |

Legacy quality diagnostic D: `["returned_top_cosine_score_below_threshold"]`. Support diagnostics D: `["mandatory_requirement_support_unknown"]`.

Full trace JSON pointer: `/D/ie-vi-decoding-proof/trace/support_assessment` trong decisions.json. Final decision chỉ là context eligibility; không tạo kết luận an ninh.

## ie-vi-certain-attack-determination

Query: Có thể khẳng định chắc chắn toàn bộ chuỗi cmd.exe, mshta.exe và powershell.exe là một cuộc tấn công không?

Dataset: `insufficient_evidence`, language `vi`, expected `abstain`. Parser `ambiguous`; scope `unspecified`; support D `unknown`.

| Arm | Decision | Stage | Reason codes | External context sufficient |
| --- | --- | --- | --- | --- |
| A | abstain | topical_relevance | query_token_coverage_below_threshold | False |
| B | abstain | topical_relevance | query_token_coverage_below_threshold | False |
| C | abstain | query_requirements | query_requirements_ambiguous, required_evidence_unknown, legacy_quality_gate_abstained | False |
| D | abstain | query_requirements | query_requirements_ambiguous, required_evidence_unknown, legacy_quality_gate_abstained | False |

Requirements: `[{"analysis": "ambiguous", "id": "r1", "kind": "process_relationship", "parameters": {"chain": true, "child": null, "parent": null}}]`.

Evidence context A/C → B/D: 39 → 39 items; 52433 → 52433 canonical serialized UTF-8 bytes. Supplementary 0; incomplete False → False. A/C incomplete có thể do enrichment tắt; xem cut reason, không suy thành budget failure.

Không có supplementary item.

Rubric ngoài A: satisfied `[]`; missing/unassessed `[]`.

Rubric ngoài D: satisfied `[]`; missing/unassessed `[]`.

Returned evidence IDs (D): `["evidence-b07a5ff4763e629715e6", "evidence-b31714b888d1489a380c"]`. Các IDs xuất hiện trong context không tự bảo đảm đủ đáp án.

| Requirement | Support | Reason codes | Trace fields |
| --- | --- | --- | ---: |
| r1 / process_relationship | unknown | query_requirement_analysis_not_supported | 0 |

Legacy quality diagnostic D: `["query_token_coverage_below_threshold"]`. Support diagnostics D: `["mandatory_requirement_support_unknown"]`.

Full trace JSON pointer: `/D/ie-vi-certain-attack-determination/trace/support_assessment` trong decisions.json. Final decision chỉ là context eligibility; không tạo kết luận an ninh.

## ur-en-weather

Query: What will the weather be in Hanoi tomorrow?

Dataset: `unrelated`, language `en`, expected `abstain`. Parser `unsupported`; scope `unspecified`; support D `unknown`.

| Arm | Decision | Stage | Reason codes | External context sufficient |
| --- | --- | --- | --- | --- |
| A | abstain | topical_relevance | returned_top_cosine_score_below_threshold | None (unknown/N/A) |
| B | abstain | topical_relevance | returned_top_cosine_score_below_threshold | None (unknown/N/A) |
| C | abstain | query_requirements | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained | None (unknown/N/A) |
| D | abstain | query_requirements | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained | None (unknown/N/A) |

Requirements: `[]`.

Evidence context A/C → B/D: 25 → 25 items; 26582 → 26582 canonical serialized UTF-8 bytes. Supplementary 0; incomplete False → False. A/C incomplete có thể do enrichment tắt; xem cut reason, không suy thành budget failure.

Không có supplementary item.

Rubric ngoài A: satisfied `[]`; missing/unassessed `[]`.

Rubric ngoài D: satisfied `[]`; missing/unassessed `[]`.

Returned evidence IDs (D): `["evidence-b07a5ff4763e629715e6", "evidence-b31714b888d1489a380c"]`. Các IDs xuất hiện trong context không tự bảo đảm đủ đáp án.

| Requirement | Support | Reason codes | Trace fields |
| --- | --- | --- | ---: |
| — | unknown | Không có mandatory requirement đã phân giải | 0 |

Legacy quality diagnostic D: `["returned_top_cosine_score_below_threshold"]`. Support diagnostics D: `["mandatory_requirement_support_unknown"]`.

Full trace JSON pointer: `/D/ur-en-weather/trace/support_assessment` trong decisions.json. Final decision chỉ là context eligibility; không tạo kết luận an ninh.

## ur-en-product-price

Query: What is the current price of a gaming laptop?

Dataset: `unrelated`, language `en`, expected `abstain`. Parser `unsupported`; scope `unspecified`; support D `unknown`.

| Arm | Decision | Stage | Reason codes | External context sufficient |
| --- | --- | --- | --- | --- |
| A | abstain | topical_relevance | returned_top_cosine_score_below_threshold | None (unknown/N/A) |
| B | abstain | topical_relevance | returned_top_cosine_score_below_threshold | None (unknown/N/A) |
| C | abstain | query_requirements | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained | None (unknown/N/A) |
| D | abstain | query_requirements | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained | None (unknown/N/A) |

Requirements: `[]`.

Evidence context A/C → B/D: 34 → 34 items; 38696 → 38696 canonical serialized UTF-8 bytes. Supplementary 0; incomplete False → False. A/C incomplete có thể do enrichment tắt; xem cut reason, không suy thành budget failure.

Không có supplementary item.

Rubric ngoài A: satisfied `[]`; missing/unassessed `[]`.

Rubric ngoài D: satisfied `[]`; missing/unassessed `[]`.

Returned evidence IDs (D): `["evidence-b07a5ff4763e629715e6", "evidence-b31714b888d1489a380c"]`. Các IDs xuất hiện trong context không tự bảo đảm đủ đáp án.

| Requirement | Support | Reason codes | Trace fields |
| --- | --- | --- | ---: |
| — | unknown | Không có mandatory requirement đã phân giải | 0 |

Legacy quality diagnostic D: `["returned_top_cosine_score_below_threshold"]`. Support diagnostics D: `["mandatory_requirement_support_unknown"]`.

Full trace JSON pointer: `/D/ur-en-product-price/trace/support_assessment` trong decisions.json. Final decision chỉ là context eligibility; không tạo kết luận an ninh.

## ur-en-linux-cron

Query: How do I schedule a Linux cron job to run every ten minutes?

Dataset: `unrelated`, language `en`, expected `abstain`. Parser `unsupported`; scope `mismatch`; support D `unknown`.

| Arm | Decision | Stage | Reason codes | External context sufficient |
| --- | --- | --- | --- | --- |
| A | proceed | — | — | None (unknown/N/A) |
| B | proceed | — | — | None (unknown/N/A) |
| C | abstain | topical_relevance | requested_scope_mismatch, query_requirements_unsupported, required_evidence_unknown | None (unknown/N/A) |
| D | abstain | topical_relevance | requested_scope_mismatch, query_requirements_unsupported, required_evidence_unknown | None (unknown/N/A) |

Requirements: `[]`.

Evidence context A/C → B/D: 39 → 39 items; 58632 → 58632 canonical serialized UTF-8 bytes. Supplementary 0; incomplete False → False. A/C incomplete có thể do enrichment tắt; xem cut reason, không suy thành budget failure.

Không có supplementary item.

Rubric ngoài A: satisfied `[]`; missing/unassessed `[]`.

Rubric ngoài D: satisfied `[]`; missing/unassessed `[]`.

Returned evidence IDs (D): `["evidence-b07a5ff4763e629715e6", "evidence-b31714b888d1489a380c"]`. Các IDs xuất hiện trong context không tự bảo đảm đủ đáp án.

| Requirement | Support | Reason codes | Trace fields |
| --- | --- | --- | ---: |
| — | unknown | Không có mandatory requirement đã phân giải | 0 |

Legacy quality diagnostic D: `[]`. Support diagnostics D: `["mandatory_requirement_support_unknown"]`.

Full trace JSON pointer: `/D/ur-en-linux-cron/trace/support_assessment` trong decisions.json. Final decision chỉ là context eligibility; không tạo kết luận an ninh.

## ur-en-sql-injection

Query: How can I prevent SQL injection in a web application's database queries?

Dataset: `unrelated`, language `en`, expected `abstain`. Parser `unsupported`; scope `unspecified`; support D `unknown`.

| Arm | Decision | Stage | Reason codes | External context sufficient |
| --- | --- | --- | --- | --- |
| A | abstain | topical_relevance | query_token_coverage_below_threshold, returned_top_cosine_score_below_threshold | None (unknown/N/A) |
| B | abstain | topical_relevance | query_token_coverage_below_threshold, returned_top_cosine_score_below_threshold | None (unknown/N/A) |
| C | abstain | query_requirements | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained | None (unknown/N/A) |
| D | abstain | query_requirements | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained | None (unknown/N/A) |

Requirements: `[]`.

Evidence context A/C → B/D: 25 → 25 items; 28185 → 28185 canonical serialized UTF-8 bytes. Supplementary 0; incomplete False → False. A/C incomplete có thể do enrichment tắt; xem cut reason, không suy thành budget failure.

Không có supplementary item.

Rubric ngoài A: satisfied `[]`; missing/unassessed `[]`.

Rubric ngoài D: satisfied `[]`; missing/unassessed `[]`.

Returned evidence IDs (D): `["evidence-b07a5ff4763e629715e6", "evidence-b31714b888d1489a380c"]`. Các IDs xuất hiện trong context không tự bảo đảm đủ đáp án.

| Requirement | Support | Reason codes | Trace fields |
| --- | --- | --- | ---: |
| — | unknown | Không có mandatory requirement đã phân giải | 0 |

Legacy quality diagnostic D: `["query_token_coverage_below_threshold", "returned_top_cosine_score_below_threshold"]`. Support diagnostics D: `["mandatory_requirement_support_unknown"]`.

Full trace JSON pointer: `/D/ur-en-sql-injection/trace/support_assessment` trong decisions.json. Final decision chỉ là context eligibility; không tạo kết luận an ninh.

## ur-vi-ransomware-encryption

Query: Mã hóa ransomware xử lý các khóa mật mã như thế nào?

Dataset: `unrelated`, language `vi`, expected `abstain`. Parser `unsupported`; scope `unspecified`; support D `unknown`.

| Arm | Decision | Stage | Reason codes | External context sufficient |
| --- | --- | --- | --- | --- |
| A | abstain | topical_relevance | query_token_coverage_below_threshold, returned_top_cosine_score_below_threshold | None (unknown/N/A) |
| B | abstain | topical_relevance | query_token_coverage_below_threshold, returned_top_cosine_score_below_threshold | None (unknown/N/A) |
| C | abstain | query_requirements | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained | None (unknown/N/A) |
| D | abstain | query_requirements | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained | None (unknown/N/A) |

Requirements: `[]`.

Evidence context A/C → B/D: 34 → 34 items; 52516 → 52516 canonical serialized UTF-8 bytes. Supplementary 0; incomplete False → False. A/C incomplete có thể do enrichment tắt; xem cut reason, không suy thành budget failure.

Không có supplementary item.

Rubric ngoài A: satisfied `[]`; missing/unassessed `[]`.

Rubric ngoài D: satisfied `[]`; missing/unassessed `[]`.

Returned evidence IDs (D): `["evidence-b07a5ff4763e629715e6", "evidence-b31714b888d1489a380c"]`. Các IDs xuất hiện trong context không tự bảo đảm đủ đáp án.

| Requirement | Support | Reason codes | Trace fields |
| --- | --- | --- | ---: |
| — | unknown | Không có mandatory requirement đã phân giải | 0 |

Legacy quality diagnostic D: `["query_token_coverage_below_threshold", "returned_top_cosine_score_below_threshold"]`. Support diagnostics D: `["mandatory_requirement_support_unknown"]`.

Full trace JSON pointer: `/D/ur-vi-ransomware-encryption/trace/support_assessment` trong decisions.json. Final decision chỉ là context eligibility; không tạo kết luận an ninh.

## ur-vi-kubernetes-configuration

Query: Cần cấu hình Kubernetes thế nào để tự động mở rộng một Deployment?

Dataset: `unrelated`, language `vi`, expected `abstain`. Parser `unsupported`; scope `unspecified`; support D `unknown`.

| Arm | Decision | Stage | Reason codes | External context sufficient |
| --- | --- | --- | --- | --- |
| A | abstain | topical_relevance | query_token_coverage_below_threshold, returned_top_cosine_score_below_threshold | None (unknown/N/A) |
| B | abstain | topical_relevance | query_token_coverage_below_threshold, returned_top_cosine_score_below_threshold | None (unknown/N/A) |
| C | abstain | query_requirements | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained | None (unknown/N/A) |
| D | abstain | query_requirements | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained | None (unknown/N/A) |

Requirements: `[]`.

Evidence context A/C → B/D: 38 → 38 items; 57078 → 57078 canonical serialized UTF-8 bytes. Supplementary 0; incomplete False → False. A/C incomplete có thể do enrichment tắt; xem cut reason, không suy thành budget failure.

Không có supplementary item.

Rubric ngoài A: satisfied `[]`; missing/unassessed `[]`.

Rubric ngoài D: satisfied `[]`; missing/unassessed `[]`.

Returned evidence IDs (D): `["evidence-b07a5ff4763e629715e6", "evidence-b31714b888d1489a380c"]`. Các IDs xuất hiện trong context không tự bảo đảm đủ đáp án.

| Requirement | Support | Reason codes | Trace fields |
| --- | --- | --- | ---: |
| — | unknown | Không có mandatory requirement đã phân giải | 0 |

Legacy quality diagnostic D: `["query_token_coverage_below_threshold", "returned_top_cosine_score_below_threshold"]`. Support diagnostics D: `["mandatory_requirement_support_unknown"]`.

Full trace JSON pointer: `/D/ur-vi-kubernetes-configuration/trace/support_assessment` trong decisions.json. Final decision chỉ là context eligibility; không tạo kết luận an ninh.

## ur-vi-literature-learning

Query: Làm thế nào phân biệt hình ảnh ẩn dụ và hoán dụ trong một bài thơ?

Dataset: `unrelated`, language `vi`, expected `abstain`. Parser `unsupported`; scope `unspecified`; support D `unknown`.

| Arm | Decision | Stage | Reason codes | External context sufficient |
| --- | --- | --- | --- | --- |
| A | abstain | topical_relevance | query_token_coverage_below_threshold, returned_top_cosine_score_below_threshold | None (unknown/N/A) |
| B | abstain | topical_relevance | query_token_coverage_below_threshold, returned_top_cosine_score_below_threshold | None (unknown/N/A) |
| C | abstain | query_requirements | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained | None (unknown/N/A) |
| D | abstain | query_requirements | query_requirements_unsupported, required_evidence_unknown, legacy_quality_gate_abstained | None (unknown/N/A) |

Requirements: `[]`.

Evidence context A/C → B/D: 37 → 37 items; 56491 → 56491 canonical serialized UTF-8 bytes. Supplementary 0; incomplete False → False. A/C incomplete có thể do enrichment tắt; xem cut reason, không suy thành budget failure.

Không có supplementary item.

Rubric ngoài A: satisfied `[]`; missing/unassessed `[]`.

Rubric ngoài D: satisfied `[]`; missing/unassessed `[]`.

Returned evidence IDs (D): `["evidence-b07a5ff4763e629715e6", "evidence-b31714b888d1489a380c"]`. Các IDs xuất hiện trong context không tự bảo đảm đủ đáp án.

| Requirement | Support | Reason codes | Trace fields |
| --- | --- | --- | ---: |
| — | unknown | Không có mandatory requirement đã phân giải | 0 |

Legacy quality diagnostic D: `["query_token_coverage_below_threshold", "returned_top_cosine_score_below_threshold"]`. Support diagnostics D: `["mandatory_requirement_support_unknown"]`.

Full trace JSON pointer: `/D/ur-vi-literature-learning/trace/support_assessment` trong decisions.json. Final decision chỉ là context eligibility; không tạo kết luận an ninh.

## ur-vi-opaque-token

Query: Chuỗi velora_quartz_token_483920761 có ý nghĩa gì?

Dataset: `unrelated`, language `vi`, expected `abstain`. Parser `ambiguous`; scope `unspecified`; support D `unknown`.

| Arm | Decision | Stage | Reason codes | External context sufficient |
| --- | --- | --- | --- | --- |
| A | abstain | topical_relevance | query_token_coverage_below_threshold, returned_top_cosine_score_below_threshold | None (unknown/N/A) |
| B | abstain | topical_relevance | query_token_coverage_below_threshold, returned_top_cosine_score_below_threshold | None (unknown/N/A) |
| C | abstain | query_requirements | query_requirements_ambiguous, required_evidence_unknown, legacy_quality_gate_abstained | None (unknown/N/A) |
| D | abstain | query_requirements | query_requirements_ambiguous, required_evidence_unknown, legacy_quality_gate_abstained | None (unknown/N/A) |

Requirements: `[{"analysis": "ambiguous", "id": "r1", "kind": "process_relationship", "parameters": {"chain": true, "child": null, "parent": null}}]`.

Evidence context A/C → B/D: 33 → 33 items; 52549 → 52549 canonical serialized UTF-8 bytes. Supplementary 0; incomplete False → False. A/C incomplete có thể do enrichment tắt; xem cut reason, không suy thành budget failure.

Không có supplementary item.

Rubric ngoài A: satisfied `[]`; missing/unassessed `[]`.

Rubric ngoài D: satisfied `[]`; missing/unassessed `[]`.

Returned evidence IDs (D): `["evidence-b07a5ff4763e629715e6", "evidence-b31714b888d1489a380c"]`. Các IDs xuất hiện trong context không tự bảo đảm đủ đáp án.

| Requirement | Support | Reason codes | Trace fields |
| --- | --- | --- | ---: |
| r1 / process_relationship | unknown | query_requirement_analysis_not_supported | 0 |

Legacy quality diagnostic D: `["query_token_coverage_below_threshold", "returned_top_cosine_score_below_threshold"]`. Support diagnostics D: `["mandatory_requirement_support_unknown"]`.

Full trace JSON pointer: `/D/ur-vi-opaque-token/trace/support_assessment` trong decisions.json. Final decision chỉ là context eligibility; không tạo kết luận an ninh.
