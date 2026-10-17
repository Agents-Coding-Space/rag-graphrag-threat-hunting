# Kết quả từng case — FIX1 với policy cố định

Policy `two-stage-dev-5a4b308b106699e0`, 32 development cases, không có held-out results. Dữ liệu được đọc từ actual contexts/signals/decisions mới trong `outputs/experiments/graphrag-2d3-fix1/` và baseline calibration đã bảo toàn. Không thêm evidence từ đáp án hoặc source pointers vào context.

`expected_decision` là nhãn dataset đã duyệt; `context_sufficient` là kết quả conservative AI rubric ngoài runtime. `true` = đủ tất cả required units theo rubric, `false` = requested assertion không được nguồn hỗ trợ hoặc thiếu required structured information, `null` = chưa đánh giá đủ semantic support/không áp dụng với unrelated. Không coi `null` là `false` hoặc `true`.

Hai positives chuyển context false→null vì factual marker chứng minh nội dung vắng trong consumers cũ không áp dụng cho consumers v2 đã có nội dung; tiêu chí rubric giữ nguyên. Actual returned context chưa được xác nhận đủ cho hai case đó. `not_evaluated` của tầng answerability là dừng từ topical gate, không phải pass/fail.

Mỗi case dưới đây ghi query, transition, layer status, reason codes, ordered retrieval hit sources, returned evidence IDs và tất cả signal fields thay đổi. Full unchanged signal values và payload fields nằm trong [signals.json](../../experiments/graphrag-2d3-fix1/signals.json), [contexts.json](../../experiments/graphrag-2d3-fix1/contexts.json), [decisions.json](../../experiments/graphrag-2d3-fix1/decisions.json) và [case_transitions.json](../../experiments/graphrag-2d3-fix1/case_transitions.json). Returned IDs không tự chứng minh nội dung đáp ứng yêu cầu.

| Case | Category | Expected | Decision before→after | Context before→after | Topical / Answerability after |
| --- | --- | --- | --- | --- | --- |
| `ie-en-attacker-identity` | insufficient_evidence | abstain | abstain→abstain | false→false | failed / not_evaluated |
| `ie-en-c2-address` | insufficient_evidence | abstain | abstain→abstain | false→false | failed / not_evaluated |
| `ie-en-payload-download-url` | insufficient_evidence | abstain | proceed→proceed | false→false | passed / passed |
| `ie-en-stolen-credentials` | insufficient_evidence | abstain | abstain→abstain | false→false | failed / not_evaluated |
| `ie-vi-certain-attack-determination` | insufficient_evidence | abstain | abstain→abstain | false→false | failed / not_evaluated |
| `ie-vi-decoded-content` | insufficient_evidence | abstain | abstain→abstain | false→false | failed / not_evaluated |
| `ie-vi-decoding-proof` | insufficient_evidence | abstain | abstain→abstain | false→false | failed / not_evaluated |
| `ie-vi-destructive-files` | insufficient_evidence | abstain | abstain→abstain | false→false | failed / not_evaluated |
| `rd-en-final-spawn-evidence` | relevant_direct | proceed | proceed→proceed | true→true | passed / passed |
| `rd-en-initial-spawn-evidence` | relevant_direct | proceed | proceed→proceed | true→true | passed / passed |
| `rd-en-process-chain` | relevant_direct | proceed | proceed→proceed | true→true | passed / passed |
| `rd-en-shell-parent` | relevant_direct | proceed | proceed→proceed | true→true | passed / passed |
| `rd-vi-initial-relation-provenance` | relevant_direct | proceed | abstain→abstain | true→true | failed / not_evaluated |
| `rd-vi-proxy-technique-assessment` | relevant_direct | proceed | abstain→abstain | true→true | failed / not_evaluated |
| `rd-vi-reviewed-scope-limitations` | relevant_direct | proceed | abstain→abstain | false→null | failed / not_evaluated |
| `rd-vi-scripting-technique-status` | relevant_direct | proceed | abstain→abstain | true→true | failed / not_evaluated |
| `rp-en-intermediate-utility` | relevant_paraphrase | proceed | abstain→abstain | true→true | failed / not_evaluated |
| `rp-en-retained-scripting-label` | relevant_paraphrase | proceed | proceed→proceed | true→true | passed / passed |
| `rp-en-shell-creator` | relevant_paraphrase | proceed | abstain→abstain | true→true | failed / not_evaluated |
| `rp-en-technique-review` | relevant_paraphrase | proceed | abstain→abstain | true→true | failed / not_evaluated |
| `rp-vi-final-review-limits` | relevant_paraphrase | proceed | abstain→abstain | false→false | failed / not_evaluated |
| `rp-vi-launch-order` | relevant_paraphrase | proceed | abstain→abstain | true→true | failed / not_evaluated |
| `rp-vi-observation-provenance` | relevant_paraphrase | proceed | abstain→abstain | true→true | failed / not_evaluated |
| `rp-vi-service-action` | relevant_paraphrase | proceed | abstain→abstain | false→null | failed / not_evaluated |
| `ur-en-linux-cron` | unrelated | abstain | abstain→proceed | null→null | passed / passed |
| `ur-en-product-price` | unrelated | abstain | abstain→abstain | null→null | failed / not_evaluated |
| `ur-en-sql-injection` | unrelated | abstain | abstain→abstain | null→null | failed / not_evaluated |
| `ur-en-weather` | unrelated | abstain | abstain→abstain | null→null | failed / not_evaluated |
| `ur-vi-kubernetes-configuration` | unrelated | abstain | abstain→abstain | null→null | failed / not_evaluated |
| `ur-vi-literature-learning` | unrelated | abstain | abstain→abstain | null→null | failed / not_evaluated |
| `ur-vi-opaque-token` | unrelated | abstain | abstain→abstain | null→null | failed / not_evaluated |
| `ur-vi-ransomware-encryption` | unrelated | abstain | abstain→abstain | null→null | failed / not_evaluated |

## `ie-en-attacker-identity`

> Who was the attacker responsible for the reviewed MSHTA execution?

| Field | Before | After |
| --- | --- | --- |
| actual_decision | `"abstain"` | `"abstain"` |
| context_sufficient | `false` | `false` |
| abstention_stage | `"topical_relevance"` | `"topical_relevance"` |
| reason_codes | `["returned_top_cosine_score_below_threshold"]` | `["returned_top_cosine_score_below_threshold"]` |
| topical_relevance | `"failed"` | `"failed"` |
| evidence_answerability | `"not_evaluated"` | `"not_evaluated"` |

| Hit rank | Before source pointer | After source pointer |
| --- | --- | --- |
| 1 | `/sigma_findings/1` | `/sigma_findings/1` |
| 2 | `/mitre_assessments/2` | `/scenario` |
| 3 | `/scenario` | `/mitre_assessments/2` |
| 4 | `/sigma_findings/0` | `/mitre_assessments/0` |
| 5 | `/mitre_assessments/0` | `/sigma_findings/0` |

| Returned evidence IDs | Value |
| --- | --- |
| Before | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |
| After | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |

Context basis: `approved_category_marks_requested_assertion_unsupported_not_scope_explanation`.

Satisfied answer units: `[]`. Missing/unassessed units: `[]`.

| Changed signal field | Before | After |
| --- | --- | --- |
| `topical_relevance.matched_query_token_count` | `5` | `6` |
| `topical_relevance.query_token_coverage` | `0.55555556` | `0.66666667` |
| `topical_relevance.returned_top_bm25_score` | `6.61899551` | `7.00566279` |
| `topical_relevance.returned_top_cosine_score` | `0.82283651` | `0.82283647` |

## `ie-en-c2-address`

> What IP address acted as the C2 server for the PowerShell process?

| Field | Before | After |
| --- | --- | --- |
| actual_decision | `"abstain"` | `"abstain"` |
| context_sufficient | `false` | `false` |
| abstention_stage | `"topical_relevance"` | `"topical_relevance"` |
| reason_codes | `["returned_top_cosine_score_below_threshold"]` | `["returned_top_cosine_score_below_threshold"]` |
| topical_relevance | `"failed"` | `"failed"` |
| evidence_answerability | `"not_evaluated"` | `"not_evaluated"` |

| Hit rank | Before source pointer | After source pointer |
| --- | --- | --- |
| 1 | `/scenario` | `/scenario` |
| 2 | `/entities/2` | `/summary/limitations/6` |
| 3 | `/entities/0` | `/entities/2` |
| 4 | `/mitre_assessments/2` | `/facts/0` |
| 5 | `/mitre_assessments/0` | `/mitre_assessments/0` |

| Returned evidence IDs | Value |
| --- | --- |
| Before | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |
| After | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |

Context basis: `approved_category_marks_requested_assertion_unsupported_not_scope_explanation`.

Satisfied answer units: `[]`. Missing/unassessed units: `[]`.

| Changed signal field | Before | After |
| --- | --- | --- |
| `evidence_answerability.chunk_type_counts.entity` | `2` | `1` |
| `evidence_answerability.chunk_type_counts.fact` | `0` | `1` |
| `evidence_answerability.chunk_type_counts.limitation` | `0` | `1` |
| `evidence_answerability.chunk_type_counts.mitre_assessment` | `2` | `1` |
| `evidence_answerability.hits_with_evidence_ids` | `4` | `3` |
| `evidence_answerability.hits_with_source_references` | `5` | `4` |
| `evidence_answerability.status_counts.candidate` | `2` | `1` |
| `evidence_answerability.status_counts.reviewable` | `1` | `2` |
| `evidence_answerability.support_edge_count` | `15` | `14` |
| `evidence_answerability.traversal_edge_count` | `21` | `20` |
| `evidence_answerability.traversal_node_count` | `13` | `14` |
| `evidence_answerability.traversal_path_count` | `40` | `29` |
| `evidence_answerability.traversed_limitation_node_count` | `0` | `1` |
| `topical_relevance.returned_top_bm25_score` | `5.49900495` | `5.85827883` |
| `topical_relevance.returned_top_cosine_score` | `0.80232751` | `0.80232748` |
| `topical_relevance.returned_top_rrf_score` | `0.031754032258` | `0.031513647643` |

## `ie-en-payload-download-url`

> Which URL did PowerShell use to download the payload in this MSHTA chain?

| Field | Before | After |
| --- | --- | --- |
| actual_decision | `"proceed"` | `"proceed"` |
| context_sufficient | `false` | `false` |
| abstention_stage | `null` | `null` |
| reason_codes | `[]` | `[]` |
| topical_relevance | `"passed"` | `"passed"` |
| evidence_answerability | `"passed"` | `"passed"` |

| Hit rank | Before source pointer | After source pointer |
| --- | --- | --- |
| 1 | `/scenario` | `/scenario` |
| 2 | `/mitre_assessments/2` | `/mitre_assessments/2` |
| 3 | `/sigma_findings/1` | `/facts/0` |
| 4 | `/mitre_assessments/1` | `/facts/1` |
| 5 | `/sigma_findings/0` | `/summary/limitations/6` |

| Returned evidence IDs | Value |
| --- | --- |
| Before | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |
| After | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |

Context basis: `approved_category_marks_requested_assertion_unsupported_not_scope_explanation`.

Satisfied answer units: `[]`. Missing/unassessed units: `[]`.

| Changed signal field | Before | After |
| --- | --- | --- |
| `evidence_answerability.chunk_type_counts.fact` | `0` | `2` |
| `evidence_answerability.chunk_type_counts.limitation` | `0` | `1` |
| `evidence_answerability.chunk_type_counts.mitre_assessment` | `2` | `1` |
| `evidence_answerability.chunk_type_counts.sigma_finding` | `2` | `0` |
| `evidence_answerability.status_counts.candidate` | `4` | `1` |
| `evidence_answerability.status_counts.observed` | `0` | `2` |
| `evidence_answerability.status_counts.reviewable` | `1` | `2` |
| `evidence_answerability.traversal_edge_count` | `15` | `21` |
| `evidence_answerability.traversal_node_count` | `13` | `14` |
| `evidence_answerability.traversal_path_count` | `36` | `33` |
| `evidence_answerability.traversed_limitation_node_count` | `0` | `1` |
| `topical_relevance.returned_top_bm25_score` | `9.45800735` | `8.73033557` |
| `topical_relevance.returned_top_cosine_score` | `0.85933597` | `0.85918457` |
| `topical_relevance.returned_top_rrf_score` | `0.032786885246` | `0.032522474881` |

## `ie-en-stolen-credentials`

> Which credentials did PowerShell steal during this activity?

| Field | Before | After |
| --- | --- | --- |
| actual_decision | `"abstain"` | `"abstain"` |
| context_sufficient | `false` | `false` |
| abstention_stage | `"topical_relevance"` | `"topical_relevance"` |
| reason_codes | `["returned_top_cosine_score_below_threshold"]` | `["returned_top_cosine_score_below_threshold"]` |
| topical_relevance | `"failed"` | `"failed"` |
| evidence_answerability | `"not_evaluated"` | `"not_evaluated"` |

| Hit rank | Before source pointer | After source pointer |
| --- | --- | --- |
| 1 | `/scenario` | `/scenario` |
| 2 | `/mitre_assessments/2` | `/facts/1` |
| 3 | `/mitre_assessments/1` | `/mitre_assessments/2` |
| 4 | `/summary/limitations/0` | `/facts/0` |
| 5 | `/evidence/1` | `/summary/limitations/6` |

| Returned evidence IDs | Value |
| --- | --- |
| Before | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |
| After | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |

Context basis: `approved_category_marks_requested_assertion_unsupported_not_scope_explanation`.

Satisfied answer units: `[]`. Missing/unassessed units: `[]`.

| Changed signal field | Before | After |
| --- | --- | --- |
| `evidence_answerability.chunk_type_counts.evidence` | `1` | `0` |
| `evidence_answerability.chunk_type_counts.fact` | `0` | `2` |
| `evidence_answerability.chunk_type_counts.mitre_assessment` | `2` | `1` |
| `evidence_answerability.hits_with_evidence_ids` | `2` | `3` |
| `evidence_answerability.hits_with_source_references` | `3` | `4` |
| `evidence_answerability.status_counts.candidate` | `2` | `1` |
| `evidence_answerability.status_counts.observed` | `1` | `2` |
| `evidence_answerability.traversal_edge_count` | `20` | `21` |
| `evidence_answerability.traversal_path_count` | `29` | `33` |
| `topical_relevance.joint_lexical_vector_hit_count` | `4` | `5` |
| `topical_relevance.lexical_hit_count` | `4` | `5` |
| `topical_relevance.returned_top_bm25_score` | `6.32696917` | `4.81150653` |
| `topical_relevance.returned_top_cosine_score` | `0.81822838` | `0.8174801` |
| `topical_relevance.returned_top_rrf_score` | `0.032522474881` | `0.032266458496` |

## `ie-vi-certain-attack-determination`

> Có thể khẳng định chắc chắn toàn bộ chuỗi cmd.exe, mshta.exe và powershell.exe là một cuộc tấn công không?

| Field | Before | After |
| --- | --- | --- |
| actual_decision | `"abstain"` | `"abstain"` |
| context_sufficient | `false` | `false` |
| abstention_stage | `"topical_relevance"` | `"topical_relevance"` |
| reason_codes | `["query_token_coverage_below_threshold"]` | `["query_token_coverage_below_threshold"]` |
| topical_relevance | `"failed"` | `"failed"` |
| evidence_answerability | `"not_evaluated"` | `"not_evaluated"` |

| Hit rank | Before source pointer | After source pointer |
| --- | --- | --- |
| 1 | `/scenario` | `/evidence/1` |
| 2 | `/evidence/1` | `/evidence/0` |
| 3 | `/evidence/0` | `/scenario` |
| 4 | `/relationships/0` | `/relationships/0` |
| 5 | `/relationships/1` | `/relationships/1` |

| Returned evidence IDs | Value |
| --- | --- |
| Before | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |
| After | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |

Context basis: `approved_category_marks_requested_assertion_unsupported_not_scope_explanation`.

Satisfied answer units: `[]`. Missing/unassessed units: `[]`.

| Changed signal field | Before | After |
| --- | --- | --- |
| `topical_relevance.returned_top_bm25_score` | `4.08038795` | `4.11675257` |
| `topical_relevance.returned_top_cosine_score` | `0.86500817` | `0.86113907` |
| `topical_relevance.returned_top_rrf_score` | `0.032266458496` | `0.032522474881` |

## `ie-vi-decoded-content`

> Nội dung payload đã được MSHTA hoặc PowerShell giải mã là gì?

| Field | Before | After |
| --- | --- | --- |
| actual_decision | `"abstain"` | `"abstain"` |
| context_sufficient | `false` | `false` |
| abstention_stage | `"topical_relevance"` | `"topical_relevance"` |
| reason_codes | `["query_token_coverage_below_threshold"]` | `["returned_top_cosine_score_below_threshold"]` |
| topical_relevance | `"failed"` | `"failed"` |
| evidence_answerability | `"not_evaluated"` | `"not_evaluated"` |

| Hit rank | Before source pointer | After source pointer |
| --- | --- | --- |
| 1 | `/scenario` | `/scenario` |
| 2 | `/mitre_assessments/2` | `/facts/0` |
| 3 | `/sigma_findings/1` | `/mitre_assessments/2` |
| 4 | `/sigma_findings/0` | `/facts/1` |
| 5 | `/relationships/0` | `/summary/limitations/6` |

| Returned evidence IDs | Value |
| --- | --- |
| Before | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |
| After | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |

Context basis: `approved_category_marks_requested_assertion_unsupported_not_scope_explanation`.

Satisfied answer units: `[]`. Missing/unassessed units: `[]`.

| Changed signal field | Before | After |
| --- | --- | --- |
| `evidence_answerability.chunk_type_counts.fact` | `0` | `2` |
| `evidence_answerability.chunk_type_counts.limitation` | `0` | `1` |
| `evidence_answerability.chunk_type_counts.relationship` | `1` | `0` |
| `evidence_answerability.chunk_type_counts.sigma_finding` | `2` | `0` |
| `evidence_answerability.hits_with_evidence_ids` | `4` | `3` |
| `evidence_answerability.hits_with_source_references` | `5` | `4` |
| `evidence_answerability.seed_node_count` | `6` | `5` |
| `evidence_answerability.status_counts.candidate` | `3` | `1` |
| `evidence_answerability.status_counts.observed` | `1` | `2` |
| `evidence_answerability.status_counts.reviewable` | `1` | `2` |
| `evidence_answerability.traversal_node_count` | `13` | `14` |
| `evidence_answerability.traversal_path_count` | `51` | `33` |
| `evidence_answerability.traversed_limitation_node_count` | `0` | `1` |
| `topical_relevance.joint_lexical_vector_hit_count` | `4` | `5` |
| `topical_relevance.lexical_hit_count` | `4` | `5` |
| `topical_relevance.matched_query_token_count` | `2` | `3` |
| `topical_relevance.query_token_coverage` | `0.16666667` | `0.25` |
| `topical_relevance.returned_top_bm25_score` | `5.53726515` | `4.5457998` |
| `topical_relevance.returned_top_cosine_score` | `0.84299805` | `0.84216155` |

## `ie-vi-decoding-proof`

> Bằng chứng nào chứng minh T1140 đã xảy ra trong chuỗi MSHTA?

| Field | Before | After |
| --- | --- | --- |
| actual_decision | `"abstain"` | `"abstain"` |
| context_sufficient | `false` | `false` |
| abstention_stage | `"topical_relevance"` | `"topical_relevance"` |
| reason_codes | `["returned_top_cosine_score_below_threshold"]` | `["returned_top_cosine_score_below_threshold"]` |
| topical_relevance | `"failed"` | `"failed"` |
| evidence_answerability | `"not_evaluated"` | `"not_evaluated"` |

| Hit rank | Before source pointer | After source pointer |
| --- | --- | --- |
| 1 | `/mitre_assessments/1` | `/mitre_assessments/1` |
| 2 | `/sigma_findings/0` | `/facts/0` |
| 3 | `/sigma_findings/1` | `/sigma_findings/0` |
| 4 | `/mitre_assessments/2` | `/sigma_findings/1` |
| 5 | `/scenario` | `/facts/1` |

| Returned evidence IDs | Value |
| --- | --- |
| Before | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |
| After | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |

Context basis: `approved_category_marks_requested_assertion_unsupported_not_scope_explanation`.

Satisfied answer units: `[]`. Missing/unassessed units: `[]`.

| Changed signal field | Before | After |
| --- | --- | --- |
| `evidence_answerability.chunk_type_counts.fact` | `0` | `2` |
| `evidence_answerability.chunk_type_counts.mitre_assessment` | `2` | `1` |
| `evidence_answerability.chunk_type_counts.scenario_summary` | `1` | `0` |
| `evidence_answerability.hits_with_evidence_ids` | `3` | `4` |
| `evidence_answerability.status_counts.candidate` | `4` | `3` |
| `evidence_answerability.status_counts.observed` | `0` | `2` |
| `evidence_answerability.status_counts.reviewable` | `1` | `0` |
| `evidence_answerability.traversal_edge_count` | `15` | `21` |
| `evidence_answerability.traversal_node_count` | `13` | `12` |
| `evidence_answerability.traversal_path_count` | `36` | `42` |
| `topical_relevance.returned_top_bm25_score` | `3.63931764` | `4.29902005` |
| `topical_relevance.returned_top_cosine_score` | `0.80882298` | `0.80946346` |
| `topical_relevance.returned_top_rrf_score` | `0.032786885246` | `0.032522474881` |

## `ie-vi-destructive-files`

> Trong hai nhóm process-creation evidence của ground truth, có bằng chứng nào cho thấy payload PowerShell cố ý phá hoại tệp không?

| Field | Before | After |
| --- | --- | --- |
| actual_decision | `"abstain"` | `"abstain"` |
| context_sufficient | `false` | `false` |
| abstention_stage | `"topical_relevance"` | `"topical_relevance"` |
| reason_codes | `["returned_top_cosine_score_below_threshold"]` | `["returned_top_cosine_score_below_threshold"]` |
| topical_relevance | `"failed"` | `"failed"` |
| evidence_answerability | `"not_evaluated"` | `"not_evaluated"` |

| Hit rank | Before source pointer | After source pointer |
| --- | --- | --- |
| 1 | `/evidence/1` | `/summary/limitations/6` |
| 2 | `/evidence/0` | `/summary/limitations/4` |
| 3 | `/summary/limitations/0` | `/evidence/1` |
| 4 | `/scenario` | `/facts/0` |
| 5 | `/mitre_assessments/2` | `/summary/limitations/0` |

| Returned evidence IDs | Value |
| --- | --- |
| Before | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |
| After | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |

Context basis: `approved_category_marks_requested_assertion_unsupported_not_scope_explanation`.

Satisfied answer units: `[]`. Missing/unassessed units: `[]`.

| Changed signal field | Before | After |
| --- | --- | --- |
| `evidence_answerability.chunk_type_counts.evidence` | `2` | `1` |
| `evidence_answerability.chunk_type_counts.fact` | `0` | `1` |
| `evidence_answerability.chunk_type_counts.limitation` | `1` | `3` |
| `evidence_answerability.chunk_type_counts.mitre_assessment` | `1` | `0` |
| `evidence_answerability.chunk_type_counts.scenario_summary` | `1` | `0` |
| `evidence_answerability.hits_with_evidence_ids` | `3` | `2` |
| `evidence_answerability.hits_with_source_references` | `4` | `2` |
| `evidence_answerability.status_counts.candidate` | `1` | `0` |
| `evidence_answerability.status_counts.reviewable` | `2` | `3` |
| `evidence_answerability.support_edge_count` | `15` | `13` |
| `evidence_answerability.traversal_edge_count` | `21` | `19` |
| `evidence_answerability.traversal_path_count` | `36` | `23` |
| `evidence_answerability.traversed_limitation_node_count` | `1` | `3` |
| `topical_relevance.matched_query_token_count` | `4` | `6` |
| `topical_relevance.query_token_coverage` | `0.18181818` | `0.27272727` |
| `topical_relevance.returned_top_bm25_score` | `6.2624113` | `7.10652179` |
| `topical_relevance.returned_top_cosine_score` | `0.83579551` | `0.83579549` |
| `topical_relevance.returned_top_rrf_score` | `0.030679156909` | `0.032002048131` |

## `rd-en-final-spawn-evidence`

> What evidence supports the mshta.exe to powershell.exe process creation relationship?

| Field | Before | After |
| --- | --- | --- |
| actual_decision | `"proceed"` | `"proceed"` |
| context_sufficient | `true` | `true` |
| abstention_stage | `null` | `null` |
| reason_codes | `[]` | `[]` |
| topical_relevance | `"passed"` | `"passed"` |
| evidence_answerability | `"passed"` | `"passed"` |

| Hit rank | Before source pointer | After source pointer |
| --- | --- | --- |
| 1 | `/relationships/0` | `/relationships/0` |
| 2 | `/evidence/1` | `/evidence/1` |
| 3 | `/mitre_assessments/2` | `/mitre_assessments/2` |
| 4 | `/relationships/1` | `/scenario` |
| 5 | `/entities/2` | `/relationships/1` |

| Returned evidence IDs | Value |
| --- | --- |
| Before | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |
| After | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |

Context basis: `all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation`.

Satisfied answer units: `["final_spawn","final_observations"]`. Missing/unassessed units: `[]`.

| Changed signal field | Before | After |
| --- | --- | --- |
| `evidence_answerability.chunk_type_counts.entity` | `1` | `0` |
| `evidence_answerability.chunk_type_counts.scenario_summary` | `0` | `1` |
| `evidence_answerability.hits_with_evidence_ids` | `5` | `4` |
| `evidence_answerability.seed_node_count` | `5` | `6` |
| `evidence_answerability.status_counts.observed` | `4` | `3` |
| `evidence_answerability.status_counts.reviewable` | `0` | `1` |
| `evidence_answerability.traversal_node_count` | `12` | `13` |
| `evidence_answerability.traversal_path_count` | `52` | `53` |
| `topical_relevance.matched_query_token_count` | `7` | `8` |
| `topical_relevance.query_token_coverage` | `0.7` | `0.8` |
| `topical_relevance.returned_top_bm25_score` | `5.86702482` | `6.36215007` |
| `topical_relevance.returned_top_cosine_score` | `0.91293862` | `0.91293859` |

## `rd-en-initial-spawn-evidence`

> What evidence supports the cmd.exe to mshta.exe process creation relationship?

| Field | Before | After |
| --- | --- | --- |
| actual_decision | `"proceed"` | `"proceed"` |
| context_sufficient | `true` | `true` |
| abstention_stage | `null` | `null` |
| reason_codes | `[]` | `[]` |
| topical_relevance | `"passed"` | `"passed"` |
| evidence_answerability | `"passed"` | `"passed"` |

| Hit rank | Before source pointer | After source pointer |
| --- | --- | --- |
| 1 | `/relationships/1` | `/relationships/1` |
| 2 | `/evidence/0` | `/evidence/0` |
| 3 | `/mitre_assessments/2` | `/mitre_assessments/2` |
| 4 | `/relationships/0` | `/scenario` |
| 5 | `/evidence/1` | `/relationships/0` |

| Returned evidence IDs | Value |
| --- | --- |
| Before | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |
| After | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |

Context basis: `all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation`.

Satisfied answer units: `["initial_spawn","initial_observations"]`. Missing/unassessed units: `[]`.

| Changed signal field | Before | After |
| --- | --- | --- |
| `evidence_answerability.chunk_type_counts.evidence` | `2` | `1` |
| `evidence_answerability.chunk_type_counts.scenario_summary` | `0` | `1` |
| `evidence_answerability.hits_with_evidence_ids` | `5` | `4` |
| `evidence_answerability.status_counts.observed` | `4` | `3` |
| `evidence_answerability.status_counts.reviewable` | `0` | `1` |
| `evidence_answerability.traversal_node_count` | `12` | `13` |
| `evidence_answerability.traversal_path_count` | `64` | `55` |
| `topical_relevance.matched_query_token_count` | `6` | `8` |
| `topical_relevance.query_token_coverage` | `0.6` | `0.8` |
| `topical_relevance.returned_top_bm25_score` | `5.86702482` | `6.42011014` |
| `topical_relevance.returned_top_rrf_score` | `0.032522474881` | `0.032258064516` |

## `rd-en-process-chain`

> Which process chain led to powershell.exe in the reviewed evidence?

| Field | Before | After |
| --- | --- | --- |
| actual_decision | `"proceed"` | `"proceed"` |
| context_sufficient | `true` | `true` |
| abstention_stage | `null` | `null` |
| reason_codes | `[]` | `[]` |
| topical_relevance | `"passed"` | `"passed"` |
| evidence_answerability | `"passed"` | `"passed"` |

| Hit rank | Before source pointer | After source pointer |
| --- | --- | --- |
| 1 | `/mitre_assessments/2` | `/scenario` |
| 2 | `/mitre_assessments/0` | `/mitre_assessments/2` |
| 3 | `/evidence/1` | `/evidence/1` |
| 4 | `/scenario` | `/entities/2` |
| 5 | `/entities/2` | `/mitre_assessments/0` |

| Returned evidence IDs | Value |
| --- | --- |
| Before | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |
| After | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |

Context basis: `all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation`.

Satisfied answer units: `["initial_spawn","final_spawn"]`. Missing/unassessed units: `[]`.

| Changed signal field | Before | After |
| --- | --- | --- |
| `topical_relevance.returned_top_bm25_score` | `5.21188364` | `6.23699744` |
| `topical_relevance.returned_top_cosine_score` | `0.86920244` | `0.86920241` |
| `topical_relevance.returned_top_rrf_score` | `0.032258064516` | `0.032266458496` |

## `rd-en-shell-parent`

> Which process is the observed parent of powershell.exe?

| Field | Before | After |
| --- | --- | --- |
| actual_decision | `"proceed"` | `"proceed"` |
| context_sufficient | `true` | `true` |
| abstention_stage | `null` | `null` |
| reason_codes | `[]` | `[]` |
| topical_relevance | `"passed"` | `"passed"` |
| evidence_answerability | `"passed"` | `"passed"` |

| Hit rank | Before source pointer | After source pointer |
| --- | --- | --- |
| 1 | `/entities/2` | `/entities/2` |
| 2 | `/mitre_assessments/2` | `/scenario` |
| 3 | `/evidence/1` | `/mitre_assessments/2` |
| 4 | `/scenario` | `/evidence/1` |
| 5 | `/relationships/0` | `/relationships/0` |

| Returned evidence IDs | Value |
| --- | --- |
| Before | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |
| After | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |

Context basis: `all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation`.

Satisfied answer units: `["final_spawn"]`. Missing/unassessed units: `[]`.

| Changed signal field | Before | After |
| --- | --- | --- |
| `topical_relevance.returned_top_bm25_score` | `6.53857651` | `7.12368524` |
| `topical_relevance.returned_top_cosine_score` | `0.87243352` | `0.87243353` |

## `rd-vi-initial-relation-provenance`

> Nguồn log và raw record references nào hỗ trợ quan hệ cmd.exe tạo mshta.exe?

| Field | Before | After |
| --- | --- | --- |
| actual_decision | `"abstain"` | `"abstain"` |
| context_sufficient | `true` | `true` |
| abstention_stage | `"topical_relevance"` | `"topical_relevance"` |
| reason_codes | `["query_token_coverage_below_threshold"]` | `["query_token_coverage_below_threshold"]` |
| topical_relevance | `"failed"` | `"failed"` |
| evidence_answerability | `"not_evaluated"` | `"not_evaluated"` |

| Hit rank | Before source pointer | After source pointer |
| --- | --- | --- |
| 1 | `/relationships/1` | `/relationships/1` |
| 2 | `/evidence/0` | `/evidence/0` |
| 3 | `/relationships/0` | `/scenario` |
| 4 | `/scenario` | `/relationships/0` |
| 5 | `/entities/1` | `/entities/1` |

| Returned evidence IDs | Value |
| --- | --- |
| Before | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |
| After | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |

Context basis: `all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation`.

Satisfied answer units: `["initial_observations"]`. Missing/unassessed units: `[]`.

| Changed signal field | Before | After |
| --- | --- | --- |
| `topical_relevance.returned_top_bm25_score` | `4.08038795` | `4.11675257` |
| `topical_relevance.returned_top_cosine_score` | `0.85033943` | `0.85033941` |

## `rd-vi-proxy-technique-assessment`

> Đánh giá hiện tại đối với ATT&CK T1218.005 có mức hỗ trợ bằng chứng và trạng thái review nào?

| Field | Before | After |
| --- | --- | --- |
| actual_decision | `"abstain"` | `"abstain"` |
| context_sufficient | `true` | `true` |
| abstention_stage | `"topical_relevance"` | `"topical_relevance"` |
| reason_codes | `["query_token_coverage_below_threshold","returned_top_cosine_score_below_threshold"]` | `["query_token_coverage_below_threshold","returned_top_cosine_score_below_threshold"]` |
| topical_relevance | `"failed"` | `"failed"` |
| evidence_answerability | `"not_evaluated"` | `"not_evaluated"` |

| Hit rank | Before source pointer | After source pointer |
| --- | --- | --- |
| 1 | `/mitre_assessments/2` | `/mitre_assessments/2` |
| 2 | `/mitre_assessments/1` | `/mitre_assessments/1` |
| 3 | `/mitre_assessments/0` | `/mitre_assessments/0` |
| 4 | `/summary/limitations/3` | `/summary/limitations/3` |
| 5 | `/summary/limitations/1` | `/summary/limitations/1` |

| Returned evidence IDs | Value |
| --- | --- |
| Before | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |
| After | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |

Context basis: `all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation`.

Satisfied answer units: `["proxy_assessment"]`. Missing/unassessed units: `[]`.

| Changed signal field | Before | After |
| --- | --- | --- |
| `topical_relevance.returned_top_bm25_score` | `4.44302297` | `5.39340971` |
| `topical_relevance.returned_top_cosine_score` | `0.79762617` | `0.79762618` |

## `rd-vi-reviewed-scope-limitations`

> Ground Truth ghi nhận những giới hạn nào đối với phạm vi bằng chứng đã review?

| Field | Before | After |
| --- | --- | --- |
| actual_decision | `"abstain"` | `"abstain"` |
| context_sufficient | `false` | `null` |
| abstention_stage | `"topical_relevance"` | `"topical_relevance"` |
| reason_codes | `["returned_top_cosine_score_below_threshold"]` | `["returned_top_cosine_score_below_threshold"]` |
| topical_relevance | `"failed"` | `"failed"` |
| evidence_answerability | `"not_evaluated"` | `"not_evaluated"` |

| Hit rank | Before source pointer | After source pointer |
| --- | --- | --- |
| 1 | `/summary/limitations/0` | `/summary/limitations/0` |
| 2 | `/mitre_assessments/1` | `/summary/limitations/3` |
| 3 | `/mitre_assessments/2` | `/mitre_assessments/1` |
| 4 | `/mitre_assessments/0` | `/mitre_assessments/2` |
| 5 | `/summary/limitations/3` | `/mitre_assessments/0` |

| Returned evidence IDs | Value |
| --- | --- |
| Before | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |
| After | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |

Context basis: `semantic_context_sufficiency_unassessed_conservative_screen_incomplete`.

Satisfied answer units: `["limitation_0","limitation_3"]`. Missing/unassessed units: `["limitation_1","limitation_2","limitation_4","limitation_5","limitation_6"]`.

| Missing/unassessed unit | Source pointer | Support status | Reason |
| --- | --- | --- | --- |
| `limitation_1` | `/summary/limitations/1` | unassessed | `no_exact_limitation_support_semantic_sufficiency_not_established` |
| `limitation_2` | `/summary/limitations/2` | unassessed | `no_exact_limitation_support_semantic_sufficiency_not_established` |
| `limitation_4` | `/summary/limitations/4` | unassessed | `no_exact_limitation_support_semantic_sufficiency_not_established` |
| `limitation_5` | `/summary/limitations/5` | unassessed | `no_exact_limitation_support_semantic_sufficiency_not_established` |
| `limitation_6` | `/summary/limitations/6` | unassessed | `no_exact_limitation_support_semantic_sufficiency_not_established` |

| Changed signal field | Before | After |
| --- | --- | --- |
| `topical_relevance.returned_top_bm25_score` | `6.53632059` | `5.89020896` |
| `topical_relevance.returned_top_cosine_score` | `0.7719129` | `0.77191291` |

## `rd-vi-scripting-technique-status`

> T1059.007 có được hỗ trợ bởi command line đã quan sát không, và trạng thái đánh giá là gì?

| Field | Before | After |
| --- | --- | --- |
| actual_decision | `"abstain"` | `"abstain"` |
| context_sufficient | `true` | `true` |
| abstention_stage | `"topical_relevance"` | `"topical_relevance"` |
| reason_codes | `["query_token_coverage_below_threshold","returned_top_cosine_score_below_threshold"]` | `["query_token_coverage_below_threshold","returned_top_cosine_score_below_threshold"]` |
| topical_relevance | `"failed"` | `"failed"` |
| evidence_answerability | `"not_evaluated"` | `"not_evaluated"` |

| Hit rank | Before source pointer | After source pointer |
| --- | --- | --- |
| 1 | `/mitre_assessments/0` | `/mitre_assessments/0` |
| 2 | `/scenario` | `/facts/1` |
| 3 | `/mitre_assessments/2` | `/facts/0` |
| 4 | `/mitre_assessments/1` | `/scenario` |
| 5 | `/relationships/1` | `/mitre_assessments/2` |

| Returned evidence IDs | Value |
| --- | --- |
| Before | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |
| After | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |

Context basis: `all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation`.

Satisfied answer units: `["scripting_assessment"]`. Missing/unassessed units: `[]`.

| Changed signal field | Before | After |
| --- | --- | --- |
| `evidence_answerability.chunk_type_counts.fact` | `0` | `2` |
| `evidence_answerability.chunk_type_counts.mitre_assessment` | `3` | `2` |
| `evidence_answerability.chunk_type_counts.relationship` | `1` | `0` |
| `evidence_answerability.hits_with_evidence_ids` | `3` | `4` |
| `evidence_answerability.hits_with_source_references` | `4` | `5` |
| `evidence_answerability.seed_node_count` | `6` | `5` |
| `evidence_answerability.status_counts.candidate` | `3` | `2` |
| `evidence_answerability.status_counts.observed` | `1` | `2` |
| `evidence_answerability.traversal_path_count` | `47` | `40` |
| `topical_relevance.joint_lexical_vector_hit_count` | `2` | `4` |
| `topical_relevance.lexical_hit_count` | `2` | `4` |
| `topical_relevance.returned_top_bm25_score` | `8.02574801` | `8.92160471` |
| `topical_relevance.returned_top_cosine_score` | `0.83420675` | `0.83420673` |

## `rp-en-intermediate-utility`

> Which Windows utility sits between the initial command interpreter and the final shell?

| Field | Before | After |
| --- | --- | --- |
| actual_decision | `"abstain"` | `"abstain"` |
| context_sufficient | `true` | `true` |
| abstention_stage | `"topical_relevance"` | `"topical_relevance"` |
| reason_codes | `["returned_top_cosine_score_below_threshold"]` | `["returned_top_cosine_score_below_threshold"]` |
| topical_relevance | `"failed"` | `"failed"` |
| evidence_answerability | `"not_evaluated"` | `"not_evaluated"` |

| Hit rank | Before source pointer | After source pointer |
| --- | --- | --- |
| 1 | `/mitre_assessments/0` | `/facts/0` |
| 2 | `/mitre_assessments/2` | `/facts/1` |
| 3 | `/scenario` | `/scenario` |
| 4 | `/mitre_assessments/1` | `/mitre_assessments/0` |
| 5 | `/summary/limitations/0` | `/mitre_assessments/2` |

| Returned evidence IDs | Value |
| --- | --- |
| Before | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |
| After | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |

Context basis: `all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation`.

Satisfied answer units: `["initial_spawn","final_spawn"]`. Missing/unassessed units: `[]`.

| Changed signal field | Before | After |
| --- | --- | --- |
| `evidence_answerability.chunk_type_counts.fact` | `0` | `2` |
| `evidence_answerability.chunk_type_counts.limitation` | `1` | `0` |
| `evidence_answerability.chunk_type_counts.mitre_assessment` | `3` | `2` |
| `evidence_answerability.hits_with_evidence_ids` | `2` | `4` |
| `evidence_answerability.hits_with_source_references` | `3` | `5` |
| `evidence_answerability.status_counts.candidate` | `3` | `2` |
| `evidence_answerability.status_counts.observed` | `0` | `2` |
| `evidence_answerability.status_counts.reviewable` | `2` | `1` |
| `evidence_answerability.traversal_edge_count` | `15` | `21` |
| `evidence_answerability.traversal_node_count` | `14` | `13` |
| `evidence_answerability.traversal_path_count` | `27` | `40` |
| `evidence_answerability.traversed_limitation_node_count` | `1` | `0` |
| `topical_relevance.matched_query_token_count` | `4` | `5` |
| `topical_relevance.query_token_coverage` | `0.33333333` | `0.41666667` |
| `topical_relevance.returned_top_bm25_score` | `4.84776025` | `6.00870081` |
| `topical_relevance.returned_top_cosine_score` | `0.79296716` | `0.79998104` |
| `topical_relevance.returned_top_rrf_score` | `0.032786885246` | `0.032266458496` |

## `rp-en-retained-scripting-label`

> Why does a scripting technique label remain in the record when the reviewed inline command uses a different scripting language?

| Field | Before | After |
| --- | --- | --- |
| actual_decision | `"proceed"` | `"proceed"` |
| context_sufficient | `true` | `true` |
| abstention_stage | `null` | `null` |
| reason_codes | `[]` | `[]` |
| topical_relevance | `"passed"` | `"passed"` |
| evidence_answerability | `"passed"` | `"passed"` |

| Hit rank | Before source pointer | After source pointer |
| --- | --- | --- |
| 1 | `/mitre_assessments/0` | `/mitre_assessments/0` |
| 2 | `/mitre_assessments/2` | `/mitre_assessments/2` |
| 3 | `/scenario` | `/scenario` |
| 4 | `/mitre_assessments/1` | `/facts/1` |
| 5 | `/summary/limitations/3` | `/mitre_assessments/1` |

| Returned evidence IDs | Value |
| --- | --- |
| Before | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |
| After | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |

Context basis: `all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation`.

Satisfied answer units: `["scripting_assessment","scripting_origin"]`. Missing/unassessed units: `[]`.

| Changed signal field | Before | After |
| --- | --- | --- |
| `evidence_answerability.chunk_type_counts.fact` | `0` | `1` |
| `evidence_answerability.chunk_type_counts.limitation` | `1` | `0` |
| `evidence_answerability.hits_with_evidence_ids` | `2` | `3` |
| `evidence_answerability.hits_with_source_references` | `3` | `4` |
| `evidence_answerability.status_counts.observed` | `0` | `1` |
| `evidence_answerability.status_counts.reviewable` | `2` | `1` |
| `evidence_answerability.traversal_edge_count` | `15` | `20` |
| `evidence_answerability.traversal_node_count` | `14` | `13` |
| `evidence_answerability.traversal_path_count` | `27` | `35` |
| `evidence_answerability.traversed_limitation_node_count` | `1` | `0` |
| `topical_relevance.matched_query_token_count` | `10` | `9` |
| `topical_relevance.query_token_coverage` | `0.58823529` | `0.52941176` |
| `topical_relevance.returned_top_bm25_score` | `8.58719052` | `9.41818544` |
| `topical_relevance.returned_top_cosine_score` | `0.84997559` | `0.84997561` |

## `rp-en-shell-creator`

> How can I trace the launch of the final shell back to its creator?

| Field | Before | After |
| --- | --- | --- |
| actual_decision | `"abstain"` | `"abstain"` |
| context_sufficient | `true` | `true` |
| abstention_stage | `"topical_relevance"` | `"topical_relevance"` |
| reason_codes | `["returned_top_cosine_score_below_threshold"]` | `["returned_top_cosine_score_below_threshold"]` |
| topical_relevance | `"failed"` | `"failed"` |
| evidence_answerability | `"not_evaluated"` | `"not_evaluated"` |

| Hit rank | Before source pointer | After source pointer |
| --- | --- | --- |
| 1 | `/mitre_assessments/2` | `/mitre_assessments/2` |
| 2 | `/mitre_assessments/1` | `/scenario` |
| 3 | `/mitre_assessments/0` | `/mitre_assessments/1` |
| 4 | `/summary/limitations/1` | `/mitre_assessments/0` |
| 5 | `/summary/limitations/2` | `/summary/limitations/5` |

| Returned evidence IDs | Value |
| --- | --- |
| Before | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |
| After | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |

Context basis: `all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation`.

Satisfied answer units: `["final_spawn","final_observations"]`. Missing/unassessed units: `[]`.

| Changed signal field | Before | After |
| --- | --- | --- |
| `evidence_answerability.chunk_type_counts.limitation` | `2` | `1` |
| `evidence_answerability.chunk_type_counts.scenario_summary` | `0` | `1` |
| `evidence_answerability.hits_with_source_references` | `2` | `3` |
| `evidence_answerability.traversed_limitation_node_count` | `2` | `1` |
| `topical_relevance.returned_top_bm25_score` | `7.40091956` | `7.7471347` |
| `topical_relevance.returned_top_cosine_score` | `0.80601208` | `0.81449298` |
| `topical_relevance.returned_top_rrf_score` | `0.031318815757` | `0.031099324976` |

## `rp-en-technique-review`

> Why is the proxy execution technique still awaiting analyst approval even though its behavior has supporting records?

| Field | Before | After |
| --- | --- | --- |
| actual_decision | `"abstain"` | `"abstain"` |
| context_sufficient | `true` | `true` |
| abstention_stage | `"topical_relevance"` | `"topical_relevance"` |
| reason_codes | `["returned_top_cosine_score_below_threshold"]` | `["returned_top_cosine_score_below_threshold"]` |
| topical_relevance | `"failed"` | `"failed"` |
| evidence_answerability | `"not_evaluated"` | `"not_evaluated"` |

| Hit rank | Before source pointer | After source pointer |
| --- | --- | --- |
| 1 | `/mitre_assessments/2` | `/mitre_assessments/2` |
| 2 | `/mitre_assessments/0` | `/mitre_assessments/0` |
| 3 | `/summary/limitations/2` | `/summary/limitations/2` |
| 4 | `/mitre_assessments/1` | `/summary/limitations/4` |
| 5 | `/sigma_findings/1` | `/mitre_assessments/1` |

| Returned evidence IDs | Value |
| --- | --- |
| Before | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |
| After | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |

Context basis: `all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation`.

Satisfied answer units: `["proxy_assessment"]`. Missing/unassessed units: `[]`.

| Changed signal field | Before | After |
| --- | --- | --- |
| `evidence_answerability.chunk_type_counts.limitation` | `1` | `2` |
| `evidence_answerability.chunk_type_counts.sigma_finding` | `1` | `0` |
| `evidence_answerability.hits_with_evidence_ids` | `3` | `2` |
| `evidence_answerability.hits_with_source_references` | `3` | `2` |
| `evidence_answerability.status_counts.candidate` | `4` | `3` |
| `evidence_answerability.status_counts.reviewable` | `1` | `2` |
| `evidence_answerability.traversal_node_count` | `13` | `14` |
| `evidence_answerability.traversal_path_count` | `36` | `27` |
| `evidence_answerability.traversed_limitation_node_count` | `1` | `2` |
| `topical_relevance.matched_query_token_count` | `6` | `5` |
| `topical_relevance.query_token_coverage` | `0.35294118` | `0.29411765` |
| `topical_relevance.returned_top_bm25_score` | `7.86140339` | `8.24836759` |

## `rp-vi-final-review-limits`

> Người phân tích còn phải xem lại điều gì trước khi đưa ra nhận định cuối cùng?

| Field | Before | After |
| --- | --- | --- |
| actual_decision | `"abstain"` | `"abstain"` |
| context_sufficient | `false` | `false` |
| abstention_stage | `"topical_relevance"` | `"topical_relevance"` |
| reason_codes | `["query_token_coverage_below_threshold","returned_top_cosine_score_below_threshold"]` | `["query_token_coverage_below_threshold","returned_top_cosine_score_below_threshold"]` |
| topical_relevance | `"failed"` | `"failed"` |
| evidence_answerability | `"not_evaluated"` | `"not_evaluated"` |

| Hit rank | Before source pointer | After source pointer |
| --- | --- | --- |
| 1 | `/mitre_assessments/1` | `/mitre_assessments/1` |
| 2 | `/mitre_assessments/0` | `/facts/0` |
| 3 | `/mitre_assessments/2` | `/facts/1` |
| 4 | `/facts/0` | `/mitre_assessments/0` |
| 5 | `/facts/1` | `/mitre_assessments/2` |

| Returned evidence IDs | Value |
| --- | --- |
| Before | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |
| After | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |

Context basis: `known_required_information_missing_from_actual_returned_context`.

Satisfied answer units: `[]`. Missing/unassessed units: `["analysis_status","limitation_0","limitation_1","limitation_2","limitation_3","limitation_4"]`.

| Missing/unassessed unit | Source pointer | Support status | Reason |
| --- | --- | --- | --- |
| `analysis_status` | `/scenario` | known_missing | `required_source_associated_structured_fields_not_returned` |
| `limitation_0` | `/summary/limitations/0` | unassessed | `no_exact_limitation_support_semantic_sufficiency_not_established` |
| `limitation_1` | `/summary/limitations/1` | unassessed | `no_exact_limitation_support_semantic_sufficiency_not_established` |
| `limitation_2` | `/summary/limitations/2` | unassessed | `no_exact_limitation_support_semantic_sufficiency_not_established` |
| `limitation_3` | `/summary/limitations/3` | unassessed | `no_exact_limitation_support_semantic_sufficiency_not_established` |
| `limitation_4` | `/summary/limitations/4` | unassessed | `no_exact_limitation_support_semantic_sufficiency_not_established` |

| Changed signal field | Before | After |
| --- | --- | --- |
| (none) | — | — |

## `rp-vi-launch-order`

> Nhìn các quan hệ cha-con đã lưu, làm thế nào dựng lại thứ tự khởi chạy ba tiến trình?

| Field | Before | After |
| --- | --- | --- |
| actual_decision | `"abstain"` | `"abstain"` |
| context_sufficient | `true` | `true` |
| abstention_stage | `"topical_relevance"` | `"topical_relevance"` |
| reason_codes | `["query_token_coverage_below_threshold","returned_top_cosine_score_below_threshold"]` | `["query_token_coverage_below_threshold","returned_top_cosine_score_below_threshold"]` |
| topical_relevance | `"failed"` | `"failed"` |
| evidence_answerability | `"not_evaluated"` | `"not_evaluated"` |

| Hit rank | Before source pointer | After source pointer |
| --- | --- | --- |
| 1 | `/relationships/1` | `/facts/0` |
| 2 | `/relationships/0` | `/relationships/1` |
| 3 | `/facts/0` | `/facts/1` |
| 4 | `/facts/1` | `/relationships/0` |
| 5 | `/summary/limitations/1` | `/summary/limitations/6` |

| Returned evidence IDs | Value |
| --- | --- |
| Before | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |
| After | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |

Context basis: `all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation`.

Satisfied answer units: `["initial_spawn","final_spawn"]`. Missing/unassessed units: `[]`.

| Changed signal field | Before | After |
| --- | --- | --- |
| `topical_relevance.returned_top_cosine_score` | `0.78778485` | `0.79364885` |

## `rp-vi-observation-provenance`

> Những bản ghi telemetry nào cùng làm căn cứ cho mỗi lần tạo tiến trình trong hai nhóm bằng chứng?

| Field | Before | After |
| --- | --- | --- |
| actual_decision | `"abstain"` | `"abstain"` |
| context_sufficient | `true` | `true` |
| abstention_stage | `"topical_relevance"` | `"topical_relevance"` |
| reason_codes | `["query_token_coverage_below_threshold","returned_top_cosine_score_below_threshold"]` | `["query_token_coverage_below_threshold","returned_top_cosine_score_below_threshold"]` |
| topical_relevance | `"failed"` | `"failed"` |
| evidence_answerability | `"not_evaluated"` | `"not_evaluated"` |

| Hit rank | Before source pointer | After source pointer |
| --- | --- | --- |
| 1 | `/mitre_assessments/1` | `/summary/limitations/6` |
| 2 | `/mitre_assessments/2` | `/summary/limitations/4` |
| 3 | `/facts/0` | `/mitre_assessments/1` |
| 4 | `/relationships/1` | `/mitre_assessments/2` |
| 5 | `/mitre_assessments/0` | `/facts/0` |

| Returned evidence IDs | Value |
| --- | --- |
| Before | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |
| After | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |

Context basis: `all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation`.

Satisfied answer units: `["initial_observations","final_observations"]`. Missing/unassessed units: `[]`.

| Changed signal field | Before | After |
| --- | --- | --- |
| `evidence_answerability.chunk_type_counts.limitation` | `0` | `2` |
| `evidence_answerability.chunk_type_counts.mitre_assessment` | `3` | `2` |
| `evidence_answerability.chunk_type_counts.relationship` | `1` | `0` |
| `evidence_answerability.hits_with_evidence_ids` | `4` | `2` |
| `evidence_answerability.hits_with_source_references` | `4` | `2` |
| `evidence_answerability.seed_node_count` | `6` | `5` |
| `evidence_answerability.status_counts.candidate` | `3` | `2` |
| `evidence_answerability.status_counts.observed` | `2` | `1` |
| `evidence_answerability.status_counts.reviewable` | `0` | `2` |
| `evidence_answerability.traversal_edge_count` | `21` | `20` |
| `evidence_answerability.traversal_node_count` | `12` | `14` |
| `evidence_answerability.traversal_path_count` | `56` | `29` |
| `evidence_answerability.traversed_limitation_node_count` | `0` | `2` |
| `topical_relevance.joint_lexical_vector_hit_count` | `0` | `2` |
| `topical_relevance.lexical_hit_count` | `0` | `2` |
| `topical_relevance.matched_query_token_count` | `0` | `1` |
| `topical_relevance.query_token_coverage` | `0.0` | `0.05` |
| `topical_relevance.returned_top_bm25_score` | `null` | `2.75460572` |
| `topical_relevance.returned_top_cosine_score` | `0.78163017` | `0.80113376` |
| `topical_relevance.returned_top_rrf_score` | `0.016393442623` | `0.032522474881` |

## `rp-vi-service-action`

> Lệnh liên quan đến dịch vụ được ghi nhận trên command line khi PowerShell được khởi chạy là gì?

| Field | Before | After |
| --- | --- | --- |
| actual_decision | `"abstain"` | `"abstain"` |
| context_sufficient | `false` | `null` |
| abstention_stage | `"topical_relevance"` | `"topical_relevance"` |
| reason_codes | `["query_token_coverage_below_threshold","returned_top_cosine_score_below_threshold"]` | `["query_token_coverage_below_threshold","returned_top_cosine_score_below_threshold"]` |
| topical_relevance | `"failed"` | `"failed"` |
| evidence_answerability | `"not_evaluated"` | `"not_evaluated"` |

| Hit rank | Before source pointer | After source pointer |
| --- | --- | --- |
| 1 | `/scenario` | `/scenario` |
| 2 | `/mitre_assessments/2` | `/facts/1` |
| 3 | `/mitre_assessments/0` | `/facts/0` |
| 4 | `/relationships/0` | `/mitre_assessments/2` |
| 5 | `/entities/2` | `/mitre_assessments/0` |

| Returned evidence IDs | Value |
| --- | --- |
| Before | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |
| After | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |

Context basis: `semantic_context_sufficiency_unassessed_conservative_screen_incomplete`.

Satisfied answer units: `["launch_command"]`. Missing/unassessed units: `["limitation_4"]`.

| Missing/unassessed unit | Source pointer | Support status | Reason |
| --- | --- | --- | --- |
| `limitation_4` | `/summary/limitations/4` | unassessed | `no_exact_limitation_support_semantic_sufficiency_not_established` |

| Changed signal field | Before | After |
| --- | --- | --- |
| `evidence_answerability.chunk_type_counts.entity` | `1` | `0` |
| `evidence_answerability.chunk_type_counts.fact` | `0` | `2` |
| `evidence_answerability.chunk_type_counts.relationship` | `1` | `0` |
| `evidence_answerability.traversal_path_count` | `41` | `40` |
| `topical_relevance.joint_lexical_vector_hit_count` | `3` | `5` |
| `topical_relevance.lexical_hit_count` | `3` | `5` |
| `topical_relevance.returned_top_bm25_score` | `4.97909685` | `5.34340338` |
| `topical_relevance.returned_top_cosine_score` | `0.84055646` | `0.83447589` |

## `ur-en-linux-cron`

> How do I schedule a Linux cron job to run every ten minutes?

| Field | Before | After |
| --- | --- | --- |
| actual_decision | `"abstain"` | `"proceed"` |
| context_sufficient | `null` | `null` |
| abstention_stage | `"topical_relevance"` | `null` |
| reason_codes | `["query_token_coverage_below_threshold","returned_top_cosine_score_below_threshold"]` | `[]` |
| topical_relevance | `"failed"` | `"passed"` |
| evidence_answerability | `"not_evaluated"` | `"passed"` |

| Hit rank | Before source pointer | After source pointer |
| --- | --- | --- |
| 1 | `/mitre_assessments/1` | `/facts/0` |
| 2 | `/scenario` | `/facts/1` |
| 3 | `/summary/limitations/2` | `/mitre_assessments/1` |
| 4 | `/mitre_assessments/0` | `/summary/limitations/6` |
| 5 | `/relationships/1` | `/scenario` |

| Returned evidence IDs | Value |
| --- | --- |
| Before | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |
| After | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |

Context basis: `outside_scope_answerability_not_applicable`.

Satisfied answer units: `[]`. Missing/unassessed units: `[]`.

| Changed signal field | Before | After |
| --- | --- | --- |
| `evidence_answerability.chunk_type_counts.fact` | `0` | `2` |
| `evidence_answerability.chunk_type_counts.mitre_assessment` | `2` | `1` |
| `evidence_answerability.chunk_type_counts.relationship` | `1` | `0` |
| `evidence_answerability.seed_node_count` | `6` | `5` |
| `evidence_answerability.status_counts.candidate` | `2` | `1` |
| `evidence_answerability.status_counts.observed` | `1` | `2` |
| `evidence_answerability.traversal_path_count` | `36` | `26` |
| `topical_relevance.joint_lexical_vector_hit_count` | `3` | `5` |
| `topical_relevance.lexical_hit_count` | `3` | `5` |
| `topical_relevance.matched_query_token_count` | `2` | `3` |
| `topical_relevance.query_token_coverage` | `0.15384615` | `0.23076923` |
| `topical_relevance.returned_top_bm25_score` | `3.27570207` | `3.91216101` |
| `topical_relevance.returned_top_cosine_score` | `0.81452207` | `0.84683677` |
| `topical_relevance.returned_top_rrf_score` | `0.031778058008` | `0.032266458496` |

## `ur-en-product-price`

> What is the current price of a gaming laptop?

| Field | Before | After |
| --- | --- | --- |
| actual_decision | `"abstain"` | `"abstain"` |
| context_sufficient | `null` | `null` |
| abstention_stage | `"topical_relevance"` | `"topical_relevance"` |
| reason_codes | `["returned_top_cosine_score_below_threshold"]` | `["returned_top_cosine_score_below_threshold"]` |
| topical_relevance | `"failed"` | `"failed"` |
| evidence_answerability | `"not_evaluated"` | `"not_evaluated"` |

| Hit rank | Before source pointer | After source pointer |
| --- | --- | --- |
| 1 | `/mitre_assessments/0` | `/mitre_assessments/0` |
| 2 | `/mitre_assessments/1` | `/mitre_assessments/1` |
| 3 | `/mitre_assessments/2` | `/mitre_assessments/2` |
| 4 | `/summary/limitations/1` | `/summary/limitations/6` |
| 5 | `/scenario` | `/summary/limitations/1` |

| Returned evidence IDs | Value |
| --- | --- |
| Before | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |
| After | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |

Context basis: `outside_scope_answerability_not_applicable`.

Satisfied answer units: `[]`. Missing/unassessed units: `[]`.

| Changed signal field | Before | After |
| --- | --- | --- |
| `evidence_answerability.chunk_type_counts.limitation` | `1` | `2` |
| `evidence_answerability.chunk_type_counts.scenario_summary` | `1` | `0` |
| `evidence_answerability.hits_with_source_references` | `3` | `2` |
| `evidence_answerability.traversed_limitation_node_count` | `1` | `2` |
| `topical_relevance.returned_top_bm25_score` | `6.47970629` | `6.81559186` |
| `topical_relevance.returned_top_cosine_score` | `0.75130365` | `0.75130367` |
| `topical_relevance.returned_top_rrf_score` | `0.032018442623` | `0.031544957774` |

## `ur-en-sql-injection`

> How can I prevent SQL injection in a web application's database queries?

| Field | Before | After |
| --- | --- | --- |
| actual_decision | `"abstain"` | `"abstain"` |
| context_sufficient | `null` | `null` |
| abstention_stage | `"topical_relevance"` | `"topical_relevance"` |
| reason_codes | `["query_token_coverage_below_threshold","returned_top_cosine_score_below_threshold"]` | `["query_token_coverage_below_threshold","returned_top_cosine_score_below_threshold"]` |
| topical_relevance | `"failed"` | `"failed"` |
| evidence_answerability | `"not_evaluated"` | `"not_evaluated"` |

| Hit rank | Before source pointer | After source pointer |
| --- | --- | --- |
| 1 | `/summary/limitations/2` | `/summary/limitations/2` |
| 2 | `/mitre_assessments/0` | `/mitre_assessments/0` |
| 3 | `/mitre_assessments/1` | `/summary/limitations/6` |
| 4 | `/scenario` | `/scenario` |
| 5 | `/mitre_assessments/2` | `/mitre_assessments/1` |

| Returned evidence IDs | Value |
| --- | --- |
| Before | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |
| After | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |

Context basis: `outside_scope_answerability_not_applicable`.

Satisfied answer units: `[]`. Missing/unassessed units: `[]`.

| Changed signal field | Before | After |
| --- | --- | --- |
| `evidence_answerability.chunk_type_counts.limitation` | `1` | `2` |
| `evidence_answerability.chunk_type_counts.mitre_assessment` | `3` | `2` |
| `evidence_answerability.hits_with_evidence_ids` | `2` | `1` |
| `evidence_answerability.hits_with_source_references` | `3` | `2` |
| `evidence_answerability.status_counts.candidate` | `3` | `2` |
| `evidence_answerability.status_counts.reviewable` | `2` | `3` |
| `evidence_answerability.support_edge_count` | `15` | `9` |
| `evidence_answerability.traversal_edge_count` | `15` | `9` |
| `evidence_answerability.traversal_node_count` | `14` | `11` |
| `evidence_answerability.traversal_path_count` | `27` | `16` |
| `evidence_answerability.traversed_evidence_node_count` | `2` | `1` |
| `evidence_answerability.traversed_limitation_node_count` | `1` | `2` |
| `topical_relevance.returned_top_bm25_score` | `2.34638997` | `2.62222294` |
| `topical_relevance.returned_top_cosine_score` | `0.8121783` | `0.81217832` |
| `topical_relevance.returned_top_rrf_score` | `0.032002048131` | `0.031498015873` |

## `ur-en-weather`

> What will the weather be in Hanoi tomorrow?

| Field | Before | After |
| --- | --- | --- |
| actual_decision | `"abstain"` | `"abstain"` |
| context_sufficient | `null` | `null` |
| abstention_stage | `"topical_relevance"` | `"topical_relevance"` |
| reason_codes | `["returned_top_cosine_score_below_threshold"]` | `["returned_top_cosine_score_below_threshold"]` |
| topical_relevance | `"failed"` | `"failed"` |
| evidence_answerability | `"not_evaluated"` | `"not_evaluated"` |

| Hit rank | Before source pointer | After source pointer |
| --- | --- | --- |
| 1 | `/summary/limitations/1` | `/summary/limitations/6` |
| 2 | `/mitre_assessments/1` | `/mitre_assessments/0` |
| 3 | `/mitre_assessments/0` | `/summary/limitations/1` |
| 4 | `/summary/limitations/2` | `/mitre_assessments/1` |
| 5 | `/mitre_assessments/2` | `/summary/limitations/2` |

| Returned evidence IDs | Value |
| --- | --- |
| Before | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |
| After | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |

Context basis: `outside_scope_answerability_not_applicable`.

Satisfied answer units: `[]`. Missing/unassessed units: `[]`.

| Changed signal field | Before | After |
| --- | --- | --- |
| `evidence_answerability.chunk_type_counts.limitation` | `2` | `3` |
| `evidence_answerability.chunk_type_counts.mitre_assessment` | `3` | `2` |
| `evidence_answerability.hits_with_evidence_ids` | `2` | `1` |
| `evidence_answerability.hits_with_source_references` | `2` | `1` |
| `evidence_answerability.status_counts.candidate` | `3` | `2` |
| `evidence_answerability.status_counts.reviewable` | `2` | `3` |
| `evidence_answerability.support_edge_count` | `15` | `9` |
| `evidence_answerability.traversal_edge_count` | `15` | `9` |
| `evidence_answerability.traversal_node_count` | `14` | `11` |
| `evidence_answerability.traversal_path_count` | `27` | `16` |
| `evidence_answerability.traversed_evidence_node_count` | `2` | `1` |
| `evidence_answerability.traversed_limitation_node_count` | `2` | `3` |
| `evidence_answerability.unique_source_reference_count` | `4` | `2` |
| `topical_relevance.returned_top_bm25_score` | `3.83130508` | `3.64201354` |
| `topical_relevance.returned_top_cosine_score` | `0.73406129` | `0.73406128` |
| `topical_relevance.returned_top_rrf_score` | `0.031778058008` | `0.031257631258` |

## `ur-vi-kubernetes-configuration`

> Cần cấu hình Kubernetes thế nào để tự động mở rộng một Deployment?

| Field | Before | After |
| --- | --- | --- |
| actual_decision | `"abstain"` | `"abstain"` |
| context_sufficient | `null` | `null` |
| abstention_stage | `"topical_relevance"` | `"topical_relevance"` |
| reason_codes | `["query_token_coverage_below_threshold","returned_top_cosine_score_below_threshold"]` | `["query_token_coverage_below_threshold","returned_top_cosine_score_below_threshold"]` |
| topical_relevance | `"failed"` | `"failed"` |
| evidence_answerability | `"not_evaluated"` | `"not_evaluated"` |

| Hit rank | Before source pointer | After source pointer |
| --- | --- | --- |
| 1 | `/mitre_assessments/1` | `/facts/0` |
| 2 | `/entities/2` | `/facts/1` |
| 3 | `/entities/0` | `/mitre_assessments/1` |
| 4 | `/relationships/0` | `/summary/limitations/6` |
| 5 | `/relationships/1` | `/entities/2` |

| Returned evidence IDs | Value |
| --- | --- |
| Before | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |
| After | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |

Context basis: `outside_scope_answerability_not_applicable`.

Satisfied answer units: `[]`. Missing/unassessed units: `[]`.

| Changed signal field | Before | After |
| --- | --- | --- |
| `evidence_answerability.chunk_type_counts.entity` | `2` | `1` |
| `evidence_answerability.chunk_type_counts.fact` | `0` | `2` |
| `evidence_answerability.chunk_type_counts.limitation` | `0` | `1` |
| `evidence_answerability.chunk_type_counts.relationship` | `2` | `0` |
| `evidence_answerability.hits_with_evidence_ids` | `4` | `3` |
| `evidence_answerability.hits_with_source_references` | `4` | `3` |
| `evidence_answerability.seed_node_count` | `4` | `5` |
| `evidence_answerability.status_counts.observed` | `4` | `3` |
| `evidence_answerability.status_counts.reviewable` | `0` | `1` |
| `evidence_answerability.traversal_node_count` | `12` | `13` |
| `evidence_answerability.traversal_path_count` | `35` | `34` |
| `evidence_answerability.traversed_limitation_node_count` | `0` | `1` |
| `topical_relevance.returned_top_cosine_score` | `0.77706801` | `0.80022951` |

## `ur-vi-literature-learning`

> Làm thế nào phân biệt hình ảnh ẩn dụ và hoán dụ trong một bài thơ?

| Field | Before | After |
| --- | --- | --- |
| actual_decision | `"abstain"` | `"abstain"` |
| context_sufficient | `null` | `null` |
| abstention_stage | `"topical_relevance"` | `"topical_relevance"` |
| reason_codes | `["query_token_coverage_below_threshold","returned_top_cosine_score_below_threshold"]` | `["query_token_coverage_below_threshold","returned_top_cosine_score_below_threshold"]` |
| topical_relevance | `"failed"` | `"failed"` |
| evidence_answerability | `"not_evaluated"` | `"not_evaluated"` |

| Hit rank | Before source pointer | After source pointer |
| --- | --- | --- |
| 1 | `/mitre_assessments/1` | `/facts/0` |
| 2 | `/relationships/0` | `/facts/1` |
| 3 | `/relationships/1` | `/mitre_assessments/1` |
| 4 | `/entities/2` | `/relationships/0` |
| 5 | `/facts/1` | `/relationships/1` |

| Returned evidence IDs | Value |
| --- | --- |
| Before | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |
| After | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |

Context basis: `outside_scope_answerability_not_applicable`.

Satisfied answer units: `[]`. Missing/unassessed units: `[]`.

| Changed signal field | Before | After |
| --- | --- | --- |
| `evidence_answerability.chunk_type_counts.entity` | `1` | `0` |
| `evidence_answerability.chunk_type_counts.fact` | `1` | `2` |
| `evidence_answerability.seed_node_count` | `5` | `6` |
| `evidence_answerability.traversal_path_count` | `44` | `54` |
| `topical_relevance.returned_top_cosine_score` | `0.73637269` | `0.76547387` |

## `ur-vi-opaque-token`

> Chuỗi velora_quartz_token_483920761 có ý nghĩa gì?

| Field | Before | After |
| --- | --- | --- |
| actual_decision | `"abstain"` | `"abstain"` |
| context_sufficient | `null` | `null` |
| abstention_stage | `"topical_relevance"` | `"topical_relevance"` |
| reason_codes | `["query_token_coverage_below_threshold","returned_top_cosine_score_below_threshold"]` | `["query_token_coverage_below_threshold","returned_top_cosine_score_below_threshold"]` |
| topical_relevance | `"failed"` | `"failed"` |
| evidence_answerability | `"not_evaluated"` | `"not_evaluated"` |

| Hit rank | Before source pointer | After source pointer |
| --- | --- | --- |
| 1 | `/relationships/1` | `/facts/0` |
| 2 | `/facts/0` | `/facts/1` |
| 3 | `/facts/1` | `/relationships/1` |
| 4 | `/relationships/0` | `/relationships/0` |
| 5 | `/entities/1` | `/entities/1` |

| Returned evidence IDs | Value |
| --- | --- |
| Before | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |
| After | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |

Context basis: `outside_scope_answerability_not_applicable`.

Satisfied answer units: `[]`. Missing/unassessed units: `[]`.

| Changed signal field | Before | After |
| --- | --- | --- |
| `topical_relevance.returned_top_cosine_score` | `0.75798392` | `0.79176038` |

## `ur-vi-ransomware-encryption`

> Mã hóa ransomware xử lý các khóa mật mã như thế nào?

| Field | Before | After |
| --- | --- | --- |
| actual_decision | `"abstain"` | `"abstain"` |
| context_sufficient | `null` | `null` |
| abstention_stage | `"topical_relevance"` | `"topical_relevance"` |
| reason_codes | `["query_token_coverage_below_threshold","returned_top_cosine_score_below_threshold"]` | `["query_token_coverage_below_threshold","returned_top_cosine_score_below_threshold"]` |
| topical_relevance | `"failed"` | `"failed"` |
| evidence_answerability | `"not_evaluated"` | `"not_evaluated"` |

| Hit rank | Before source pointer | After source pointer |
| --- | --- | --- |
| 1 | `/relationships/1` | `/facts/0` |
| 2 | `/relationships/0` | `/facts/1` |
| 3 | `/evidence/1` | `/relationships/1` |
| 4 | `/evidence/0` | `/relationships/0` |
| 5 | `/entities/0` | `/summary/limitations/6` |

| Returned evidence IDs | Value |
| --- | --- |
| Before | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |
| After | `["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"]` |

Context basis: `outside_scope_answerability_not_applicable`.

Satisfied answer units: `[]`. Missing/unassessed units: `[]`.

| Changed signal field | Before | After |
| --- | --- | --- |
| `evidence_answerability.chunk_type_counts.entity` | `1` | `0` |
| `evidence_answerability.chunk_type_counts.evidence` | `2` | `0` |
| `evidence_answerability.chunk_type_counts.fact` | `0` | `2` |
| `evidence_answerability.chunk_type_counts.limitation` | `0` | `1` |
| `evidence_answerability.hits_with_evidence_ids` | `5` | `4` |
| `evidence_answerability.hits_with_source_references` | `5` | `4` |
| `evidence_answerability.seed_node_count` | `5` | `6` |
| `evidence_answerability.status_counts.observed` | `5` | `4` |
| `evidence_answerability.status_counts.reviewable` | `0` | `1` |
| `evidence_answerability.support_edge_count` | `15` | `11` |
| `evidence_answerability.traversal_edge_count` | `21` | `17` |
| `evidence_answerability.traversal_path_count` | `52` | `50` |
| `evidence_answerability.traversed_limitation_node_count` | `0` | `1` |
| `topical_relevance.returned_top_cosine_score` | `0.7825986` | `0.80556518` |
