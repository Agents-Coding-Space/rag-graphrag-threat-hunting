# Kết quả từng case — calibration

Policy `two-stage-dev-5a4b308b106699e0`; toàn bộ 32 cases là development/calibration. Không có held-out results.

`expected_decision` là nhãn dataset đã duyệt. `context_sufficient` là đánh giá ngoài gate bằng conservative AI rubric trên context thực sự đã trả về; không phải nhãn human approval mới. `null` nghĩa chưa áp dụng/chưa đủ nhãn, không phải `false`. Các IDs/refs mong đợi chỉ dùng đối chiếu bên ngoài, không bổ sung context hoặc signals.

Signals đầy đủ nằm ở [signals.json](signals.json), actual contexts ở [contexts.json](contexts.json), diagnostics ở [external_context_adjudication.json](external_context_adjudication.json). Dưới đây giữ nguyên toàn bộ signals của từng case và không dereference raw refs.

| Case | Category | Expected | Actual | Abstention stage | Context sufficient |
| --- | --- | --- | --- | --- | --- |
| ie-en-attacker-identity | insufficient_evidence | abstain | abstain | topical_relevance | false |
| ie-en-c2-address | insufficient_evidence | abstain | abstain | topical_relevance | false |
| ie-en-payload-download-url | insufficient_evidence | abstain | proceed | null | false |
| ie-en-stolen-credentials | insufficient_evidence | abstain | abstain | topical_relevance | false |
| ie-vi-certain-attack-determination | insufficient_evidence | abstain | abstain | topical_relevance | false |
| ie-vi-decoded-content | insufficient_evidence | abstain | abstain | topical_relevance | false |
| ie-vi-decoding-proof | insufficient_evidence | abstain | abstain | topical_relevance | false |
| ie-vi-destructive-files | insufficient_evidence | abstain | abstain | topical_relevance | false |
| rd-en-final-spawn-evidence | relevant_direct | proceed | proceed | null | true |
| rd-en-initial-spawn-evidence | relevant_direct | proceed | proceed | null | true |
| rd-en-process-chain | relevant_direct | proceed | proceed | null | true |
| rd-en-shell-parent | relevant_direct | proceed | proceed | null | true |
| rd-vi-initial-relation-provenance | relevant_direct | proceed | abstain | topical_relevance | true |
| rd-vi-proxy-technique-assessment | relevant_direct | proceed | abstain | topical_relevance | true |
| rd-vi-reviewed-scope-limitations | relevant_direct | proceed | abstain | topical_relevance | false |
| rd-vi-scripting-technique-status | relevant_direct | proceed | abstain | topical_relevance | true |
| rp-en-intermediate-utility | relevant_paraphrase | proceed | abstain | topical_relevance | true |
| rp-en-retained-scripting-label | relevant_paraphrase | proceed | proceed | null | true |
| rp-en-shell-creator | relevant_paraphrase | proceed | abstain | topical_relevance | true |
| rp-en-technique-review | relevant_paraphrase | proceed | abstain | topical_relevance | true |
| rp-vi-final-review-limits | relevant_paraphrase | proceed | abstain | topical_relevance | false |
| rp-vi-launch-order | relevant_paraphrase | proceed | abstain | topical_relevance | true |
| rp-vi-observation-provenance | relevant_paraphrase | proceed | abstain | topical_relevance | true |
| rp-vi-service-action | relevant_paraphrase | proceed | abstain | topical_relevance | false |
| ur-en-linux-cron | unrelated | abstain | abstain | topical_relevance | null |
| ur-en-product-price | unrelated | abstain | abstain | topical_relevance | null |
| ur-en-sql-injection | unrelated | abstain | abstain | topical_relevance | null |
| ur-en-weather | unrelated | abstain | abstain | topical_relevance | null |
| ur-vi-kubernetes-configuration | unrelated | abstain | abstain | topical_relevance | null |
| ur-vi-literature-learning | unrelated | abstain | abstain | topical_relevance | null |
| ur-vi-opaque-token | unrelated | abstain | abstain | topical_relevance | null |
| ur-vi-ransomware-encryption | unrelated | abstain | abstain | topical_relevance | null |

## ie-en-attacker-identity

Câu hỏi (en): Who was the attacker responsible for the reviewed MSHTA execution?

| Thuộc tính | Giá trị |
| --- | --- |
| Partition | calibration |
| Category | insufficient_evidence |
| Expected decision (dataset) | abstain |
| Actual decision | abstain |
| Abstention stage | topical_relevance |
| Reason codes | ["returned_top_cosine_score_below_threshold"] |
| Topical expected label | true |
| Dataset answerable | false |
| Actual context sufficient | false |
| External context basis | approved_category_marks_requested_assertion_unsupported_not_scope_explanation |
| Topical actual stage status | failed |
| Answerability actual stage status | not_evaluated |

Đáp án tham chiếu đã duyệt (evaluation only; giữ nguyên nội dung lịch sử):

Không đủ bằng chứng để quy kết danh tính kẻ tấn công. Process và tài khoản chạy tiến trình trong telemetry chỉ là thực thể quan sát, không chứng minh người hoặc nhóm chịu trách nhiệm; ground truth chưa có attribution được duyệt.

Đối chiếu expected evidence và context thực tế; đây là diagnostic ngoài gate:

```json
{
  "ground_truth_pointers": [
    "/evidence/0",
    "/evidence/1",
    "/scenario",
    "/summary/limitations/0",
    "/summary/limitations/2"
  ],
  "raw_record_references": [],
  "expected_evidence_ids": [],
  "returned_evidence_ids": [
    "evidence-b07a5ff4763e629715e6",
    "evidence-b31714b888d1489a380c"
  ],
  "missing_expected_evidence_ids": [],
  "missing_evidence_diagnostics": [],
  "external_context_sufficiency_basis": "approved_category_marks_requested_assertion_unsupported_not_scope_explanation"
}
```

Signals đầy đủ đã cung cấp cho gate:

```json
{
  "schema_version": "graphrag-gate-signals/v1",
  "corpus_id": "retrieval-corpus--631ff39273344120e671693f867fbb47057f029d5de0c982d90c7b27e508d7b9",
  "graph_id": "knowledge-graph--45c9e1a1369012689417635f46b00e25ea0b5be2d39a6cf9375428d302ce27ea",
  "scenario_id": "mshta-powershell",
  "source_ground_truth": {
    "path": "outputs/ground_truth/mshta-powershell/scenario_ground_truth.json",
    "schema_version": "scenario-ground-truth/v1",
    "sha256": "b2e3aa48c2c20e6a49479e765db0a1d660121fdb70472ca36f308b1094ddbc41",
    "scenario_id": "mshta-powershell"
  },
  "query": {
    "text": "Who was the attacker responsible for the reviewed MSHTA execution?",
    "normalized_terms": [
      "who",
      "was",
      "the",
      "attacker",
      "responsible",
      "for",
      "reviewed",
      "mshta",
      "execution"
    ],
    "top_k": 5,
    "candidate_k": 20,
    "filters": {
      "chunk_types": null,
      "required_dimensions": null
    }
  },
  "topical_relevance": {
    "retrieval_hit_count": 5,
    "lexical_hit_count": 5,
    "vector_hit_count": 5,
    "joint_lexical_vector_hit_count": 5,
    "returned_top_rrf_score": 0.032786885246,
    "returned_top_bm25_score": 6.61899551,
    "returned_top_cosine_score": 0.82283651,
    "query_token_count": 9,
    "matched_query_token_count": 5,
    "query_token_coverage": 0.55555556
  },
  "evidence_answerability": {
    "chunk_type_counts": {
      "scenario_summary": 1,
      "entity": 0,
      "fact": 0,
      "relationship": 0,
      "evidence": 0,
      "sigma_finding": 2,
      "mitre_assessment": 2,
      "limitation": 0
    },
    "status_counts": {
      "candidate": 4,
      "inferred": 0,
      "observed": 0,
      "reviewable": 1
    },
    "hits_with_evidence_ids": 4,
    "hits_with_source_references": 5,
    "unique_source_reference_count": 4,
    "mapped_hit_count": 5,
    "seed_node_count": 5,
    "traversal_performed": true,
    "traversal_node_count": 13,
    "traversal_edge_count": 15,
    "traversal_path_count": 39,
    "traversed_evidence_node_count": 2,
    "traversed_limitation_node_count": 0,
    "support_edge_count": 15
  },
  "warnings": [],
  "metadata": {
    "decision_made": false,
    "score_interpretations": {
      "rrf": "reciprocal_rank_fusion_not_probability",
      "bm25": "bm25_relevance_not_probability",
      "cosine": "cosine_similarity_not_probability"
    },
    "topical_signal_count": 10,
    "answerability_signal_count": 14
  }
}
```

## ie-en-c2-address

Câu hỏi (en): What IP address acted as the C2 server for the PowerShell process?

| Thuộc tính | Giá trị |
| --- | --- |
| Partition | calibration |
| Category | insufficient_evidence |
| Expected decision (dataset) | abstain |
| Actual decision | abstain |
| Abstention stage | topical_relevance |
| Reason codes | ["returned_top_cosine_score_below_threshold"] |
| Topical expected label | true |
| Dataset answerable | false |
| Actual context sufficient | false |
| External context basis | approved_category_marks_requested_assertion_unsupported_not_scope_explanation |
| Topical actual stage status | failed |
| Answerability actual stage status | not_evaluated |

Đáp án tham chiếu đã duyệt (evaluation only; giữ nguyên nội dung lịch sử):

Không đủ bằng chứng để xác định IP C2 cho PowerShell trong chuỗi MSHTA. Hai nhóm evidence này không cung cấp quan hệ C2 hay endpoint tương ứng; không được gán IP từ kịch bản khác hoặc coi giới hạn hiện có là kết luận vắng mặt trên toàn dataset.

Đối chiếu expected evidence và context thực tế; đây là diagnostic ngoài gate:

```json
{
  "ground_truth_pointers": [
    "/evidence/1",
    "/scenario",
    "/summary/limitations/0",
    "/summary/limitations/2"
  ],
  "raw_record_references": [],
  "expected_evidence_ids": [],
  "returned_evidence_ids": [
    "evidence-b07a5ff4763e629715e6",
    "evidence-b31714b888d1489a380c"
  ],
  "missing_expected_evidence_ids": [],
  "missing_evidence_diagnostics": [],
  "external_context_sufficiency_basis": "approved_category_marks_requested_assertion_unsupported_not_scope_explanation"
}
```

Signals đầy đủ đã cung cấp cho gate:

```json
{
  "schema_version": "graphrag-gate-signals/v1",
  "corpus_id": "retrieval-corpus--631ff39273344120e671693f867fbb47057f029d5de0c982d90c7b27e508d7b9",
  "graph_id": "knowledge-graph--45c9e1a1369012689417635f46b00e25ea0b5be2d39a6cf9375428d302ce27ea",
  "scenario_id": "mshta-powershell",
  "source_ground_truth": {
    "path": "outputs/ground_truth/mshta-powershell/scenario_ground_truth.json",
    "schema_version": "scenario-ground-truth/v1",
    "sha256": "b2e3aa48c2c20e6a49479e765db0a1d660121fdb70472ca36f308b1094ddbc41",
    "scenario_id": "mshta-powershell"
  },
  "query": {
    "text": "What IP address acted as the C2 server for the PowerShell process?",
    "normalized_terms": [
      "what",
      "ip",
      "address",
      "acted",
      "as",
      "the",
      "c2",
      "server",
      "for",
      "powershell",
      "process"
    ],
    "top_k": 5,
    "candidate_k": 20,
    "filters": {
      "chunk_types": null,
      "required_dimensions": null
    }
  },
  "topical_relevance": {
    "retrieval_hit_count": 5,
    "lexical_hit_count": 5,
    "vector_hit_count": 5,
    "joint_lexical_vector_hit_count": 5,
    "returned_top_rrf_score": 0.031754032258,
    "returned_top_bm25_score": 5.49900495,
    "returned_top_cosine_score": 0.80232751,
    "query_token_count": 11,
    "matched_query_token_count": 5,
    "query_token_coverage": 0.45454545
  },
  "evidence_answerability": {
    "chunk_type_counts": {
      "scenario_summary": 1,
      "entity": 2,
      "fact": 0,
      "relationship": 0,
      "evidence": 0,
      "sigma_finding": 0,
      "mitre_assessment": 2,
      "limitation": 0
    },
    "status_counts": {
      "candidate": 2,
      "inferred": 0,
      "observed": 2,
      "reviewable": 1
    },
    "hits_with_evidence_ids": 4,
    "hits_with_source_references": 5,
    "unique_source_reference_count": 4,
    "mapped_hit_count": 5,
    "seed_node_count": 5,
    "traversal_performed": true,
    "traversal_node_count": 13,
    "traversal_edge_count": 21,
    "traversal_path_count": 40,
    "traversed_evidence_node_count": 2,
    "traversed_limitation_node_count": 0,
    "support_edge_count": 15
  },
  "warnings": [],
  "metadata": {
    "decision_made": false,
    "score_interpretations": {
      "rrf": "reciprocal_rank_fusion_not_probability",
      "bm25": "bm25_relevance_not_probability",
      "cosine": "cosine_similarity_not_probability"
    },
    "topical_signal_count": 10,
    "answerability_signal_count": 14
  }
}
```

## ie-en-payload-download-url

Câu hỏi (en): Which URL did PowerShell use to download the payload in this MSHTA chain?

| Thuộc tính | Giá trị |
| --- | --- |
| Partition | calibration |
| Category | insufficient_evidence |
| Expected decision (dataset) | abstain |
| Actual decision | proceed |
| Abstention stage | null |
| Reason codes | [] |
| Topical expected label | true |
| Dataset answerable | false |
| Actual context sufficient | false |
| External context basis | approved_category_marks_requested_assertion_unsupported_not_scope_explanation |
| Topical actual stage status | passed |
| Answerability actual stage status | passed |

Đáp án tham chiếu đã duyệt (evaluation only; giữ nguyên nội dung lịch sử):

Không đủ bằng chứng để nêu URL tải payload. Hai evidence groups đã lưu chủ yếu là process creation; command line ghi Get-Service sysmon, không cung cấp download URL. Không được bịa URL hoặc kết luận mọi download đều vắng mặt trên toàn dataset từ ground truth giới hạn này.

Đối chiếu expected evidence và context thực tế; đây là diagnostic ngoài gate:

```json
{
  "ground_truth_pointers": [
    "/evidence/1",
    "/scenario",
    "/summary/limitations/0",
    "/summary/limitations/2"
  ],
  "raw_record_references": [],
  "expected_evidence_ids": [],
  "returned_evidence_ids": [
    "evidence-b07a5ff4763e629715e6",
    "evidence-b31714b888d1489a380c"
  ],
  "missing_expected_evidence_ids": [],
  "missing_evidence_diagnostics": [],
  "external_context_sufficiency_basis": "approved_category_marks_requested_assertion_unsupported_not_scope_explanation"
}
```

Signals đầy đủ đã cung cấp cho gate:

```json
{
  "schema_version": "graphrag-gate-signals/v1",
  "corpus_id": "retrieval-corpus--631ff39273344120e671693f867fbb47057f029d5de0c982d90c7b27e508d7b9",
  "graph_id": "knowledge-graph--45c9e1a1369012689417635f46b00e25ea0b5be2d39a6cf9375428d302ce27ea",
  "scenario_id": "mshta-powershell",
  "source_ground_truth": {
    "path": "outputs/ground_truth/mshta-powershell/scenario_ground_truth.json",
    "schema_version": "scenario-ground-truth/v1",
    "sha256": "b2e3aa48c2c20e6a49479e765db0a1d660121fdb70472ca36f308b1094ddbc41",
    "scenario_id": "mshta-powershell"
  },
  "query": {
    "text": "Which URL did PowerShell use to download the payload in this MSHTA chain?",
    "normalized_terms": [
      "which",
      "url",
      "did",
      "powershell",
      "use",
      "to",
      "download",
      "the",
      "payload",
      "in",
      "this",
      "mshta",
      "chain"
    ],
    "top_k": 5,
    "candidate_k": 20,
    "filters": {
      "chunk_types": null,
      "required_dimensions": null
    }
  },
  "topical_relevance": {
    "retrieval_hit_count": 5,
    "lexical_hit_count": 5,
    "vector_hit_count": 5,
    "joint_lexical_vector_hit_count": 5,
    "returned_top_rrf_score": 0.032786885246,
    "returned_top_bm25_score": 9.45800735,
    "returned_top_cosine_score": 0.85933597,
    "query_token_count": 13,
    "matched_query_token_count": 7,
    "query_token_coverage": 0.53846154
  },
  "evidence_answerability": {
    "chunk_type_counts": {
      "scenario_summary": 1,
      "entity": 0,
      "fact": 0,
      "relationship": 0,
      "evidence": 0,
      "sigma_finding": 2,
      "mitre_assessment": 2,
      "limitation": 0
    },
    "status_counts": {
      "candidate": 4,
      "inferred": 0,
      "observed": 0,
      "reviewable": 1
    },
    "hits_with_evidence_ids": 3,
    "hits_with_source_references": 4,
    "unique_source_reference_count": 4,
    "mapped_hit_count": 5,
    "seed_node_count": 5,
    "traversal_performed": true,
    "traversal_node_count": 13,
    "traversal_edge_count": 15,
    "traversal_path_count": 36,
    "traversed_evidence_node_count": 2,
    "traversed_limitation_node_count": 0,
    "support_edge_count": 15
  },
  "warnings": [],
  "metadata": {
    "decision_made": false,
    "score_interpretations": {
      "rrf": "reciprocal_rank_fusion_not_probability",
      "bm25": "bm25_relevance_not_probability",
      "cosine": "cosine_similarity_not_probability"
    },
    "topical_signal_count": 10,
    "answerability_signal_count": 14
  }
}
```

## ie-en-stolen-credentials

Câu hỏi (en): Which credentials did PowerShell steal during this activity?

| Thuộc tính | Giá trị |
| --- | --- |
| Partition | calibration |
| Category | insufficient_evidence |
| Expected decision (dataset) | abstain |
| Actual decision | abstain |
| Abstention stage | topical_relevance |
| Reason codes | ["returned_top_cosine_score_below_threshold"] |
| Topical expected label | true |
| Dataset answerable | false |
| Actual context sufficient | false |
| External context basis | approved_category_marks_requested_assertion_unsupported_not_scope_explanation |
| Topical actual stage status | failed |
| Answerability actual stage status | not_evaluated |

Đáp án tham chiếu đã duyệt (evaluation only; giữ nguyên nội dung lịch sử):

Không đủ bằng chứng để nêu thông tin xác thực bị đánh cắp. Evidence và summary hiện có không chứng minh credential theft hay cung cấp stolen values; command line Get-Service sysmon không tự chứng minh hành vi này. Không suy rộng thành kết luận toàn dataset không có đánh cắp thông tin xác thực.

Đối chiếu expected evidence và context thực tế; đây là diagnostic ngoài gate:

```json
{
  "ground_truth_pointers": [
    "/evidence/1",
    "/scenario",
    "/summary/limitations/0",
    "/summary/limitations/2"
  ],
  "raw_record_references": [],
  "expected_evidence_ids": [],
  "returned_evidence_ids": [
    "evidence-b07a5ff4763e629715e6",
    "evidence-b31714b888d1489a380c"
  ],
  "missing_expected_evidence_ids": [],
  "missing_evidence_diagnostics": [],
  "external_context_sufficiency_basis": "approved_category_marks_requested_assertion_unsupported_not_scope_explanation"
}
```

Signals đầy đủ đã cung cấp cho gate:

```json
{
  "schema_version": "graphrag-gate-signals/v1",
  "corpus_id": "retrieval-corpus--631ff39273344120e671693f867fbb47057f029d5de0c982d90c7b27e508d7b9",
  "graph_id": "knowledge-graph--45c9e1a1369012689417635f46b00e25ea0b5be2d39a6cf9375428d302ce27ea",
  "scenario_id": "mshta-powershell",
  "source_ground_truth": {
    "path": "outputs/ground_truth/mshta-powershell/scenario_ground_truth.json",
    "schema_version": "scenario-ground-truth/v1",
    "sha256": "b2e3aa48c2c20e6a49479e765db0a1d660121fdb70472ca36f308b1094ddbc41",
    "scenario_id": "mshta-powershell"
  },
  "query": {
    "text": "Which credentials did PowerShell steal during this activity?",
    "normalized_terms": [
      "which",
      "credentials",
      "did",
      "powershell",
      "steal",
      "during",
      "this",
      "activity"
    ],
    "top_k": 5,
    "candidate_k": 20,
    "filters": {
      "chunk_types": null,
      "required_dimensions": null
    }
  },
  "topical_relevance": {
    "retrieval_hit_count": 5,
    "lexical_hit_count": 4,
    "vector_hit_count": 5,
    "joint_lexical_vector_hit_count": 4,
    "returned_top_rrf_score": 0.032522474881,
    "returned_top_bm25_score": 6.32696917,
    "returned_top_cosine_score": 0.81822838,
    "query_token_count": 8,
    "matched_query_token_count": 3,
    "query_token_coverage": 0.375
  },
  "evidence_answerability": {
    "chunk_type_counts": {
      "scenario_summary": 1,
      "entity": 0,
      "fact": 0,
      "relationship": 0,
      "evidence": 1,
      "sigma_finding": 0,
      "mitre_assessment": 2,
      "limitation": 1
    },
    "status_counts": {
      "candidate": 2,
      "inferred": 0,
      "observed": 1,
      "reviewable": 2
    },
    "hits_with_evidence_ids": 2,
    "hits_with_source_references": 3,
    "unique_source_reference_count": 4,
    "mapped_hit_count": 5,
    "seed_node_count": 5,
    "traversal_performed": true,
    "traversal_node_count": 14,
    "traversal_edge_count": 20,
    "traversal_path_count": 29,
    "traversed_evidence_node_count": 2,
    "traversed_limitation_node_count": 1,
    "support_edge_count": 15
  },
  "warnings": [],
  "metadata": {
    "decision_made": false,
    "score_interpretations": {
      "rrf": "reciprocal_rank_fusion_not_probability",
      "bm25": "bm25_relevance_not_probability",
      "cosine": "cosine_similarity_not_probability"
    },
    "topical_signal_count": 10,
    "answerability_signal_count": 14
  }
}
```

## ie-vi-certain-attack-determination

Câu hỏi (vi): Có thể khẳng định chắc chắn toàn bộ chuỗi cmd.exe, mshta.exe và powershell.exe là một cuộc tấn công không?

| Thuộc tính | Giá trị |
| --- | --- |
| Partition | calibration |
| Category | insufficient_evidence |
| Expected decision (dataset) | abstain |
| Actual decision | abstain |
| Abstention stage | topical_relevance |
| Reason codes | ["query_token_coverage_below_threshold"] |
| Topical expected label | true |
| Dataset answerable | false |
| Actual context sufficient | false |
| External context basis | approved_category_marks_requested_assertion_unsupported_not_scope_explanation |
| Topical actual stage status | failed |
| Answerability actual stage status | not_evaluated |

Đáp án tham chiếu đã duyệt (evaluation only; giữ nguyên nội dung lịch sử):

Chưa thể khẳng định chắc chắn toàn bộ chuỗi là cuộc tấn công từ ground truth hiện có. Quan hệ cha-con và command line đáng chú ý được quan sát, nhưng scenario còn draft_reviewable, MITRE assessments còn candidate và human review chưa hoàn tất. Có thể mô tả các hành vi được hỗ trợ, không nâng chúng thành nhận định chắc chắn được yêu cầu.

Đối chiếu expected evidence và context thực tế; đây là diagnostic ngoài gate:

```json
{
  "ground_truth_pointers": [
    "/mitre_assessments/2",
    "/scenario",
    "/summary/limitations/0",
    "/summary/limitations/2",
    "/summary/limitations/3"
  ],
  "raw_record_references": [],
  "expected_evidence_ids": [],
  "returned_evidence_ids": [
    "evidence-b07a5ff4763e629715e6",
    "evidence-b31714b888d1489a380c"
  ],
  "missing_expected_evidence_ids": [],
  "missing_evidence_diagnostics": [],
  "external_context_sufficiency_basis": "approved_category_marks_requested_assertion_unsupported_not_scope_explanation"
}
```

Signals đầy đủ đã cung cấp cho gate:

```json
{
  "schema_version": "graphrag-gate-signals/v1",
  "corpus_id": "retrieval-corpus--631ff39273344120e671693f867fbb47057f029d5de0c982d90c7b27e508d7b9",
  "graph_id": "knowledge-graph--45c9e1a1369012689417635f46b00e25ea0b5be2d39a6cf9375428d302ce27ea",
  "scenario_id": "mshta-powershell",
  "source_ground_truth": {
    "path": "outputs/ground_truth/mshta-powershell/scenario_ground_truth.json",
    "schema_version": "scenario-ground-truth/v1",
    "sha256": "b2e3aa48c2c20e6a49479e765db0a1d660121fdb70472ca36f308b1094ddbc41",
    "scenario_id": "mshta-powershell"
  },
  "query": {
    "text": "Có thể khẳng định chắc chắn toàn bộ chuỗi cmd.exe, mshta.exe và powershell.exe là một cuộc tấn công không?",
    "normalized_terms": [
      "có",
      "thể",
      "khẳng",
      "định",
      "chắc",
      "chắn",
      "toàn",
      "bộ",
      "chuỗi",
      "cmd.exe",
      "mshta.exe",
      "và",
      "powershell.exe",
      "là",
      "một",
      "cuộc",
      "tấn",
      "công",
      "không"
    ],
    "top_k": 5,
    "candidate_k": 20,
    "filters": {
      "chunk_types": null,
      "required_dimensions": null
    }
  },
  "topical_relevance": {
    "retrieval_hit_count": 5,
    "lexical_hit_count": 5,
    "vector_hit_count": 5,
    "joint_lexical_vector_hit_count": 5,
    "returned_top_rrf_score": 0.032266458496,
    "returned_top_bm25_score": 4.08038795,
    "returned_top_cosine_score": 0.86500817,
    "query_token_count": 19,
    "matched_query_token_count": 3,
    "query_token_coverage": 0.15789474
  },
  "evidence_answerability": {
    "chunk_type_counts": {
      "scenario_summary": 1,
      "entity": 0,
      "fact": 0,
      "relationship": 2,
      "evidence": 2,
      "sigma_finding": 0,
      "mitre_assessment": 0,
      "limitation": 0
    },
    "status_counts": {
      "candidate": 0,
      "inferred": 0,
      "observed": 4,
      "reviewable": 1
    },
    "hits_with_evidence_ids": 4,
    "hits_with_source_references": 5,
    "unique_source_reference_count": 4,
    "mapped_hit_count": 5,
    "seed_node_count": 6,
    "traversal_performed": true,
    "traversal_node_count": 13,
    "traversal_edge_count": 21,
    "traversal_path_count": 53,
    "traversed_evidence_node_count": 2,
    "traversed_limitation_node_count": 0,
    "support_edge_count": 15
  },
  "warnings": [],
  "metadata": {
    "decision_made": false,
    "score_interpretations": {
      "rrf": "reciprocal_rank_fusion_not_probability",
      "bm25": "bm25_relevance_not_probability",
      "cosine": "cosine_similarity_not_probability"
    },
    "topical_signal_count": 10,
    "answerability_signal_count": 14
  }
}
```

## ie-vi-decoded-content

Câu hỏi (vi): Nội dung payload đã được MSHTA hoặc PowerShell giải mã là gì?

| Thuộc tính | Giá trị |
| --- | --- |
| Partition | calibration |
| Category | insufficient_evidence |
| Expected decision (dataset) | abstain |
| Actual decision | abstain |
| Abstention stage | topical_relevance |
| Reason codes | ["query_token_coverage_below_threshold"] |
| Topical expected label | true |
| Dataset answerable | false |
| Actual context sufficient | false |
| External context basis | approved_category_marks_requested_assertion_unsupported_not_scope_explanation |
| Topical actual stage status | failed |
| Answerability actual stage status | not_evaluated |

Đáp án tham chiếu đã duyệt (evaluation only; giữ nguyên nội dung lịch sử):

Không đủ bằng chứng để đưa ra nội dung payload đã giải mã. Artifact có command line VBScript và Get-Service sysmon, nhưng không có căn cứ về thao tác giải mã hoặc kết quả giải mã; T1140 còn not_assessed. Không coi lệnh quan sát được là decoded payload.

Đối chiếu expected evidence và context thực tế; đây là diagnostic ngoài gate:

```json
{
  "ground_truth_pointers": [
    "/evidence/0",
    "/evidence/1",
    "/mitre_assessments/1",
    "/summary/limitations/0",
    "/summary/limitations/2"
  ],
  "raw_record_references": [],
  "expected_evidence_ids": [],
  "returned_evidence_ids": [
    "evidence-b07a5ff4763e629715e6",
    "evidence-b31714b888d1489a380c"
  ],
  "missing_expected_evidence_ids": [],
  "missing_evidence_diagnostics": [],
  "external_context_sufficiency_basis": "approved_category_marks_requested_assertion_unsupported_not_scope_explanation"
}
```

Signals đầy đủ đã cung cấp cho gate:

```json
{
  "schema_version": "graphrag-gate-signals/v1",
  "corpus_id": "retrieval-corpus--631ff39273344120e671693f867fbb47057f029d5de0c982d90c7b27e508d7b9",
  "graph_id": "knowledge-graph--45c9e1a1369012689417635f46b00e25ea0b5be2d39a6cf9375428d302ce27ea",
  "scenario_id": "mshta-powershell",
  "source_ground_truth": {
    "path": "outputs/ground_truth/mshta-powershell/scenario_ground_truth.json",
    "schema_version": "scenario-ground-truth/v1",
    "sha256": "b2e3aa48c2c20e6a49479e765db0a1d660121fdb70472ca36f308b1094ddbc41",
    "scenario_id": "mshta-powershell"
  },
  "query": {
    "text": "Nội dung payload đã được MSHTA hoặc PowerShell giải mã là gì?",
    "normalized_terms": [
      "nội",
      "dung",
      "payload",
      "đã",
      "được",
      "mshta",
      "hoặc",
      "powershell",
      "giải",
      "mã",
      "là",
      "gì"
    ],
    "top_k": 5,
    "candidate_k": 20,
    "filters": {
      "chunk_types": null,
      "required_dimensions": null
    }
  },
  "topical_relevance": {
    "retrieval_hit_count": 5,
    "lexical_hit_count": 4,
    "vector_hit_count": 5,
    "joint_lexical_vector_hit_count": 4,
    "returned_top_rrf_score": 0.032786885246,
    "returned_top_bm25_score": 5.53726515,
    "returned_top_cosine_score": 0.84299805,
    "query_token_count": 12,
    "matched_query_token_count": 2,
    "query_token_coverage": 0.16666667
  },
  "evidence_answerability": {
    "chunk_type_counts": {
      "scenario_summary": 1,
      "entity": 0,
      "fact": 0,
      "relationship": 1,
      "evidence": 0,
      "sigma_finding": 2,
      "mitre_assessment": 1,
      "limitation": 0
    },
    "status_counts": {
      "candidate": 3,
      "inferred": 0,
      "observed": 1,
      "reviewable": 1
    },
    "hits_with_evidence_ids": 4,
    "hits_with_source_references": 5,
    "unique_source_reference_count": 4,
    "mapped_hit_count": 5,
    "seed_node_count": 6,
    "traversal_performed": true,
    "traversal_node_count": 13,
    "traversal_edge_count": 21,
    "traversal_path_count": 51,
    "traversed_evidence_node_count": 2,
    "traversed_limitation_node_count": 0,
    "support_edge_count": 15
  },
  "warnings": [],
  "metadata": {
    "decision_made": false,
    "score_interpretations": {
      "rrf": "reciprocal_rank_fusion_not_probability",
      "bm25": "bm25_relevance_not_probability",
      "cosine": "cosine_similarity_not_probability"
    },
    "topical_signal_count": 10,
    "answerability_signal_count": 14
  }
}
```

## ie-vi-decoding-proof

Câu hỏi (vi): Bằng chứng nào chứng minh T1140 đã xảy ra trong chuỗi MSHTA?

| Thuộc tính | Giá trị |
| --- | --- |
| Partition | calibration |
| Category | insufficient_evidence |
| Expected decision (dataset) | abstain |
| Actual decision | abstain |
| Abstention stage | topical_relevance |
| Reason codes | ["returned_top_cosine_score_below_threshold"] |
| Topical expected label | true |
| Dataset answerable | false |
| Actual context sufficient | false |
| External context basis | approved_category_marks_requested_assertion_unsupported_not_scope_explanation |
| Topical actual stage status | failed |
| Answerability actual stage status | not_evaluated |

Đáp án tham chiếu đã duyệt (evaluation only; giữ nguyên nội dung lịch sử):

Ground truth hiện không có bằng chứng chứng minh T1140 đã xảy ra. /mitre_assessments/1 ghi status=candidate, evidence_support=not_assessed và supporting_evidence_ids rỗng; nhãn được giải quyết từ Sigma tag, không phải bằng chứng hành vi giải mã.

Đối chiếu expected evidence và context thực tế; đây là diagnostic ngoài gate:

```json
{
  "ground_truth_pointers": [
    "/mitre_assessments/1"
  ],
  "raw_record_references": [],
  "expected_evidence_ids": [],
  "returned_evidence_ids": [
    "evidence-b07a5ff4763e629715e6",
    "evidence-b31714b888d1489a380c"
  ],
  "missing_expected_evidence_ids": [],
  "missing_evidence_diagnostics": [],
  "external_context_sufficiency_basis": "approved_category_marks_requested_assertion_unsupported_not_scope_explanation"
}
```

Signals đầy đủ đã cung cấp cho gate:

```json
{
  "schema_version": "graphrag-gate-signals/v1",
  "corpus_id": "retrieval-corpus--631ff39273344120e671693f867fbb47057f029d5de0c982d90c7b27e508d7b9",
  "graph_id": "knowledge-graph--45c9e1a1369012689417635f46b00e25ea0b5be2d39a6cf9375428d302ce27ea",
  "scenario_id": "mshta-powershell",
  "source_ground_truth": {
    "path": "outputs/ground_truth/mshta-powershell/scenario_ground_truth.json",
    "schema_version": "scenario-ground-truth/v1",
    "sha256": "b2e3aa48c2c20e6a49479e765db0a1d660121fdb70472ca36f308b1094ddbc41",
    "scenario_id": "mshta-powershell"
  },
  "query": {
    "text": "Bằng chứng nào chứng minh T1140 đã xảy ra trong chuỗi MSHTA?",
    "normalized_terms": [
      "bằng",
      "chứng",
      "nào",
      "minh",
      "t1140",
      "đã",
      "xảy",
      "ra",
      "trong",
      "chuỗi",
      "mshta"
    ],
    "top_k": 5,
    "candidate_k": 20,
    "filters": {
      "chunk_types": null,
      "required_dimensions": null
    }
  },
  "topical_relevance": {
    "retrieval_hit_count": 5,
    "lexical_hit_count": 5,
    "vector_hit_count": 5,
    "joint_lexical_vector_hit_count": 5,
    "returned_top_rrf_score": 0.032786885246,
    "returned_top_bm25_score": 3.63931764,
    "returned_top_cosine_score": 0.80882298,
    "query_token_count": 11,
    "matched_query_token_count": 2,
    "query_token_coverage": 0.18181818
  },
  "evidence_answerability": {
    "chunk_type_counts": {
      "scenario_summary": 1,
      "entity": 0,
      "fact": 0,
      "relationship": 0,
      "evidence": 0,
      "sigma_finding": 2,
      "mitre_assessment": 2,
      "limitation": 0
    },
    "status_counts": {
      "candidate": 4,
      "inferred": 0,
      "observed": 0,
      "reviewable": 1
    },
    "hits_with_evidence_ids": 3,
    "hits_with_source_references": 4,
    "unique_source_reference_count": 4,
    "mapped_hit_count": 5,
    "seed_node_count": 5,
    "traversal_performed": true,
    "traversal_node_count": 13,
    "traversal_edge_count": 15,
    "traversal_path_count": 36,
    "traversed_evidence_node_count": 2,
    "traversed_limitation_node_count": 0,
    "support_edge_count": 15
  },
  "warnings": [],
  "metadata": {
    "decision_made": false,
    "score_interpretations": {
      "rrf": "reciprocal_rank_fusion_not_probability",
      "bm25": "bm25_relevance_not_probability",
      "cosine": "cosine_similarity_not_probability"
    },
    "topical_signal_count": 10,
    "answerability_signal_count": 14
  }
}
```

## ie-vi-destructive-files

Câu hỏi (vi): Trong hai nhóm process-creation evidence của ground truth, có bằng chứng nào cho thấy payload PowerShell cố ý phá hoại tệp không?

| Thuộc tính | Giá trị |
| --- | --- |
| Partition | calibration |
| Category | insufficient_evidence |
| Expected decision (dataset) | abstain |
| Actual decision | abstain |
| Abstention stage | topical_relevance |
| Reason codes | ["returned_top_cosine_score_below_threshold"] |
| Topical expected label | true |
| Dataset answerable | false |
| Actual context sufficient | false |
| External context basis | approved_category_marks_requested_assertion_unsupported_not_scope_explanation |
| Topical actual stage status | failed |
| Answerability actual stage status | not_evaluated |

Đáp án tham chiếu đã duyệt (evaluation only; giữ nguyên nội dung lịch sử):

Hai nhóm process-creation evidence không chứng minh payload PowerShell cố ý phá hoại tệp. Log gốc có record xóa tệp tạm, nhưng việc xóa tệp tạm không tự chứng minh ý định phá hoại và nằm ngoài hai nhóm evidence của core này. Không suy ra toàn dataset không có thao tác xóa tệp; câu hỏi liệt kê tệp đã xóa trong raw cần một phạm vi evidence khác.

Đối chiếu expected evidence và context thực tế; đây là diagnostic ngoài gate:

```json
{
  "ground_truth_pointers": [
    "/evidence/1",
    "/scenario",
    "/summary/limitations/0",
    "/summary/limitations/2",
    "/summary/limitations/6"
  ],
  "raw_record_references": [],
  "expected_evidence_ids": [],
  "returned_evidence_ids": [
    "evidence-b07a5ff4763e629715e6",
    "evidence-b31714b888d1489a380c"
  ],
  "missing_expected_evidence_ids": [],
  "missing_evidence_diagnostics": [],
  "external_context_sufficiency_basis": "approved_category_marks_requested_assertion_unsupported_not_scope_explanation"
}
```

Signals đầy đủ đã cung cấp cho gate:

```json
{
  "schema_version": "graphrag-gate-signals/v1",
  "corpus_id": "retrieval-corpus--631ff39273344120e671693f867fbb47057f029d5de0c982d90c7b27e508d7b9",
  "graph_id": "knowledge-graph--45c9e1a1369012689417635f46b00e25ea0b5be2d39a6cf9375428d302ce27ea",
  "scenario_id": "mshta-powershell",
  "source_ground_truth": {
    "path": "outputs/ground_truth/mshta-powershell/scenario_ground_truth.json",
    "schema_version": "scenario-ground-truth/v1",
    "sha256": "b2e3aa48c2c20e6a49479e765db0a1d660121fdb70472ca36f308b1094ddbc41",
    "scenario_id": "mshta-powershell"
  },
  "query": {
    "text": "Trong hai nhóm process-creation evidence của ground truth, có bằng chứng nào cho thấy payload PowerShell cố ý phá hoại tệp không?",
    "normalized_terms": [
      "trong",
      "hai",
      "nhóm",
      "process-creation",
      "evidence",
      "của",
      "ground",
      "truth",
      "có",
      "bằng",
      "chứng",
      "nào",
      "cho",
      "thấy",
      "payload",
      "powershell",
      "cố",
      "ý",
      "phá",
      "hoại",
      "tệp",
      "không"
    ],
    "top_k": 5,
    "candidate_k": 20,
    "filters": {
      "chunk_types": null,
      "required_dimensions": null
    }
  },
  "topical_relevance": {
    "retrieval_hit_count": 5,
    "lexical_hit_count": 5,
    "vector_hit_count": 5,
    "joint_lexical_vector_hit_count": 5,
    "returned_top_rrf_score": 0.030679156909,
    "returned_top_bm25_score": 6.2624113,
    "returned_top_cosine_score": 0.83579551,
    "query_token_count": 22,
    "matched_query_token_count": 4,
    "query_token_coverage": 0.18181818
  },
  "evidence_answerability": {
    "chunk_type_counts": {
      "scenario_summary": 1,
      "entity": 0,
      "fact": 0,
      "relationship": 0,
      "evidence": 2,
      "sigma_finding": 0,
      "mitre_assessment": 1,
      "limitation": 1
    },
    "status_counts": {
      "candidate": 1,
      "inferred": 0,
      "observed": 2,
      "reviewable": 2
    },
    "hits_with_evidence_ids": 3,
    "hits_with_source_references": 4,
    "unique_source_reference_count": 4,
    "mapped_hit_count": 5,
    "seed_node_count": 5,
    "traversal_performed": true,
    "traversal_node_count": 14,
    "traversal_edge_count": 21,
    "traversal_path_count": 36,
    "traversed_evidence_node_count": 2,
    "traversed_limitation_node_count": 1,
    "support_edge_count": 15
  },
  "warnings": [],
  "metadata": {
    "decision_made": false,
    "score_interpretations": {
      "rrf": "reciprocal_rank_fusion_not_probability",
      "bm25": "bm25_relevance_not_probability",
      "cosine": "cosine_similarity_not_probability"
    },
    "topical_signal_count": 10,
    "answerability_signal_count": 14
  }
}
```

## rd-en-final-spawn-evidence

Câu hỏi (en): What evidence supports the mshta.exe to powershell.exe process creation relationship?

| Thuộc tính | Giá trị |
| --- | --- |
| Partition | calibration |
| Category | relevant_direct |
| Expected decision (dataset) | proceed |
| Actual decision | proceed |
| Abstention stage | null |
| Reason codes | [] |
| Topical expected label | true |
| Dataset answerable | true |
| Actual context sufficient | true |
| External context basis | all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation |
| Topical actual stage status | passed |
| Answerability actual stage status | passed |

Đáp án tham chiếu đã duyệt (evaluation only; giữ nguyên nội dung lịch sử):

evidence-b31714b888d1489a380c giữ Security Event ID 4688 ở jsonl:line:30 và Sysmon Event ID 1 ở jsonl:line:398. ParentImage/ParentProcessName là mshta.exe, Image/NewProcessName là powershell.exe; PID cha 10980 tương ứng 0x2ae4, PID con 9572 tương ứng 0x2564. Sysmon ParentProcessGuid khớp ProcessGuid của mshta.exe trong nhóm đầu.

Đối chiếu expected evidence và context thực tế; đây là diagnostic ngoài gate:

```json
{
  "ground_truth_pointers": [
    "/evidence/1",
    "/facts/1",
    "/relationships/0"
  ],
  "raw_record_references": [
    {
      "raw_record_ref": "jsonl:line:30",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    },
    {
      "raw_record_ref": "jsonl:line:398",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    }
  ],
  "expected_evidence_ids": [
    "evidence-b31714b888d1489a380c"
  ],
  "returned_evidence_ids": [
    "evidence-b07a5ff4763e629715e6",
    "evidence-b31714b888d1489a380c"
  ],
  "missing_expected_evidence_ids": [],
  "missing_evidence_diagnostics": [],
  "external_context_sufficiency_basis": "all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation"
}
```

Signals đầy đủ đã cung cấp cho gate:

```json
{
  "schema_version": "graphrag-gate-signals/v1",
  "corpus_id": "retrieval-corpus--631ff39273344120e671693f867fbb47057f029d5de0c982d90c7b27e508d7b9",
  "graph_id": "knowledge-graph--45c9e1a1369012689417635f46b00e25ea0b5be2d39a6cf9375428d302ce27ea",
  "scenario_id": "mshta-powershell",
  "source_ground_truth": {
    "path": "outputs/ground_truth/mshta-powershell/scenario_ground_truth.json",
    "schema_version": "scenario-ground-truth/v1",
    "sha256": "b2e3aa48c2c20e6a49479e765db0a1d660121fdb70472ca36f308b1094ddbc41",
    "scenario_id": "mshta-powershell"
  },
  "query": {
    "text": "What evidence supports the mshta.exe to powershell.exe process creation relationship?",
    "normalized_terms": [
      "what",
      "evidence",
      "supports",
      "the",
      "mshta.exe",
      "to",
      "powershell.exe",
      "process",
      "creation",
      "relationship"
    ],
    "top_k": 5,
    "candidate_k": 20,
    "filters": {
      "chunk_types": null,
      "required_dimensions": null
    }
  },
  "topical_relevance": {
    "retrieval_hit_count": 5,
    "lexical_hit_count": 5,
    "vector_hit_count": 5,
    "joint_lexical_vector_hit_count": 5,
    "returned_top_rrf_score": 0.032522474881,
    "returned_top_bm25_score": 5.86702482,
    "returned_top_cosine_score": 0.91293862,
    "query_token_count": 10,
    "matched_query_token_count": 7,
    "query_token_coverage": 0.7
  },
  "evidence_answerability": {
    "chunk_type_counts": {
      "scenario_summary": 0,
      "entity": 1,
      "fact": 0,
      "relationship": 2,
      "evidence": 1,
      "sigma_finding": 0,
      "mitre_assessment": 1,
      "limitation": 0
    },
    "status_counts": {
      "candidate": 1,
      "inferred": 0,
      "observed": 4,
      "reviewable": 0
    },
    "hits_with_evidence_ids": 5,
    "hits_with_source_references": 5,
    "unique_source_reference_count": 4,
    "mapped_hit_count": 5,
    "seed_node_count": 5,
    "traversal_performed": true,
    "traversal_node_count": 12,
    "traversal_edge_count": 21,
    "traversal_path_count": 52,
    "traversed_evidence_node_count": 2,
    "traversed_limitation_node_count": 0,
    "support_edge_count": 15
  },
  "warnings": [],
  "metadata": {
    "decision_made": false,
    "score_interpretations": {
      "rrf": "reciprocal_rank_fusion_not_probability",
      "bm25": "bm25_relevance_not_probability",
      "cosine": "cosine_similarity_not_probability"
    },
    "topical_signal_count": 10,
    "answerability_signal_count": 14
  }
}
```

## rd-en-initial-spawn-evidence

Câu hỏi (en): What evidence supports the cmd.exe to mshta.exe process creation relationship?

| Thuộc tính | Giá trị |
| --- | --- |
| Partition | calibration |
| Category | relevant_direct |
| Expected decision (dataset) | proceed |
| Actual decision | proceed |
| Abstention stage | null |
| Reason codes | [] |
| Topical expected label | true |
| Dataset answerable | true |
| Actual context sufficient | true |
| External context basis | all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation |
| Topical actual stage status | passed |
| Answerability actual stage status | passed |

Đáp án tham chiếu đã duyệt (evaluation only; giữ nguyên nội dung lịch sử):

evidence-b07a5ff4763e629715e6 giữ Sysmon Event ID 1 ở jsonl:line:275 và Security Event ID 4688 ở jsonl:line:4. ParentImage/ParentProcessName là cmd.exe, Image/NewProcessName là mshta.exe; PID cha 5888 tương ứng 0x1700, PID con 10980 tương ứng 0x2ae4. Hai records hỗ trợ một quan hệ cmd.exe → mshta.exe.

Đối chiếu expected evidence và context thực tế; đây là diagnostic ngoài gate:

```json
{
  "ground_truth_pointers": [
    "/evidence/0",
    "/facts/0",
    "/relationships/1"
  ],
  "raw_record_references": [
    {
      "raw_record_ref": "jsonl:line:275",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    },
    {
      "raw_record_ref": "jsonl:line:4",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    }
  ],
  "expected_evidence_ids": [
    "evidence-b07a5ff4763e629715e6"
  ],
  "returned_evidence_ids": [
    "evidence-b07a5ff4763e629715e6",
    "evidence-b31714b888d1489a380c"
  ],
  "missing_expected_evidence_ids": [],
  "missing_evidence_diagnostics": [],
  "external_context_sufficiency_basis": "all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation"
}
```

Signals đầy đủ đã cung cấp cho gate:

```json
{
  "schema_version": "graphrag-gate-signals/v1",
  "corpus_id": "retrieval-corpus--631ff39273344120e671693f867fbb47057f029d5de0c982d90c7b27e508d7b9",
  "graph_id": "knowledge-graph--45c9e1a1369012689417635f46b00e25ea0b5be2d39a6cf9375428d302ce27ea",
  "scenario_id": "mshta-powershell",
  "source_ground_truth": {
    "path": "outputs/ground_truth/mshta-powershell/scenario_ground_truth.json",
    "schema_version": "scenario-ground-truth/v1",
    "sha256": "b2e3aa48c2c20e6a49479e765db0a1d660121fdb70472ca36f308b1094ddbc41",
    "scenario_id": "mshta-powershell"
  },
  "query": {
    "text": "What evidence supports the cmd.exe to mshta.exe process creation relationship?",
    "normalized_terms": [
      "what",
      "evidence",
      "supports",
      "the",
      "cmd.exe",
      "to",
      "mshta.exe",
      "process",
      "creation",
      "relationship"
    ],
    "top_k": 5,
    "candidate_k": 20,
    "filters": {
      "chunk_types": null,
      "required_dimensions": null
    }
  },
  "topical_relevance": {
    "retrieval_hit_count": 5,
    "lexical_hit_count": 5,
    "vector_hit_count": 5,
    "joint_lexical_vector_hit_count": 5,
    "returned_top_rrf_score": 0.032522474881,
    "returned_top_bm25_score": 5.86702482,
    "returned_top_cosine_score": 0.91129758,
    "query_token_count": 10,
    "matched_query_token_count": 6,
    "query_token_coverage": 0.6
  },
  "evidence_answerability": {
    "chunk_type_counts": {
      "scenario_summary": 0,
      "entity": 0,
      "fact": 0,
      "relationship": 2,
      "evidence": 2,
      "sigma_finding": 0,
      "mitre_assessment": 1,
      "limitation": 0
    },
    "status_counts": {
      "candidate": 1,
      "inferred": 0,
      "observed": 4,
      "reviewable": 0
    },
    "hits_with_evidence_ids": 5,
    "hits_with_source_references": 5,
    "unique_source_reference_count": 4,
    "mapped_hit_count": 5,
    "seed_node_count": 6,
    "traversal_performed": true,
    "traversal_node_count": 12,
    "traversal_edge_count": 21,
    "traversal_path_count": 64,
    "traversed_evidence_node_count": 2,
    "traversed_limitation_node_count": 0,
    "support_edge_count": 15
  },
  "warnings": [],
  "metadata": {
    "decision_made": false,
    "score_interpretations": {
      "rrf": "reciprocal_rank_fusion_not_probability",
      "bm25": "bm25_relevance_not_probability",
      "cosine": "cosine_similarity_not_probability"
    },
    "topical_signal_count": 10,
    "answerability_signal_count": 14
  }
}
```

## rd-en-process-chain

Câu hỏi (en): Which process chain led to powershell.exe in the reviewed evidence?

| Thuộc tính | Giá trị |
| --- | --- |
| Partition | calibration |
| Category | relevant_direct |
| Expected decision (dataset) | proceed |
| Actual decision | proceed |
| Abstention stage | null |
| Reason codes | [] |
| Topical expected label | true |
| Dataset answerable | true |
| Actual context sufficient | true |
| External context basis | all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation |
| Topical actual stage status | passed |
| Answerability actual stage status | passed |

Đáp án tham chiếu đã duyệt (evaluation only; giữ nguyên nội dung lịch sử):

Chuỗi được quan sát trên WORKSTATION5 là cmd.exe → mshta.exe → powershell.exe. fact-cmd-spawns-mshta và fact-mshta-spawns-powershell ghi hai quan hệ có hướng; Sysmon 1 ở lines 275/398 và Security 4688 ở lines 4/30 là các góc telemetry hỗ trợ cùng hai lần tạo tiến trình, không phải bốn lần tạo riêng.

Đối chiếu expected evidence và context thực tế; đây là diagnostic ngoài gate:

```json
{
  "ground_truth_pointers": [
    "/evidence/0",
    "/evidence/1",
    "/facts/0",
    "/facts/1",
    "/relationships/0",
    "/relationships/1",
    "/scenario"
  ],
  "raw_record_references": [
    {
      "raw_record_ref": "jsonl:line:275",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    },
    {
      "raw_record_ref": "jsonl:line:30",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    },
    {
      "raw_record_ref": "jsonl:line:398",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    },
    {
      "raw_record_ref": "jsonl:line:4",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    }
  ],
  "expected_evidence_ids": [
    "evidence-b07a5ff4763e629715e6",
    "evidence-b31714b888d1489a380c"
  ],
  "returned_evidence_ids": [
    "evidence-b07a5ff4763e629715e6",
    "evidence-b31714b888d1489a380c"
  ],
  "missing_expected_evidence_ids": [],
  "missing_evidence_diagnostics": [],
  "external_context_sufficiency_basis": "all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation"
}
```

Signals đầy đủ đã cung cấp cho gate:

```json
{
  "schema_version": "graphrag-gate-signals/v1",
  "corpus_id": "retrieval-corpus--631ff39273344120e671693f867fbb47057f029d5de0c982d90c7b27e508d7b9",
  "graph_id": "knowledge-graph--45c9e1a1369012689417635f46b00e25ea0b5be2d39a6cf9375428d302ce27ea",
  "scenario_id": "mshta-powershell",
  "source_ground_truth": {
    "path": "outputs/ground_truth/mshta-powershell/scenario_ground_truth.json",
    "schema_version": "scenario-ground-truth/v1",
    "sha256": "b2e3aa48c2c20e6a49479e765db0a1d660121fdb70472ca36f308b1094ddbc41",
    "scenario_id": "mshta-powershell"
  },
  "query": {
    "text": "Which process chain led to powershell.exe in the reviewed evidence?",
    "normalized_terms": [
      "which",
      "process",
      "chain",
      "led",
      "to",
      "powershell.exe",
      "in",
      "the",
      "reviewed",
      "evidence"
    ],
    "top_k": 5,
    "candidate_k": 20,
    "filters": {
      "chunk_types": null,
      "required_dimensions": null
    }
  },
  "topical_relevance": {
    "retrieval_hit_count": 5,
    "lexical_hit_count": 5,
    "vector_hit_count": 5,
    "joint_lexical_vector_hit_count": 5,
    "returned_top_rrf_score": 0.032258064516,
    "returned_top_bm25_score": 5.21188364,
    "returned_top_cosine_score": 0.86920244,
    "query_token_count": 10,
    "matched_query_token_count": 7,
    "query_token_coverage": 0.7
  },
  "evidence_answerability": {
    "chunk_type_counts": {
      "scenario_summary": 1,
      "entity": 1,
      "fact": 0,
      "relationship": 0,
      "evidence": 1,
      "sigma_finding": 0,
      "mitre_assessment": 2,
      "limitation": 0
    },
    "status_counts": {
      "candidate": 2,
      "inferred": 0,
      "observed": 2,
      "reviewable": 1
    },
    "hits_with_evidence_ids": 4,
    "hits_with_source_references": 5,
    "unique_source_reference_count": 4,
    "mapped_hit_count": 5,
    "seed_node_count": 5,
    "traversal_performed": true,
    "traversal_node_count": 13,
    "traversal_edge_count": 20,
    "traversal_path_count": 40,
    "traversed_evidence_node_count": 2,
    "traversed_limitation_node_count": 0,
    "support_edge_count": 15
  },
  "warnings": [],
  "metadata": {
    "decision_made": false,
    "score_interpretations": {
      "rrf": "reciprocal_rank_fusion_not_probability",
      "bm25": "bm25_relevance_not_probability",
      "cosine": "cosine_similarity_not_probability"
    },
    "topical_signal_count": 10,
    "answerability_signal_count": 14
  }
}
```

## rd-en-shell-parent

Câu hỏi (en): Which process is the observed parent of powershell.exe?

| Thuộc tính | Giá trị |
| --- | --- |
| Partition | calibration |
| Category | relevant_direct |
| Expected decision (dataset) | proceed |
| Actual decision | proceed |
| Abstention stage | null |
| Reason codes | [] |
| Topical expected label | true |
| Dataset answerable | true |
| Actual context sufficient | true |
| External context basis | all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation |
| Topical actual stage status | passed |
| Answerability actual stage status | passed |

Đáp án tham chiếu đã duyệt (evaluation only; giữ nguyên nội dung lịch sử):

Tiến trình cha của powershell.exe là mshta.exe. fact-mshta-spawns-powershell liên kết process-9c691740bde5d3dbdc4e với process-9f7ceeecb4cd61358ab7; evidence-b31714b888d1489a380c giữ refs jsonl:line:30 và jsonl:line:398.

Đối chiếu expected evidence và context thực tế; đây là diagnostic ngoài gate:

```json
{
  "ground_truth_pointers": [
    "/evidence/1",
    "/facts/1",
    "/relationships/0",
    "/scenario"
  ],
  "raw_record_references": [
    {
      "raw_record_ref": "jsonl:line:30",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    },
    {
      "raw_record_ref": "jsonl:line:398",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    }
  ],
  "expected_evidence_ids": [
    "evidence-b31714b888d1489a380c"
  ],
  "returned_evidence_ids": [
    "evidence-b07a5ff4763e629715e6",
    "evidence-b31714b888d1489a380c"
  ],
  "missing_expected_evidence_ids": [],
  "missing_evidence_diagnostics": [],
  "external_context_sufficiency_basis": "all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation"
}
```

Signals đầy đủ đã cung cấp cho gate:

```json
{
  "schema_version": "graphrag-gate-signals/v1",
  "corpus_id": "retrieval-corpus--631ff39273344120e671693f867fbb47057f029d5de0c982d90c7b27e508d7b9",
  "graph_id": "knowledge-graph--45c9e1a1369012689417635f46b00e25ea0b5be2d39a6cf9375428d302ce27ea",
  "scenario_id": "mshta-powershell",
  "source_ground_truth": {
    "path": "outputs/ground_truth/mshta-powershell/scenario_ground_truth.json",
    "schema_version": "scenario-ground-truth/v1",
    "sha256": "b2e3aa48c2c20e6a49479e765db0a1d660121fdb70472ca36f308b1094ddbc41",
    "scenario_id": "mshta-powershell"
  },
  "query": {
    "text": "Which process is the observed parent of powershell.exe?",
    "normalized_terms": [
      "which",
      "process",
      "is",
      "the",
      "observed",
      "parent",
      "of",
      "powershell.exe"
    ],
    "top_k": 5,
    "candidate_k": 20,
    "filters": {
      "chunk_types": null,
      "required_dimensions": null
    }
  },
  "topical_relevance": {
    "retrieval_hit_count": 5,
    "lexical_hit_count": 5,
    "vector_hit_count": 5,
    "joint_lexical_vector_hit_count": 5,
    "returned_top_rrf_score": 0.032522474881,
    "returned_top_bm25_score": 6.53857651,
    "returned_top_cosine_score": 0.87243352,
    "query_token_count": 8,
    "matched_query_token_count": 7,
    "query_token_coverage": 0.875
  },
  "evidence_answerability": {
    "chunk_type_counts": {
      "scenario_summary": 1,
      "entity": 1,
      "fact": 0,
      "relationship": 1,
      "evidence": 1,
      "sigma_finding": 0,
      "mitre_assessment": 1,
      "limitation": 0
    },
    "status_counts": {
      "candidate": 1,
      "inferred": 0,
      "observed": 3,
      "reviewable": 1
    },
    "hits_with_evidence_ids": 4,
    "hits_with_source_references": 5,
    "unique_source_reference_count": 4,
    "mapped_hit_count": 5,
    "seed_node_count": 5,
    "traversal_performed": true,
    "traversal_node_count": 13,
    "traversal_edge_count": 21,
    "traversal_path_count": 43,
    "traversed_evidence_node_count": 2,
    "traversed_limitation_node_count": 0,
    "support_edge_count": 15
  },
  "warnings": [],
  "metadata": {
    "decision_made": false,
    "score_interpretations": {
      "rrf": "reciprocal_rank_fusion_not_probability",
      "bm25": "bm25_relevance_not_probability",
      "cosine": "cosine_similarity_not_probability"
    },
    "topical_signal_count": 10,
    "answerability_signal_count": 14
  }
}
```

## rd-vi-initial-relation-provenance

Câu hỏi (vi): Nguồn log và raw record references nào hỗ trợ quan hệ cmd.exe tạo mshta.exe?

| Thuộc tính | Giá trị |
| --- | --- |
| Partition | calibration |
| Category | relevant_direct |
| Expected decision (dataset) | proceed |
| Actual decision | abstain |
| Abstention stage | topical_relevance |
| Reason codes | ["query_token_coverage_below_threshold"] |
| Topical expected label | true |
| Dataset answerable | true |
| Actual context sufficient | true |
| External context basis | all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation |
| Topical actual stage status | failed |
| Answerability actual stage status | not_evaluated |

Đáp án tham chiếu đã duyệt (evaluation only; giữ nguyên nội dung lịch sử):

Quan hệ cmd.exe tạo mshta.exe được truy về file cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json, tại jsonl:line:275 (Sysmon 1) và jsonl:line:4 (Security 4688). fact-cmd-spawns-mshta, relationship-9e41d0cc407e7878b2d8 và evidence-b07a5ff4763e629715e6 cùng giữ các refs này.

Đối chiếu expected evidence và context thực tế; đây là diagnostic ngoài gate:

```json
{
  "ground_truth_pointers": [
    "/evidence/0",
    "/facts/0",
    "/relationships/1"
  ],
  "raw_record_references": [
    {
      "raw_record_ref": "jsonl:line:275",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    },
    {
      "raw_record_ref": "jsonl:line:4",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    }
  ],
  "expected_evidence_ids": [
    "evidence-b07a5ff4763e629715e6"
  ],
  "returned_evidence_ids": [
    "evidence-b07a5ff4763e629715e6",
    "evidence-b31714b888d1489a380c"
  ],
  "missing_expected_evidence_ids": [],
  "missing_evidence_diagnostics": [],
  "external_context_sufficiency_basis": "all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation"
}
```

Signals đầy đủ đã cung cấp cho gate:

```json
{
  "schema_version": "graphrag-gate-signals/v1",
  "corpus_id": "retrieval-corpus--631ff39273344120e671693f867fbb47057f029d5de0c982d90c7b27e508d7b9",
  "graph_id": "knowledge-graph--45c9e1a1369012689417635f46b00e25ea0b5be2d39a6cf9375428d302ce27ea",
  "scenario_id": "mshta-powershell",
  "source_ground_truth": {
    "path": "outputs/ground_truth/mshta-powershell/scenario_ground_truth.json",
    "schema_version": "scenario-ground-truth/v1",
    "sha256": "b2e3aa48c2c20e6a49479e765db0a1d660121fdb70472ca36f308b1094ddbc41",
    "scenario_id": "mshta-powershell"
  },
  "query": {
    "text": "Nguồn log và raw record references nào hỗ trợ quan hệ cmd.exe tạo mshta.exe?",
    "normalized_terms": [
      "nguồn",
      "log",
      "và",
      "raw",
      "record",
      "references",
      "nào",
      "hỗ",
      "trợ",
      "quan",
      "hệ",
      "cmd.exe",
      "tạo",
      "mshta.exe"
    ],
    "top_k": 5,
    "candidate_k": 20,
    "filters": {
      "chunk_types": null,
      "required_dimensions": null
    }
  },
  "topical_relevance": {
    "retrieval_hit_count": 5,
    "lexical_hit_count": 5,
    "vector_hit_count": 5,
    "joint_lexical_vector_hit_count": 5,
    "returned_top_rrf_score": 0.032522474881,
    "returned_top_bm25_score": 4.08038795,
    "returned_top_cosine_score": 0.85033943,
    "query_token_count": 14,
    "matched_query_token_count": 2,
    "query_token_coverage": 0.14285714
  },
  "evidence_answerability": {
    "chunk_type_counts": {
      "scenario_summary": 1,
      "entity": 1,
      "fact": 0,
      "relationship": 2,
      "evidence": 1,
      "sigma_finding": 0,
      "mitre_assessment": 0,
      "limitation": 0
    },
    "status_counts": {
      "candidate": 0,
      "inferred": 0,
      "observed": 4,
      "reviewable": 1
    },
    "hits_with_evidence_ids": 4,
    "hits_with_source_references": 5,
    "unique_source_reference_count": 4,
    "mapped_hit_count": 5,
    "seed_node_count": 5,
    "traversal_performed": true,
    "traversal_node_count": 13,
    "traversal_edge_count": 21,
    "traversal_path_count": 43,
    "traversed_evidence_node_count": 2,
    "traversed_limitation_node_count": 0,
    "support_edge_count": 15
  },
  "warnings": [],
  "metadata": {
    "decision_made": false,
    "score_interpretations": {
      "rrf": "reciprocal_rank_fusion_not_probability",
      "bm25": "bm25_relevance_not_probability",
      "cosine": "cosine_similarity_not_probability"
    },
    "topical_signal_count": 10,
    "answerability_signal_count": 14
  }
}
```

## rd-vi-proxy-technique-assessment

Câu hỏi (vi): Đánh giá hiện tại đối với ATT&CK T1218.005 có mức hỗ trợ bằng chứng và trạng thái review nào?

| Thuộc tính | Giá trị |
| --- | --- |
| Partition | calibration |
| Category | relevant_direct |
| Expected decision (dataset) | proceed |
| Actual decision | abstain |
| Abstention stage | topical_relevance |
| Reason codes | ["query_token_coverage_below_threshold", "returned_top_cosine_score_below_threshold"] |
| Topical expected label | true |
| Dataset answerable | true |
| Actual context sufficient | true |
| External context basis | all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation |
| Topical actual stage status | failed |
| Answerability actual stage status | not_evaluated |

Đáp án tham chiếu đã duyệt (evaluation only; giữ nguyên nội dung lịch sử):

T1218.005 (Mshta) có evidence_support=supported_by_observed_behavior, status=candidate và review_status=needs_review tại /mitre_assessments/2. Hai evidence groups hỗ trợ mshta.exe với vbscript:Execute và việc sinh PowerShell; mapping này chưa được con người duyệt hay đánh dấu confirmed.

Đối chiếu expected evidence và context thực tế; đây là diagnostic ngoài gate:

```json
{
  "ground_truth_pointers": [
    "/mitre_assessments/2"
  ],
  "raw_record_references": [
    {
      "raw_record_ref": "jsonl:line:275",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    },
    {
      "raw_record_ref": "jsonl:line:30",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    },
    {
      "raw_record_ref": "jsonl:line:398",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    },
    {
      "raw_record_ref": "jsonl:line:4",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    }
  ],
  "expected_evidence_ids": [
    "evidence-b07a5ff4763e629715e6",
    "evidence-b31714b888d1489a380c"
  ],
  "returned_evidence_ids": [
    "evidence-b07a5ff4763e629715e6",
    "evidence-b31714b888d1489a380c"
  ],
  "missing_expected_evidence_ids": [],
  "missing_evidence_diagnostics": [],
  "external_context_sufficiency_basis": "all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation"
}
```

Signals đầy đủ đã cung cấp cho gate:

```json
{
  "schema_version": "graphrag-gate-signals/v1",
  "corpus_id": "retrieval-corpus--631ff39273344120e671693f867fbb47057f029d5de0c982d90c7b27e508d7b9",
  "graph_id": "knowledge-graph--45c9e1a1369012689417635f46b00e25ea0b5be2d39a6cf9375428d302ce27ea",
  "scenario_id": "mshta-powershell",
  "source_ground_truth": {
    "path": "outputs/ground_truth/mshta-powershell/scenario_ground_truth.json",
    "schema_version": "scenario-ground-truth/v1",
    "sha256": "b2e3aa48c2c20e6a49479e765db0a1d660121fdb70472ca36f308b1094ddbc41",
    "scenario_id": "mshta-powershell"
  },
  "query": {
    "text": "Đánh giá hiện tại đối với ATT&CK T1218.005 có mức hỗ trợ bằng chứng và trạng thái review nào?",
    "normalized_terms": [
      "đánh",
      "giá",
      "hiện",
      "tại",
      "đối",
      "với",
      "att",
      "ck",
      "t1218.005",
      "có",
      "mức",
      "hỗ",
      "trợ",
      "bằng",
      "chứng",
      "và",
      "trạng",
      "thái",
      "review",
      "nào"
    ],
    "top_k": 5,
    "candidate_k": 20,
    "filters": {
      "chunk_types": null,
      "required_dimensions": null
    }
  },
  "topical_relevance": {
    "retrieval_hit_count": 5,
    "lexical_hit_count": 5,
    "vector_hit_count": 5,
    "joint_lexical_vector_hit_count": 5,
    "returned_top_rrf_score": 0.032266458496,
    "returned_top_bm25_score": 4.44302297,
    "returned_top_cosine_score": 0.79762617,
    "query_token_count": 20,
    "matched_query_token_count": 2,
    "query_token_coverage": 0.1
  },
  "evidence_answerability": {
    "chunk_type_counts": {
      "scenario_summary": 0,
      "entity": 0,
      "fact": 0,
      "relationship": 0,
      "evidence": 0,
      "sigma_finding": 0,
      "mitre_assessment": 3,
      "limitation": 2
    },
    "status_counts": {
      "candidate": 3,
      "inferred": 0,
      "observed": 0,
      "reviewable": 2
    },
    "hits_with_evidence_ids": 2,
    "hits_with_source_references": 2,
    "unique_source_reference_count": 4,
    "mapped_hit_count": 5,
    "seed_node_count": 5,
    "traversal_performed": true,
    "traversal_node_count": 14,
    "traversal_edge_count": 15,
    "traversal_path_count": 27,
    "traversed_evidence_node_count": 2,
    "traversed_limitation_node_count": 2,
    "support_edge_count": 15
  },
  "warnings": [],
  "metadata": {
    "decision_made": false,
    "score_interpretations": {
      "rrf": "reciprocal_rank_fusion_not_probability",
      "bm25": "bm25_relevance_not_probability",
      "cosine": "cosine_similarity_not_probability"
    },
    "topical_signal_count": 10,
    "answerability_signal_count": 14
  }
}
```

## rd-vi-reviewed-scope-limitations

Câu hỏi (vi): Ground Truth ghi nhận những giới hạn nào đối với phạm vi bằng chứng đã review?

| Thuộc tính | Giá trị |
| --- | --- |
| Partition | calibration |
| Category | relevant_direct |
| Expected decision (dataset) | proceed |
| Actual decision | abstain |
| Abstention stage | topical_relevance |
| Reason codes | ["returned_top_cosine_score_below_threshold"] |
| Topical expected label | true |
| Dataset answerable | true |
| Actual context sufficient | false |
| External context basis | known_required_information_missing_from_actual_returned_context |
| Topical actual stage status | failed |
| Answerability actual stage status | not_evaluated |

Đáp án tham chiếu đã duyệt (evaluation only; giữ nguyên nội dung lịch sử):

Ground truth chỉ chứa hai behavior/evidence groups, không phải toàn bộ process inventory. Sysmon có timestamp_conflict: canonical dùng TimeCreated, còn UtcTime lệch khoảng bốn giờ và timezone chưa được xác nhận. Process creation không chứng minh cmdlet hoàn tất hay trạng thái dịch vụ. Log gốc có conhost creation, log clearing và temporary-file deletion ngoài core, nên không được kết luận các hành vi đó vắng mặt trên toàn dataset hoặc tự coi là destructive payload. Chưa có negative detector toàn diện; MITRE assessments còn candidate và human approval còn pending.

Đối chiếu expected evidence và context thực tế; đây là diagnostic ngoài gate:

```json
{
  "ground_truth_pointers": [
    "/scenario",
    "/summary/limitations/0",
    "/summary/limitations/1",
    "/summary/limitations/2",
    "/summary/limitations/3",
    "/summary/limitations/4",
    "/summary/limitations/5",
    "/summary/limitations/6"
  ],
  "raw_record_references": [],
  "expected_evidence_ids": [],
  "returned_evidence_ids": [
    "evidence-b07a5ff4763e629715e6",
    "evidence-b31714b888d1489a380c"
  ],
  "missing_expected_evidence_ids": [],
  "missing_evidence_diagnostics": [
    {
      "answer_unit_id": "limitation_1",
      "source_ground_truth_pointer": "/summary/limitations/1",
      "support_status": "unassessed",
      "reason": "no_exact_limitation_support_semantic_sufficiency_not_established"
    },
    {
      "answer_unit_id": "limitation_2",
      "source_ground_truth_pointer": "/summary/limitations/2",
      "support_status": "unassessed",
      "reason": "no_exact_limitation_support_semantic_sufficiency_not_established"
    },
    {
      "answer_unit_id": "limitation_4",
      "source_ground_truth_pointer": "/summary/limitations/4",
      "support_status": "known_missing",
      "reason": "full_consumer_audit_established_required_information_is_absent"
    },
    {
      "answer_unit_id": "limitation_5",
      "source_ground_truth_pointer": "/summary/limitations/5",
      "support_status": "known_missing",
      "reason": "full_consumer_audit_established_required_information_is_absent"
    },
    {
      "answer_unit_id": "limitation_6",
      "source_ground_truth_pointer": "/summary/limitations/6",
      "support_status": "known_missing",
      "reason": "full_consumer_audit_established_required_information_is_absent"
    }
  ],
  "external_context_sufficiency_basis": "known_required_information_missing_from_actual_returned_context"
}
```

Signals đầy đủ đã cung cấp cho gate:

```json
{
  "schema_version": "graphrag-gate-signals/v1",
  "corpus_id": "retrieval-corpus--631ff39273344120e671693f867fbb47057f029d5de0c982d90c7b27e508d7b9",
  "graph_id": "knowledge-graph--45c9e1a1369012689417635f46b00e25ea0b5be2d39a6cf9375428d302ce27ea",
  "scenario_id": "mshta-powershell",
  "source_ground_truth": {
    "path": "outputs/ground_truth/mshta-powershell/scenario_ground_truth.json",
    "schema_version": "scenario-ground-truth/v1",
    "sha256": "b2e3aa48c2c20e6a49479e765db0a1d660121fdb70472ca36f308b1094ddbc41",
    "scenario_id": "mshta-powershell"
  },
  "query": {
    "text": "Ground Truth ghi nhận những giới hạn nào đối với phạm vi bằng chứng đã review?",
    "normalized_terms": [
      "ground",
      "truth",
      "ghi",
      "nhận",
      "những",
      "giới",
      "hạn",
      "nào",
      "đối",
      "với",
      "phạm",
      "vi",
      "bằng",
      "chứng",
      "đã",
      "review"
    ],
    "top_k": 5,
    "candidate_k": 20,
    "filters": {
      "chunk_types": null,
      "required_dimensions": null
    }
  },
  "topical_relevance": {
    "retrieval_hit_count": 5,
    "lexical_hit_count": 5,
    "vector_hit_count": 5,
    "joint_lexical_vector_hit_count": 5,
    "returned_top_rrf_score": 0.032266458496,
    "returned_top_bm25_score": 6.53632059,
    "returned_top_cosine_score": 0.7719129,
    "query_token_count": 16,
    "matched_query_token_count": 3,
    "query_token_coverage": 0.1875
  },
  "evidence_answerability": {
    "chunk_type_counts": {
      "scenario_summary": 0,
      "entity": 0,
      "fact": 0,
      "relationship": 0,
      "evidence": 0,
      "sigma_finding": 0,
      "mitre_assessment": 3,
      "limitation": 2
    },
    "status_counts": {
      "candidate": 3,
      "inferred": 0,
      "observed": 0,
      "reviewable": 2
    },
    "hits_with_evidence_ids": 2,
    "hits_with_source_references": 2,
    "unique_source_reference_count": 4,
    "mapped_hit_count": 5,
    "seed_node_count": 5,
    "traversal_performed": true,
    "traversal_node_count": 14,
    "traversal_edge_count": 15,
    "traversal_path_count": 27,
    "traversed_evidence_node_count": 2,
    "traversed_limitation_node_count": 2,
    "support_edge_count": 15
  },
  "warnings": [],
  "metadata": {
    "decision_made": false,
    "score_interpretations": {
      "rrf": "reciprocal_rank_fusion_not_probability",
      "bm25": "bm25_relevance_not_probability",
      "cosine": "cosine_similarity_not_probability"
    },
    "topical_signal_count": 10,
    "answerability_signal_count": 14
  }
}
```

## rd-vi-scripting-technique-status

Câu hỏi (vi): T1059.007 có được hỗ trợ bởi command line đã quan sát không, và trạng thái đánh giá là gì?

| Thuộc tính | Giá trị |
| --- | --- |
| Partition | calibration |
| Category | relevant_direct |
| Expected decision (dataset) | proceed |
| Actual decision | abstain |
| Abstention stage | topical_relevance |
| Reason codes | ["query_token_coverage_below_threshold", "returned_top_cosine_score_below_threshold"] |
| Topical expected label | true |
| Dataset answerable | true |
| Actual context sufficient | true |
| External context basis | all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation |
| Topical actual stage status | failed |
| Answerability actual stage status | not_evaluated |

Đáp án tham chiếu đã duyệt (evaluation only; giữ nguyên nội dung lịch sử):

T1059.007 là JavaScript, nhưng command line quan sát được dùng vbscript:Execute. /mitre_assessments/0 ghi not_supported_by_observed_command, status=candidate và review_status=needs_review; nhãn được giữ từ Sigma tag để truy vết nguồn, không chứng minh JavaScript đã chạy.

Đối chiếu expected evidence và context thực tế; đây là diagnostic ngoài gate:

```json
{
  "ground_truth_pointers": [
    "/mitre_assessments/0"
  ],
  "raw_record_references": [
    {
      "raw_record_ref": "jsonl:line:275",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    },
    {
      "raw_record_ref": "jsonl:line:4",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    }
  ],
  "expected_evidence_ids": [
    "evidence-b07a5ff4763e629715e6"
  ],
  "returned_evidence_ids": [
    "evidence-b07a5ff4763e629715e6",
    "evidence-b31714b888d1489a380c"
  ],
  "missing_expected_evidence_ids": [],
  "missing_evidence_diagnostics": [],
  "external_context_sufficiency_basis": "all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation"
}
```

Signals đầy đủ đã cung cấp cho gate:

```json
{
  "schema_version": "graphrag-gate-signals/v1",
  "corpus_id": "retrieval-corpus--631ff39273344120e671693f867fbb47057f029d5de0c982d90c7b27e508d7b9",
  "graph_id": "knowledge-graph--45c9e1a1369012689417635f46b00e25ea0b5be2d39a6cf9375428d302ce27ea",
  "scenario_id": "mshta-powershell",
  "source_ground_truth": {
    "path": "outputs/ground_truth/mshta-powershell/scenario_ground_truth.json",
    "schema_version": "scenario-ground-truth/v1",
    "sha256": "b2e3aa48c2c20e6a49479e765db0a1d660121fdb70472ca36f308b1094ddbc41",
    "scenario_id": "mshta-powershell"
  },
  "query": {
    "text": "T1059.007 có được hỗ trợ bởi command line đã quan sát không, và trạng thái đánh giá là gì?",
    "normalized_terms": [
      "t1059.007",
      "có",
      "được",
      "hỗ",
      "trợ",
      "bởi",
      "command",
      "line",
      "đã",
      "quan",
      "sát",
      "không",
      "và",
      "trạng",
      "thái",
      "đánh",
      "giá",
      "là",
      "gì"
    ],
    "top_k": 5,
    "candidate_k": 20,
    "filters": {
      "chunk_types": null,
      "required_dimensions": null
    }
  },
  "topical_relevance": {
    "retrieval_hit_count": 5,
    "lexical_hit_count": 2,
    "vector_hit_count": 5,
    "joint_lexical_vector_hit_count": 2,
    "returned_top_rrf_score": 0.032786885246,
    "returned_top_bm25_score": 8.02574801,
    "returned_top_cosine_score": 0.83420675,
    "query_token_count": 19,
    "matched_query_token_count": 3,
    "query_token_coverage": 0.15789474
  },
  "evidence_answerability": {
    "chunk_type_counts": {
      "scenario_summary": 1,
      "entity": 0,
      "fact": 0,
      "relationship": 1,
      "evidence": 0,
      "sigma_finding": 0,
      "mitre_assessment": 3,
      "limitation": 0
    },
    "status_counts": {
      "candidate": 3,
      "inferred": 0,
      "observed": 1,
      "reviewable": 1
    },
    "hits_with_evidence_ids": 3,
    "hits_with_source_references": 4,
    "unique_source_reference_count": 4,
    "mapped_hit_count": 5,
    "seed_node_count": 6,
    "traversal_performed": true,
    "traversal_node_count": 13,
    "traversal_edge_count": 21,
    "traversal_path_count": 47,
    "traversed_evidence_node_count": 2,
    "traversed_limitation_node_count": 0,
    "support_edge_count": 15
  },
  "warnings": [],
  "metadata": {
    "decision_made": false,
    "score_interpretations": {
      "rrf": "reciprocal_rank_fusion_not_probability",
      "bm25": "bm25_relevance_not_probability",
      "cosine": "cosine_similarity_not_probability"
    },
    "topical_signal_count": 10,
    "answerability_signal_count": 14
  }
}
```

## rp-en-intermediate-utility

Câu hỏi (en): Which Windows utility sits between the initial command interpreter and the final shell?

| Thuộc tính | Giá trị |
| --- | --- |
| Partition | calibration |
| Category | relevant_paraphrase |
| Expected decision (dataset) | proceed |
| Actual decision | abstain |
| Abstention stage | topical_relevance |
| Reason codes | ["returned_top_cosine_score_below_threshold"] |
| Topical expected label | true |
| Dataset answerable | true |
| Actual context sufficient | true |
| External context basis | all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation |
| Topical actual stage status | failed |
| Answerability actual stage status | not_evaluated |

Đáp án tham chiếu đã duyệt (evaluation only; giữ nguyên nội dung lịch sử):

Tiện ích nằm giữa cmd.exe và powershell.exe là mshta.exe: cmd.exe → mshta.exe → powershell.exe. Hai process_spawn relationships và evidence tương ứng ghi rõ hướng của từng liên kết.

Đối chiếu expected evidence và context thực tế; đây là diagnostic ngoài gate:

```json
{
  "ground_truth_pointers": [
    "/evidence/0",
    "/evidence/1",
    "/facts/0",
    "/facts/1",
    "/relationships/0",
    "/relationships/1",
    "/scenario"
  ],
  "raw_record_references": [
    {
      "raw_record_ref": "jsonl:line:275",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    },
    {
      "raw_record_ref": "jsonl:line:30",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    },
    {
      "raw_record_ref": "jsonl:line:398",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    },
    {
      "raw_record_ref": "jsonl:line:4",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    }
  ],
  "expected_evidence_ids": [
    "evidence-b07a5ff4763e629715e6",
    "evidence-b31714b888d1489a380c"
  ],
  "returned_evidence_ids": [
    "evidence-b07a5ff4763e629715e6",
    "evidence-b31714b888d1489a380c"
  ],
  "missing_expected_evidence_ids": [],
  "missing_evidence_diagnostics": [],
  "external_context_sufficiency_basis": "all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation"
}
```

Signals đầy đủ đã cung cấp cho gate:

```json
{
  "schema_version": "graphrag-gate-signals/v1",
  "corpus_id": "retrieval-corpus--631ff39273344120e671693f867fbb47057f029d5de0c982d90c7b27e508d7b9",
  "graph_id": "knowledge-graph--45c9e1a1369012689417635f46b00e25ea0b5be2d39a6cf9375428d302ce27ea",
  "scenario_id": "mshta-powershell",
  "source_ground_truth": {
    "path": "outputs/ground_truth/mshta-powershell/scenario_ground_truth.json",
    "schema_version": "scenario-ground-truth/v1",
    "sha256": "b2e3aa48c2c20e6a49479e765db0a1d660121fdb70472ca36f308b1094ddbc41",
    "scenario_id": "mshta-powershell"
  },
  "query": {
    "text": "Which Windows utility sits between the initial command interpreter and the final shell?",
    "normalized_terms": [
      "which",
      "windows",
      "utility",
      "sits",
      "between",
      "the",
      "initial",
      "command",
      "interpreter",
      "and",
      "final",
      "shell"
    ],
    "top_k": 5,
    "candidate_k": 20,
    "filters": {
      "chunk_types": null,
      "required_dimensions": null
    }
  },
  "topical_relevance": {
    "retrieval_hit_count": 5,
    "lexical_hit_count": 5,
    "vector_hit_count": 5,
    "joint_lexical_vector_hit_count": 5,
    "returned_top_rrf_score": 0.032786885246,
    "returned_top_bm25_score": 4.84776025,
    "returned_top_cosine_score": 0.79296716,
    "query_token_count": 12,
    "matched_query_token_count": 4,
    "query_token_coverage": 0.33333333
  },
  "evidence_answerability": {
    "chunk_type_counts": {
      "scenario_summary": 1,
      "entity": 0,
      "fact": 0,
      "relationship": 0,
      "evidence": 0,
      "sigma_finding": 0,
      "mitre_assessment": 3,
      "limitation": 1
    },
    "status_counts": {
      "candidate": 3,
      "inferred": 0,
      "observed": 0,
      "reviewable": 2
    },
    "hits_with_evidence_ids": 2,
    "hits_with_source_references": 3,
    "unique_source_reference_count": 4,
    "mapped_hit_count": 5,
    "seed_node_count": 5,
    "traversal_performed": true,
    "traversal_node_count": 14,
    "traversal_edge_count": 15,
    "traversal_path_count": 27,
    "traversed_evidence_node_count": 2,
    "traversed_limitation_node_count": 1,
    "support_edge_count": 15
  },
  "warnings": [],
  "metadata": {
    "decision_made": false,
    "score_interpretations": {
      "rrf": "reciprocal_rank_fusion_not_probability",
      "bm25": "bm25_relevance_not_probability",
      "cosine": "cosine_similarity_not_probability"
    },
    "topical_signal_count": 10,
    "answerability_signal_count": 14
  }
}
```

## rp-en-retained-scripting-label

Câu hỏi (en): Why does a scripting technique label remain in the record when the reviewed inline command uses a different scripting language?

| Thuộc tính | Giá trị |
| --- | --- |
| Partition | calibration |
| Category | relevant_paraphrase |
| Expected decision (dataset) | proceed |
| Actual decision | proceed |
| Abstention stage | null |
| Reason codes | [] |
| Topical expected label | true |
| Dataset answerable | true |
| Actual context sufficient | true |
| External context basis | all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation |
| Topical actual stage status | passed |
| Answerability actual stage status | passed |

Đáp án tham chiếu đã duyệt (evaluation only; giữ nguyên nội dung lịch sử):

T1059.007 được giữ vì xuất phát từ tag của Sigma rule, để bảo toàn provenance. Command line dùng VBScript, không phải JavaScript; assessment vì vậy ghi not_supported_by_observed_command và không coi nhãn JavaScript là hành vi đã được chứng minh.

Đối chiếu expected evidence và context thực tế; đây là diagnostic ngoài gate:

```json
{
  "ground_truth_pointers": [
    "/mitre_assessments/0",
    "/scenario"
  ],
  "raw_record_references": [
    {
      "raw_record_ref": "jsonl:line:275",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    },
    {
      "raw_record_ref": "jsonl:line:4",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    }
  ],
  "expected_evidence_ids": [
    "evidence-b07a5ff4763e629715e6"
  ],
  "returned_evidence_ids": [
    "evidence-b07a5ff4763e629715e6",
    "evidence-b31714b888d1489a380c"
  ],
  "missing_expected_evidence_ids": [],
  "missing_evidence_diagnostics": [],
  "external_context_sufficiency_basis": "all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation"
}
```

Signals đầy đủ đã cung cấp cho gate:

```json
{
  "schema_version": "graphrag-gate-signals/v1",
  "corpus_id": "retrieval-corpus--631ff39273344120e671693f867fbb47057f029d5de0c982d90c7b27e508d7b9",
  "graph_id": "knowledge-graph--45c9e1a1369012689417635f46b00e25ea0b5be2d39a6cf9375428d302ce27ea",
  "scenario_id": "mshta-powershell",
  "source_ground_truth": {
    "path": "outputs/ground_truth/mshta-powershell/scenario_ground_truth.json",
    "schema_version": "scenario-ground-truth/v1",
    "sha256": "b2e3aa48c2c20e6a49479e765db0a1d660121fdb70472ca36f308b1094ddbc41",
    "scenario_id": "mshta-powershell"
  },
  "query": {
    "text": "Why does a scripting technique label remain in the record when the reviewed inline command uses a different scripting language?",
    "normalized_terms": [
      "why",
      "does",
      "a",
      "scripting",
      "technique",
      "label",
      "remain",
      "in",
      "the",
      "record",
      "when",
      "reviewed",
      "inline",
      "command",
      "uses",
      "different",
      "language"
    ],
    "top_k": 5,
    "candidate_k": 20,
    "filters": {
      "chunk_types": null,
      "required_dimensions": null
    }
  },
  "topical_relevance": {
    "retrieval_hit_count": 5,
    "lexical_hit_count": 5,
    "vector_hit_count": 5,
    "joint_lexical_vector_hit_count": 5,
    "returned_top_rrf_score": 0.032786885246,
    "returned_top_bm25_score": 8.58719052,
    "returned_top_cosine_score": 0.84997559,
    "query_token_count": 17,
    "matched_query_token_count": 10,
    "query_token_coverage": 0.58823529
  },
  "evidence_answerability": {
    "chunk_type_counts": {
      "scenario_summary": 1,
      "entity": 0,
      "fact": 0,
      "relationship": 0,
      "evidence": 0,
      "sigma_finding": 0,
      "mitre_assessment": 3,
      "limitation": 1
    },
    "status_counts": {
      "candidate": 3,
      "inferred": 0,
      "observed": 0,
      "reviewable": 2
    },
    "hits_with_evidence_ids": 2,
    "hits_with_source_references": 3,
    "unique_source_reference_count": 4,
    "mapped_hit_count": 5,
    "seed_node_count": 5,
    "traversal_performed": true,
    "traversal_node_count": 14,
    "traversal_edge_count": 15,
    "traversal_path_count": 27,
    "traversed_evidence_node_count": 2,
    "traversed_limitation_node_count": 1,
    "support_edge_count": 15
  },
  "warnings": [],
  "metadata": {
    "decision_made": false,
    "score_interpretations": {
      "rrf": "reciprocal_rank_fusion_not_probability",
      "bm25": "bm25_relevance_not_probability",
      "cosine": "cosine_similarity_not_probability"
    },
    "topical_signal_count": 10,
    "answerability_signal_count": 14
  }
}
```

## rp-en-shell-creator

Câu hỏi (en): How can I trace the launch of the final shell back to its creator?

| Thuộc tính | Giá trị |
| --- | --- |
| Partition | calibration |
| Category | relevant_paraphrase |
| Expected decision (dataset) | proceed |
| Actual decision | abstain |
| Abstention stage | topical_relevance |
| Reason codes | ["returned_top_cosine_score_below_threshold"] |
| Topical expected label | true |
| Dataset answerable | true |
| Actual context sufficient | true |
| External context basis | all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation |
| Topical actual stage status | failed |
| Answerability actual stage status | not_evaluated |

Đáp án tham chiếu đã duyệt (evaluation only; giữ nguyên nội dung lịch sử):

Truy từ process-9f7ceeecb4cd61358ab7 (powershell.exe) về relationship-1641029b76ea1ac3df6e và fact-mshta-spawns-powershell; source là process-9c691740bde5d3dbdc4e (mshta.exe). evidence-b31714b888d1489a380c đưa về Security 4688 line 30 và Sysmon 1 line 398 để kiểm tra cha-con.

Đối chiếu expected evidence và context thực tế; đây là diagnostic ngoài gate:

```json
{
  "ground_truth_pointers": [
    "/evidence/1",
    "/facts/1",
    "/relationships/0"
  ],
  "raw_record_references": [
    {
      "raw_record_ref": "jsonl:line:30",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    },
    {
      "raw_record_ref": "jsonl:line:398",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    }
  ],
  "expected_evidence_ids": [
    "evidence-b31714b888d1489a380c"
  ],
  "returned_evidence_ids": [
    "evidence-b07a5ff4763e629715e6",
    "evidence-b31714b888d1489a380c"
  ],
  "missing_expected_evidence_ids": [],
  "missing_evidence_diagnostics": [],
  "external_context_sufficiency_basis": "all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation"
}
```

Signals đầy đủ đã cung cấp cho gate:

```json
{
  "schema_version": "graphrag-gate-signals/v1",
  "corpus_id": "retrieval-corpus--631ff39273344120e671693f867fbb47057f029d5de0c982d90c7b27e508d7b9",
  "graph_id": "knowledge-graph--45c9e1a1369012689417635f46b00e25ea0b5be2d39a6cf9375428d302ce27ea",
  "scenario_id": "mshta-powershell",
  "source_ground_truth": {
    "path": "outputs/ground_truth/mshta-powershell/scenario_ground_truth.json",
    "schema_version": "scenario-ground-truth/v1",
    "sha256": "b2e3aa48c2c20e6a49479e765db0a1d660121fdb70472ca36f308b1094ddbc41",
    "scenario_id": "mshta-powershell"
  },
  "query": {
    "text": "How can I trace the launch of the final shell back to its creator?",
    "normalized_terms": [
      "how",
      "can",
      "i",
      "trace",
      "the",
      "launch",
      "of",
      "final",
      "shell",
      "back",
      "to",
      "its",
      "creator"
    ],
    "top_k": 5,
    "candidate_k": 20,
    "filters": {
      "chunk_types": null,
      "required_dimensions": null
    }
  },
  "topical_relevance": {
    "retrieval_hit_count": 5,
    "lexical_hit_count": 5,
    "vector_hit_count": 5,
    "joint_lexical_vector_hit_count": 5,
    "returned_top_rrf_score": 0.031318815757,
    "returned_top_bm25_score": 7.40091956,
    "returned_top_cosine_score": 0.80601208,
    "query_token_count": 13,
    "matched_query_token_count": 5,
    "query_token_coverage": 0.38461538
  },
  "evidence_answerability": {
    "chunk_type_counts": {
      "scenario_summary": 0,
      "entity": 0,
      "fact": 0,
      "relationship": 0,
      "evidence": 0,
      "sigma_finding": 0,
      "mitre_assessment": 3,
      "limitation": 2
    },
    "status_counts": {
      "candidate": 3,
      "inferred": 0,
      "observed": 0,
      "reviewable": 2
    },
    "hits_with_evidence_ids": 2,
    "hits_with_source_references": 2,
    "unique_source_reference_count": 4,
    "mapped_hit_count": 5,
    "seed_node_count": 5,
    "traversal_performed": true,
    "traversal_node_count": 14,
    "traversal_edge_count": 15,
    "traversal_path_count": 27,
    "traversed_evidence_node_count": 2,
    "traversed_limitation_node_count": 2,
    "support_edge_count": 15
  },
  "warnings": [],
  "metadata": {
    "decision_made": false,
    "score_interpretations": {
      "rrf": "reciprocal_rank_fusion_not_probability",
      "bm25": "bm25_relevance_not_probability",
      "cosine": "cosine_similarity_not_probability"
    },
    "topical_signal_count": 10,
    "answerability_signal_count": 14
  }
}
```

## rp-en-technique-review

Câu hỏi (en): Why is the proxy execution technique still awaiting analyst approval even though its behavior has supporting records?

| Thuộc tính | Giá trị |
| --- | --- |
| Partition | calibration |
| Category | relevant_paraphrase |
| Expected decision (dataset) | proceed |
| Actual decision | abstain |
| Abstention stage | topical_relevance |
| Reason codes | ["returned_top_cosine_score_below_threshold"] |
| Topical expected label | true |
| Dataset answerable | true |
| Actual context sufficient | true |
| External context basis | all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation |
| Topical actual stage status | failed |
| Answerability actual stage status | not_evaluated |

Đáp án tham chiếu đã duyệt (evaluation only; giữ nguyên nội dung lịch sử):

T1218.005 được hỗ trợ ở mức hành vi quan sát, nhưng status vẫn candidate và review_status=needs_review. Khớp Sigma hoặc quan sát mshta.exe sinh PowerShell không tự thay thế phê duyệt của người phân tích; artifact còn giới hạn phạm vi và timestamp_conflict, chưa có kết luận tấn công cuối cùng.

Đối chiếu expected evidence và context thực tế; đây là diagnostic ngoài gate:

```json
{
  "ground_truth_pointers": [
    "/mitre_assessments/2",
    "/scenario",
    "/summary/limitations/3"
  ],
  "raw_record_references": [
    {
      "raw_record_ref": "jsonl:line:275",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    },
    {
      "raw_record_ref": "jsonl:line:30",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    },
    {
      "raw_record_ref": "jsonl:line:398",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    },
    {
      "raw_record_ref": "jsonl:line:4",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    }
  ],
  "expected_evidence_ids": [
    "evidence-b07a5ff4763e629715e6",
    "evidence-b31714b888d1489a380c"
  ],
  "returned_evidence_ids": [
    "evidence-b07a5ff4763e629715e6",
    "evidence-b31714b888d1489a380c"
  ],
  "missing_expected_evidence_ids": [],
  "missing_evidence_diagnostics": [],
  "external_context_sufficiency_basis": "all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation"
}
```

Signals đầy đủ đã cung cấp cho gate:

```json
{
  "schema_version": "graphrag-gate-signals/v1",
  "corpus_id": "retrieval-corpus--631ff39273344120e671693f867fbb47057f029d5de0c982d90c7b27e508d7b9",
  "graph_id": "knowledge-graph--45c9e1a1369012689417635f46b00e25ea0b5be2d39a6cf9375428d302ce27ea",
  "scenario_id": "mshta-powershell",
  "source_ground_truth": {
    "path": "outputs/ground_truth/mshta-powershell/scenario_ground_truth.json",
    "schema_version": "scenario-ground-truth/v1",
    "sha256": "b2e3aa48c2c20e6a49479e765db0a1d660121fdb70472ca36f308b1094ddbc41",
    "scenario_id": "mshta-powershell"
  },
  "query": {
    "text": "Why is the proxy execution technique still awaiting analyst approval even though its behavior has supporting records?",
    "normalized_terms": [
      "why",
      "is",
      "the",
      "proxy",
      "execution",
      "technique",
      "still",
      "awaiting",
      "analyst",
      "approval",
      "even",
      "though",
      "its",
      "behavior",
      "has",
      "supporting",
      "records"
    ],
    "top_k": 5,
    "candidate_k": 20,
    "filters": {
      "chunk_types": null,
      "required_dimensions": null
    }
  },
  "topical_relevance": {
    "retrieval_hit_count": 5,
    "lexical_hit_count": 5,
    "vector_hit_count": 5,
    "joint_lexical_vector_hit_count": 5,
    "returned_top_rrf_score": 0.032522474881,
    "returned_top_bm25_score": 7.86140339,
    "returned_top_cosine_score": 0.83565082,
    "query_token_count": 17,
    "matched_query_token_count": 6,
    "query_token_coverage": 0.35294118
  },
  "evidence_answerability": {
    "chunk_type_counts": {
      "scenario_summary": 0,
      "entity": 0,
      "fact": 0,
      "relationship": 0,
      "evidence": 0,
      "sigma_finding": 1,
      "mitre_assessment": 3,
      "limitation": 1
    },
    "status_counts": {
      "candidate": 4,
      "inferred": 0,
      "observed": 0,
      "reviewable": 1
    },
    "hits_with_evidence_ids": 3,
    "hits_with_source_references": 3,
    "unique_source_reference_count": 4,
    "mapped_hit_count": 5,
    "seed_node_count": 5,
    "traversal_performed": true,
    "traversal_node_count": 13,
    "traversal_edge_count": 15,
    "traversal_path_count": 36,
    "traversed_evidence_node_count": 2,
    "traversed_limitation_node_count": 1,
    "support_edge_count": 15
  },
  "warnings": [],
  "metadata": {
    "decision_made": false,
    "score_interpretations": {
      "rrf": "reciprocal_rank_fusion_not_probability",
      "bm25": "bm25_relevance_not_probability",
      "cosine": "cosine_similarity_not_probability"
    },
    "topical_signal_count": 10,
    "answerability_signal_count": 14
  }
}
```

## rp-vi-final-review-limits

Câu hỏi (vi): Người phân tích còn phải xem lại điều gì trước khi đưa ra nhận định cuối cùng?

| Thuộc tính | Giá trị |
| --- | --- |
| Partition | calibration |
| Category | relevant_paraphrase |
| Expected decision (dataset) | proceed |
| Actual decision | abstain |
| Abstention stage | topical_relevance |
| Reason codes | ["query_token_coverage_below_threshold", "returned_top_cosine_score_below_threshold"] |
| Topical expected label | true |
| Dataset answerable | true |
| Actual context sufficient | false |
| External context basis | known_required_information_missing_from_actual_returned_context |
| Topical actual stage status | failed |
| Answerability actual stage status | not_evaluated |

Đáp án tham chiếu đã duyệt (evaluation only; giữ nguyên nội dung lịch sử):

Người phân tích cần kiểm tra lại correlation và refs của hai behavior groups, xử lý timestamp_conflict của Sysmon, xem mức hỗ trợ của từng MITRE assessment và giữ giới hạn negative scan. Cần duyệt ground truth và phân biệt lệnh xuất hiện trên command line với kết quả thực thi; các candidate hiện có chưa phải kết luận tấn công cuối cùng.

Đối chiếu expected evidence và context thực tế; đây là diagnostic ngoài gate:

```json
{
  "ground_truth_pointers": [
    "/scenario",
    "/summary/limitations/0",
    "/summary/limitations/1",
    "/summary/limitations/2",
    "/summary/limitations/3"
  ],
  "raw_record_references": [],
  "expected_evidence_ids": [],
  "returned_evidence_ids": [
    "evidence-b07a5ff4763e629715e6",
    "evidence-b31714b888d1489a380c"
  ],
  "missing_expected_evidence_ids": [],
  "missing_evidence_diagnostics": [
    {
      "answer_unit_id": "analysis_status",
      "source_ground_truth_pointer": "/scenario",
      "support_status": "known_missing",
      "reason": "required_source_associated_structured_fields_not_returned"
    },
    {
      "answer_unit_id": "limitation_0",
      "source_ground_truth_pointer": "/summary/limitations/0",
      "support_status": "unassessed",
      "reason": "no_exact_limitation_support_semantic_sufficiency_not_established"
    },
    {
      "answer_unit_id": "limitation_1",
      "source_ground_truth_pointer": "/summary/limitations/1",
      "support_status": "unassessed",
      "reason": "no_exact_limitation_support_semantic_sufficiency_not_established"
    },
    {
      "answer_unit_id": "limitation_2",
      "source_ground_truth_pointer": "/summary/limitations/2",
      "support_status": "unassessed",
      "reason": "no_exact_limitation_support_semantic_sufficiency_not_established"
    },
    {
      "answer_unit_id": "limitation_3",
      "source_ground_truth_pointer": "/summary/limitations/3",
      "support_status": "unassessed",
      "reason": "no_exact_limitation_support_semantic_sufficiency_not_established"
    },
    {
      "answer_unit_id": "limitation_4",
      "source_ground_truth_pointer": "/summary/limitations/4",
      "support_status": "known_missing",
      "reason": "full_consumer_audit_established_required_information_is_absent"
    }
  ],
  "external_context_sufficiency_basis": "known_required_information_missing_from_actual_returned_context"
}
```

Signals đầy đủ đã cung cấp cho gate:

```json
{
  "schema_version": "graphrag-gate-signals/v1",
  "corpus_id": "retrieval-corpus--631ff39273344120e671693f867fbb47057f029d5de0c982d90c7b27e508d7b9",
  "graph_id": "knowledge-graph--45c9e1a1369012689417635f46b00e25ea0b5be2d39a6cf9375428d302ce27ea",
  "scenario_id": "mshta-powershell",
  "source_ground_truth": {
    "path": "outputs/ground_truth/mshta-powershell/scenario_ground_truth.json",
    "schema_version": "scenario-ground-truth/v1",
    "sha256": "b2e3aa48c2c20e6a49479e765db0a1d660121fdb70472ca36f308b1094ddbc41",
    "scenario_id": "mshta-powershell"
  },
  "query": {
    "text": "Người phân tích còn phải xem lại điều gì trước khi đưa ra nhận định cuối cùng?",
    "normalized_terms": [
      "người",
      "phân",
      "tích",
      "còn",
      "phải",
      "xem",
      "lại",
      "điều",
      "gì",
      "trước",
      "khi",
      "đưa",
      "ra",
      "nhận",
      "định",
      "cuối",
      "cùng"
    ],
    "top_k": 5,
    "candidate_k": 20,
    "filters": {
      "chunk_types": null,
      "required_dimensions": null
    }
  },
  "topical_relevance": {
    "retrieval_hit_count": 5,
    "lexical_hit_count": 0,
    "vector_hit_count": 5,
    "joint_lexical_vector_hit_count": 0,
    "returned_top_rrf_score": 0.016393442623,
    "returned_top_bm25_score": null,
    "returned_top_cosine_score": 0.76222476,
    "query_token_count": 17,
    "matched_query_token_count": 0,
    "query_token_coverage": 0.0
  },
  "evidence_answerability": {
    "chunk_type_counts": {
      "scenario_summary": 0,
      "entity": 0,
      "fact": 2,
      "relationship": 0,
      "evidence": 0,
      "sigma_finding": 0,
      "mitre_assessment": 3,
      "limitation": 0
    },
    "status_counts": {
      "candidate": 3,
      "inferred": 0,
      "observed": 2,
      "reviewable": 0
    },
    "hits_with_evidence_ids": 4,
    "hits_with_source_references": 4,
    "unique_source_reference_count": 4,
    "mapped_hit_count": 5,
    "seed_node_count": 5,
    "traversal_performed": true,
    "traversal_node_count": 12,
    "traversal_edge_count": 21,
    "traversal_path_count": 44,
    "traversed_evidence_node_count": 2,
    "traversed_limitation_node_count": 0,
    "support_edge_count": 15
  },
  "warnings": [
    "lexical: No eligible chunks matched the normalized lexical query terms."
  ],
  "metadata": {
    "decision_made": false,
    "score_interpretations": {
      "rrf": "reciprocal_rank_fusion_not_probability",
      "bm25": "bm25_relevance_not_probability",
      "cosine": "cosine_similarity_not_probability"
    },
    "topical_signal_count": 10,
    "answerability_signal_count": 14
  }
}
```

## rp-vi-launch-order

Câu hỏi (vi): Nhìn các quan hệ cha-con đã lưu, làm thế nào dựng lại thứ tự khởi chạy ba tiến trình?

| Thuộc tính | Giá trị |
| --- | --- |
| Partition | calibration |
| Category | relevant_paraphrase |
| Expected decision (dataset) | proceed |
| Actual decision | abstain |
| Abstention stage | topical_relevance |
| Reason codes | ["query_token_coverage_below_threshold", "returned_top_cosine_score_below_threshold"] |
| Topical expected label | true |
| Dataset answerable | true |
| Actual context sufficient | true |
| External context basis | all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation |
| Topical actual stage status | failed |
| Answerability actual stage status | not_evaluated |

Đáp án tham chiếu đã duyệt (evaluation only; giữ nguyên nội dung lịch sử):

Dựng thứ tự bằng hướng của facts và relationships: fact-cmd-spawns-mshta trước, rồi fact-mshta-spawns-powershell, tạo chuỗi cmd.exe → mshta.exe → powershell.exe. Không suy ra thứ tự bằng vị trí phần tử trong mảng relationships; mảng lưu quan hệ cuối ở /relationships/0 và quan hệ đầu ở /relationships/1. Mỗi bước có một cặp Security/Sysmon telemetry, không đếm đôi.

Đối chiếu expected evidence và context thực tế; đây là diagnostic ngoài gate:

```json
{
  "ground_truth_pointers": [
    "/evidence/0",
    "/evidence/1",
    "/facts/0",
    "/facts/1",
    "/relationships/0",
    "/relationships/1",
    "/scenario"
  ],
  "raw_record_references": [
    {
      "raw_record_ref": "jsonl:line:275",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    },
    {
      "raw_record_ref": "jsonl:line:30",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    },
    {
      "raw_record_ref": "jsonl:line:398",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    },
    {
      "raw_record_ref": "jsonl:line:4",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    }
  ],
  "expected_evidence_ids": [
    "evidence-b07a5ff4763e629715e6",
    "evidence-b31714b888d1489a380c"
  ],
  "returned_evidence_ids": [
    "evidence-b07a5ff4763e629715e6",
    "evidence-b31714b888d1489a380c"
  ],
  "missing_expected_evidence_ids": [],
  "missing_evidence_diagnostics": [],
  "external_context_sufficiency_basis": "all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation"
}
```

Signals đầy đủ đã cung cấp cho gate:

```json
{
  "schema_version": "graphrag-gate-signals/v1",
  "corpus_id": "retrieval-corpus--631ff39273344120e671693f867fbb47057f029d5de0c982d90c7b27e508d7b9",
  "graph_id": "knowledge-graph--45c9e1a1369012689417635f46b00e25ea0b5be2d39a6cf9375428d302ce27ea",
  "scenario_id": "mshta-powershell",
  "source_ground_truth": {
    "path": "outputs/ground_truth/mshta-powershell/scenario_ground_truth.json",
    "schema_version": "scenario-ground-truth/v1",
    "sha256": "b2e3aa48c2c20e6a49479e765db0a1d660121fdb70472ca36f308b1094ddbc41",
    "scenario_id": "mshta-powershell"
  },
  "query": {
    "text": "Nhìn các quan hệ cha-con đã lưu, làm thế nào dựng lại thứ tự khởi chạy ba tiến trình?",
    "normalized_terms": [
      "nhìn",
      "các",
      "quan",
      "hệ",
      "cha-con",
      "đã",
      "lưu",
      "làm",
      "thế",
      "nào",
      "dựng",
      "lại",
      "thứ",
      "tự",
      "khởi",
      "chạy",
      "ba",
      "tiến",
      "trình"
    ],
    "top_k": 5,
    "candidate_k": 20,
    "filters": {
      "chunk_types": null,
      "required_dimensions": null
    }
  },
  "topical_relevance": {
    "retrieval_hit_count": 5,
    "lexical_hit_count": 0,
    "vector_hit_count": 5,
    "joint_lexical_vector_hit_count": 0,
    "returned_top_rrf_score": 0.016393442623,
    "returned_top_bm25_score": null,
    "returned_top_cosine_score": 0.78778485,
    "query_token_count": 19,
    "matched_query_token_count": 0,
    "query_token_coverage": 0.0
  },
  "evidence_answerability": {
    "chunk_type_counts": {
      "scenario_summary": 0,
      "entity": 0,
      "fact": 2,
      "relationship": 2,
      "evidence": 0,
      "sigma_finding": 0,
      "mitre_assessment": 0,
      "limitation": 1
    },
    "status_counts": {
      "candidate": 0,
      "inferred": 0,
      "observed": 4,
      "reviewable": 1
    },
    "hits_with_evidence_ids": 4,
    "hits_with_source_references": 4,
    "unique_source_reference_count": 4,
    "mapped_hit_count": 5,
    "seed_node_count": 6,
    "traversal_performed": true,
    "traversal_node_count": 12,
    "traversal_edge_count": 17,
    "traversal_path_count": 50,
    "traversed_evidence_node_count": 2,
    "traversed_limitation_node_count": 1,
    "support_edge_count": 11
  },
  "warnings": [
    "lexical: No eligible chunks matched the normalized lexical query terms."
  ],
  "metadata": {
    "decision_made": false,
    "score_interpretations": {
      "rrf": "reciprocal_rank_fusion_not_probability",
      "bm25": "bm25_relevance_not_probability",
      "cosine": "cosine_similarity_not_probability"
    },
    "topical_signal_count": 10,
    "answerability_signal_count": 14
  }
}
```

## rp-vi-observation-provenance

Câu hỏi (vi): Những bản ghi telemetry nào cùng làm căn cứ cho mỗi lần tạo tiến trình trong hai nhóm bằng chứng?

| Thuộc tính | Giá trị |
| --- | --- |
| Partition | calibration |
| Category | relevant_paraphrase |
| Expected decision (dataset) | proceed |
| Actual decision | abstain |
| Abstention stage | topical_relevance |
| Reason codes | ["query_token_coverage_below_threshold", "returned_top_cosine_score_below_threshold"] |
| Topical expected label | true |
| Dataset answerable | true |
| Actual context sufficient | true |
| External context basis | all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation |
| Topical actual stage status | failed |
| Answerability actual stage status | not_evaluated |

Đáp án tham chiếu đã duyệt (evaluation only; giữ nguyên nội dung lịch sử):

Nhóm evidence-b07a5ff4763e629715e6 gồm Security 4688 line 4 và Sysmon 1 line 275 cho cmd.exe → mshta.exe. Nhóm evidence-b31714b888d1489a380c gồm Security 4688 line 30 và Sysmon 1 line 398 cho mshta.exe → powershell.exe. Tất cả thuộc cùng source file; chúng được tương quan thành hai behavior groups để tránh đếm telemetry thành nhiều tiến trình.

Đối chiếu expected evidence và context thực tế; đây là diagnostic ngoài gate:

```json
{
  "ground_truth_pointers": [
    "/evidence/0",
    "/evidence/1"
  ],
  "raw_record_references": [
    {
      "raw_record_ref": "jsonl:line:275",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    },
    {
      "raw_record_ref": "jsonl:line:30",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    },
    {
      "raw_record_ref": "jsonl:line:398",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    },
    {
      "raw_record_ref": "jsonl:line:4",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    }
  ],
  "expected_evidence_ids": [
    "evidence-b07a5ff4763e629715e6",
    "evidence-b31714b888d1489a380c"
  ],
  "returned_evidence_ids": [
    "evidence-b07a5ff4763e629715e6",
    "evidence-b31714b888d1489a380c"
  ],
  "missing_expected_evidence_ids": [],
  "missing_evidence_diagnostics": [],
  "external_context_sufficiency_basis": "all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation"
}
```

Signals đầy đủ đã cung cấp cho gate:

```json
{
  "schema_version": "graphrag-gate-signals/v1",
  "corpus_id": "retrieval-corpus--631ff39273344120e671693f867fbb47057f029d5de0c982d90c7b27e508d7b9",
  "graph_id": "knowledge-graph--45c9e1a1369012689417635f46b00e25ea0b5be2d39a6cf9375428d302ce27ea",
  "scenario_id": "mshta-powershell",
  "source_ground_truth": {
    "path": "outputs/ground_truth/mshta-powershell/scenario_ground_truth.json",
    "schema_version": "scenario-ground-truth/v1",
    "sha256": "b2e3aa48c2c20e6a49479e765db0a1d660121fdb70472ca36f308b1094ddbc41",
    "scenario_id": "mshta-powershell"
  },
  "query": {
    "text": "Những bản ghi telemetry nào cùng làm căn cứ cho mỗi lần tạo tiến trình trong hai nhóm bằng chứng?",
    "normalized_terms": [
      "những",
      "bản",
      "ghi",
      "telemetry",
      "nào",
      "cùng",
      "làm",
      "căn",
      "cứ",
      "cho",
      "mỗi",
      "lần",
      "tạo",
      "tiến",
      "trình",
      "trong",
      "hai",
      "nhóm",
      "bằng",
      "chứng"
    ],
    "top_k": 5,
    "candidate_k": 20,
    "filters": {
      "chunk_types": null,
      "required_dimensions": null
    }
  },
  "topical_relevance": {
    "retrieval_hit_count": 5,
    "lexical_hit_count": 0,
    "vector_hit_count": 5,
    "joint_lexical_vector_hit_count": 0,
    "returned_top_rrf_score": 0.016393442623,
    "returned_top_bm25_score": null,
    "returned_top_cosine_score": 0.78163017,
    "query_token_count": 20,
    "matched_query_token_count": 0,
    "query_token_coverage": 0.0
  },
  "evidence_answerability": {
    "chunk_type_counts": {
      "scenario_summary": 0,
      "entity": 0,
      "fact": 1,
      "relationship": 1,
      "evidence": 0,
      "sigma_finding": 0,
      "mitre_assessment": 3,
      "limitation": 0
    },
    "status_counts": {
      "candidate": 3,
      "inferred": 0,
      "observed": 2,
      "reviewable": 0
    },
    "hits_with_evidence_ids": 4,
    "hits_with_source_references": 4,
    "unique_source_reference_count": 4,
    "mapped_hit_count": 5,
    "seed_node_count": 6,
    "traversal_performed": true,
    "traversal_node_count": 12,
    "traversal_edge_count": 21,
    "traversal_path_count": 56,
    "traversed_evidence_node_count": 2,
    "traversed_limitation_node_count": 0,
    "support_edge_count": 15
  },
  "warnings": [
    "lexical: No eligible chunks matched the normalized lexical query terms."
  ],
  "metadata": {
    "decision_made": false,
    "score_interpretations": {
      "rrf": "reciprocal_rank_fusion_not_probability",
      "bm25": "bm25_relevance_not_probability",
      "cosine": "cosine_similarity_not_probability"
    },
    "topical_signal_count": 10,
    "answerability_signal_count": 14
  }
}
```

## rp-vi-service-action

Câu hỏi (vi): Lệnh liên quan đến dịch vụ được ghi nhận trên command line khi PowerShell được khởi chạy là gì?

| Thuộc tính | Giá trị |
| --- | --- |
| Partition | calibration |
| Category | relevant_paraphrase |
| Expected decision (dataset) | proceed |
| Actual decision | abstain |
| Abstention stage | topical_relevance |
| Reason codes | ["query_token_coverage_below_threshold", "returned_top_cosine_score_below_threshold"] |
| Topical expected label | true |
| Dataset answerable | true |
| Actual context sufficient | false |
| External context basis | known_required_information_missing_from_actual_returned_context |
| Topical actual stage status | failed |
| Answerability actual stage status | not_evaluated |

Đáp án tham chiếu đã duyệt (evaluation only; giữ nguyên nội dung lịch sử):

Command line của PowerShell ở jsonl:line:30 và jsonl:line:398 chứa -noexit -command Get-Service sysmon. Điều được quan sát trực tiếp là PowerShell được khởi chạy với lệnh này; căn cứ hiện có chưa cung cấp đầu ra cmdlet hoặc chứng minh trạng thái dịch vụ Sysmon. Không suy ra payload tải xuống, C2 hay thao tác phá hoại.

Đối chiếu expected evidence và context thực tế; đây là diagnostic ngoài gate:

```json
{
  "ground_truth_pointers": [
    "/scenario"
  ],
  "raw_record_references": [
    {
      "raw_record_ref": "jsonl:line:30",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    },
    {
      "raw_record_ref": "jsonl:line:398",
      "source_file": "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    }
  ],
  "expected_evidence_ids": [
    "evidence-b31714b888d1489a380c"
  ],
  "returned_evidence_ids": [
    "evidence-b07a5ff4763e629715e6",
    "evidence-b31714b888d1489a380c"
  ],
  "missing_expected_evidence_ids": [],
  "missing_evidence_diagnostics": [
    {
      "answer_unit_id": "launch_command",
      "source_ground_truth_pointer": "/facts/1",
      "support_status": "known_missing",
      "reason": "original_command_line_field_not_returned_summary_or_reference_is_insufficient"
    },
    {
      "answer_unit_id": "limitation_4",
      "source_ground_truth_pointer": "/summary/limitations/4",
      "support_status": "known_missing",
      "reason": "full_consumer_audit_established_required_information_is_absent"
    }
  ],
  "external_context_sufficiency_basis": "known_required_information_missing_from_actual_returned_context"
}
```

Signals đầy đủ đã cung cấp cho gate:

```json
{
  "schema_version": "graphrag-gate-signals/v1",
  "corpus_id": "retrieval-corpus--631ff39273344120e671693f867fbb47057f029d5de0c982d90c7b27e508d7b9",
  "graph_id": "knowledge-graph--45c9e1a1369012689417635f46b00e25ea0b5be2d39a6cf9375428d302ce27ea",
  "scenario_id": "mshta-powershell",
  "source_ground_truth": {
    "path": "outputs/ground_truth/mshta-powershell/scenario_ground_truth.json",
    "schema_version": "scenario-ground-truth/v1",
    "sha256": "b2e3aa48c2c20e6a49479e765db0a1d660121fdb70472ca36f308b1094ddbc41",
    "scenario_id": "mshta-powershell"
  },
  "query": {
    "text": "Lệnh liên quan đến dịch vụ được ghi nhận trên command line khi PowerShell được khởi chạy là gì?",
    "normalized_terms": [
      "lệnh",
      "liên",
      "quan",
      "đến",
      "dịch",
      "vụ",
      "được",
      "ghi",
      "nhận",
      "trên",
      "command",
      "line",
      "khi",
      "powershell",
      "khởi",
      "chạy",
      "là",
      "gì"
    ],
    "top_k": 5,
    "candidate_k": 20,
    "filters": {
      "chunk_types": null,
      "required_dimensions": null
    }
  },
  "topical_relevance": {
    "retrieval_hit_count": 5,
    "lexical_hit_count": 3,
    "vector_hit_count": 5,
    "joint_lexical_vector_hit_count": 3,
    "returned_top_rrf_score": 0.032786885246,
    "returned_top_bm25_score": 4.97909685,
    "returned_top_cosine_score": 0.84055646,
    "query_token_count": 18,
    "matched_query_token_count": 3,
    "query_token_coverage": 0.16666667
  },
  "evidence_answerability": {
    "chunk_type_counts": {
      "scenario_summary": 1,
      "entity": 1,
      "fact": 0,
      "relationship": 1,
      "evidence": 0,
      "sigma_finding": 0,
      "mitre_assessment": 2,
      "limitation": 0
    },
    "status_counts": {
      "candidate": 2,
      "inferred": 0,
      "observed": 2,
      "reviewable": 1
    },
    "hits_with_evidence_ids": 4,
    "hits_with_source_references": 5,
    "unique_source_reference_count": 4,
    "mapped_hit_count": 5,
    "seed_node_count": 5,
    "traversal_performed": true,
    "traversal_node_count": 13,
    "traversal_edge_count": 21,
    "traversal_path_count": 41,
    "traversed_evidence_node_count": 2,
    "traversed_limitation_node_count": 0,
    "support_edge_count": 15
  },
  "warnings": [],
  "metadata": {
    "decision_made": false,
    "score_interpretations": {
      "rrf": "reciprocal_rank_fusion_not_probability",
      "bm25": "bm25_relevance_not_probability",
      "cosine": "cosine_similarity_not_probability"
    },
    "topical_signal_count": 10,
    "answerability_signal_count": 14
  }
}
```

## ur-en-linux-cron

Câu hỏi (en): How do I schedule a Linux cron job to run every ten minutes?

| Thuộc tính | Giá trị |
| --- | --- |
| Partition | calibration |
| Category | unrelated |
| Expected decision (dataset) | abstain |
| Actual decision | abstain |
| Abstention stage | topical_relevance |
| Reason codes | ["query_token_coverage_below_threshold", "returned_top_cosine_score_below_threshold"] |
| Topical expected label | false |
| Dataset answerable | null |
| Actual context sufficient | null |
| External context basis | outside_scope_answerability_not_applicable |
| Topical actual stage status | failed |
| Answerability actual stage status | not_evaluated |

Đáp án tham chiếu đã duyệt (evaluation only; giữ nguyên nội dung lịch sử):

Hướng dẫn Linux cron nằm ngoài phạm vi bằng chứng thực thi tiến trình Windows của ground truth MSHTA–PowerShell.

Đối chiếu expected evidence và context thực tế; đây là diagnostic ngoài gate:

```json
{
  "ground_truth_pointers": [],
  "raw_record_references": [],
  "expected_evidence_ids": [],
  "returned_evidence_ids": [
    "evidence-b07a5ff4763e629715e6",
    "evidence-b31714b888d1489a380c"
  ],
  "missing_expected_evidence_ids": [],
  "missing_evidence_diagnostics": [],
  "external_context_sufficiency_basis": "outside_scope_answerability_not_applicable"
}
```

Signals đầy đủ đã cung cấp cho gate:

```json
{
  "schema_version": "graphrag-gate-signals/v1",
  "corpus_id": "retrieval-corpus--631ff39273344120e671693f867fbb47057f029d5de0c982d90c7b27e508d7b9",
  "graph_id": "knowledge-graph--45c9e1a1369012689417635f46b00e25ea0b5be2d39a6cf9375428d302ce27ea",
  "scenario_id": "mshta-powershell",
  "source_ground_truth": {
    "path": "outputs/ground_truth/mshta-powershell/scenario_ground_truth.json",
    "schema_version": "scenario-ground-truth/v1",
    "sha256": "b2e3aa48c2c20e6a49479e765db0a1d660121fdb70472ca36f308b1094ddbc41",
    "scenario_id": "mshta-powershell"
  },
  "query": {
    "text": "How do I schedule a Linux cron job to run every ten minutes?",
    "normalized_terms": [
      "how",
      "do",
      "i",
      "schedule",
      "a",
      "linux",
      "cron",
      "job",
      "to",
      "run",
      "every",
      "ten",
      "minutes"
    ],
    "top_k": 5,
    "candidate_k": 20,
    "filters": {
      "chunk_types": null,
      "required_dimensions": null
    }
  },
  "topical_relevance": {
    "retrieval_hit_count": 5,
    "lexical_hit_count": 3,
    "vector_hit_count": 5,
    "joint_lexical_vector_hit_count": 3,
    "returned_top_rrf_score": 0.031778058008,
    "returned_top_bm25_score": 3.27570207,
    "returned_top_cosine_score": 0.81452207,
    "query_token_count": 13,
    "matched_query_token_count": 2,
    "query_token_coverage": 0.15384615
  },
  "evidence_answerability": {
    "chunk_type_counts": {
      "scenario_summary": 1,
      "entity": 0,
      "fact": 0,
      "relationship": 1,
      "evidence": 0,
      "sigma_finding": 0,
      "mitre_assessment": 2,
      "limitation": 1
    },
    "status_counts": {
      "candidate": 2,
      "inferred": 0,
      "observed": 1,
      "reviewable": 2
    },
    "hits_with_evidence_ids": 2,
    "hits_with_source_references": 3,
    "unique_source_reference_count": 4,
    "mapped_hit_count": 5,
    "seed_node_count": 6,
    "traversal_performed": true,
    "traversal_node_count": 14,
    "traversal_edge_count": 20,
    "traversal_path_count": 36,
    "traversed_evidence_node_count": 2,
    "traversed_limitation_node_count": 1,
    "support_edge_count": 14
  },
  "warnings": [],
  "metadata": {
    "decision_made": false,
    "score_interpretations": {
      "rrf": "reciprocal_rank_fusion_not_probability",
      "bm25": "bm25_relevance_not_probability",
      "cosine": "cosine_similarity_not_probability"
    },
    "topical_signal_count": 10,
    "answerability_signal_count": 14
  }
}
```

## ur-en-product-price

Câu hỏi (en): What is the current price of a gaming laptop?

| Thuộc tính | Giá trị |
| --- | --- |
| Partition | calibration |
| Category | unrelated |
| Expected decision (dataset) | abstain |
| Actual decision | abstain |
| Abstention stage | topical_relevance |
| Reason codes | ["returned_top_cosine_score_below_threshold"] |
| Topical expected label | false |
| Dataset answerable | null |
| Actual context sufficient | null |
| External context basis | outside_scope_answerability_not_applicable |
| Topical actual stage status | failed |
| Answerability actual stage status | not_evaluated |

Đáp án tham chiếu đã duyệt (evaluation only; giữ nguyên nội dung lịch sử):

Câu hỏi giá laptop nằm ngoài phạm vi ground truth MSHTA–PowerShell; corpus này không cung cấp căn cứ về giá sản phẩm.

Đối chiếu expected evidence và context thực tế; đây là diagnostic ngoài gate:

```json
{
  "ground_truth_pointers": [],
  "raw_record_references": [],
  "expected_evidence_ids": [],
  "returned_evidence_ids": [
    "evidence-b07a5ff4763e629715e6",
    "evidence-b31714b888d1489a380c"
  ],
  "missing_expected_evidence_ids": [],
  "missing_evidence_diagnostics": [],
  "external_context_sufficiency_basis": "outside_scope_answerability_not_applicable"
}
```

Signals đầy đủ đã cung cấp cho gate:

```json
{
  "schema_version": "graphrag-gate-signals/v1",
  "corpus_id": "retrieval-corpus--631ff39273344120e671693f867fbb47057f029d5de0c982d90c7b27e508d7b9",
  "graph_id": "knowledge-graph--45c9e1a1369012689417635f46b00e25ea0b5be2d39a6cf9375428d302ce27ea",
  "scenario_id": "mshta-powershell",
  "source_ground_truth": {
    "path": "outputs/ground_truth/mshta-powershell/scenario_ground_truth.json",
    "schema_version": "scenario-ground-truth/v1",
    "sha256": "b2e3aa48c2c20e6a49479e765db0a1d660121fdb70472ca36f308b1094ddbc41",
    "scenario_id": "mshta-powershell"
  },
  "query": {
    "text": "What is the current price of a gaming laptop?",
    "normalized_terms": [
      "what",
      "is",
      "the",
      "current",
      "price",
      "of",
      "a",
      "gaming",
      "laptop"
    ],
    "top_k": 5,
    "candidate_k": 20,
    "filters": {
      "chunk_types": null,
      "required_dimensions": null
    }
  },
  "topical_relevance": {
    "retrieval_hit_count": 5,
    "lexical_hit_count": 5,
    "vector_hit_count": 5,
    "joint_lexical_vector_hit_count": 5,
    "returned_top_rrf_score": 0.032018442623,
    "returned_top_bm25_score": 6.47970629,
    "returned_top_cosine_score": 0.75130365,
    "query_token_count": 9,
    "matched_query_token_count": 5,
    "query_token_coverage": 0.55555556
  },
  "evidence_answerability": {
    "chunk_type_counts": {
      "scenario_summary": 1,
      "entity": 0,
      "fact": 0,
      "relationship": 0,
      "evidence": 0,
      "sigma_finding": 0,
      "mitre_assessment": 3,
      "limitation": 1
    },
    "status_counts": {
      "candidate": 3,
      "inferred": 0,
      "observed": 0,
      "reviewable": 2
    },
    "hits_with_evidence_ids": 2,
    "hits_with_source_references": 3,
    "unique_source_reference_count": 4,
    "mapped_hit_count": 5,
    "seed_node_count": 5,
    "traversal_performed": true,
    "traversal_node_count": 14,
    "traversal_edge_count": 15,
    "traversal_path_count": 27,
    "traversed_evidence_node_count": 2,
    "traversed_limitation_node_count": 1,
    "support_edge_count": 15
  },
  "warnings": [],
  "metadata": {
    "decision_made": false,
    "score_interpretations": {
      "rrf": "reciprocal_rank_fusion_not_probability",
      "bm25": "bm25_relevance_not_probability",
      "cosine": "cosine_similarity_not_probability"
    },
    "topical_signal_count": 10,
    "answerability_signal_count": 14
  }
}
```

## ur-en-sql-injection

Câu hỏi (en): How can I prevent SQL injection in a web application's database queries?

| Thuộc tính | Giá trị |
| --- | --- |
| Partition | calibration |
| Category | unrelated |
| Expected decision (dataset) | abstain |
| Actual decision | abstain |
| Abstention stage | topical_relevance |
| Reason codes | ["query_token_coverage_below_threshold", "returned_top_cosine_score_below_threshold"] |
| Topical expected label | false |
| Dataset answerable | null |
| Actual context sufficient | null |
| External context basis | outside_scope_answerability_not_applicable |
| Topical actual stage status | failed |
| Answerability actual stage status | not_evaluated |

Đáp án tham chiếu đã duyệt (evaluation only; giữ nguyên nội dung lịch sử):

Hướng dẫn phòng SQL injection nằm ngoài phạm vi ground truth MSHTA–PowerShell; corpus này không phải nguồn trả lời câu hỏi cấu hình bảo mật cơ sở dữ liệu web.

Đối chiếu expected evidence và context thực tế; đây là diagnostic ngoài gate:

```json
{
  "ground_truth_pointers": [],
  "raw_record_references": [],
  "expected_evidence_ids": [],
  "returned_evidence_ids": [
    "evidence-b07a5ff4763e629715e6",
    "evidence-b31714b888d1489a380c"
  ],
  "missing_expected_evidence_ids": [],
  "missing_evidence_diagnostics": [],
  "external_context_sufficiency_basis": "outside_scope_answerability_not_applicable"
}
```

Signals đầy đủ đã cung cấp cho gate:

```json
{
  "schema_version": "graphrag-gate-signals/v1",
  "corpus_id": "retrieval-corpus--631ff39273344120e671693f867fbb47057f029d5de0c982d90c7b27e508d7b9",
  "graph_id": "knowledge-graph--45c9e1a1369012689417635f46b00e25ea0b5be2d39a6cf9375428d302ce27ea",
  "scenario_id": "mshta-powershell",
  "source_ground_truth": {
    "path": "outputs/ground_truth/mshta-powershell/scenario_ground_truth.json",
    "schema_version": "scenario-ground-truth/v1",
    "sha256": "b2e3aa48c2c20e6a49479e765db0a1d660121fdb70472ca36f308b1094ddbc41",
    "scenario_id": "mshta-powershell"
  },
  "query": {
    "text": "How can I prevent SQL injection in a web application's database queries?",
    "normalized_terms": [
      "how",
      "can",
      "i",
      "prevent",
      "sql",
      "injection",
      "in",
      "a",
      "web",
      "application",
      "s",
      "database",
      "queries"
    ],
    "top_k": 5,
    "candidate_k": 20,
    "filters": {
      "chunk_types": null,
      "required_dimensions": null
    }
  },
  "topical_relevance": {
    "retrieval_hit_count": 5,
    "lexical_hit_count": 5,
    "vector_hit_count": 5,
    "joint_lexical_vector_hit_count": 5,
    "returned_top_rrf_score": 0.032002048131,
    "returned_top_bm25_score": 2.34638997,
    "returned_top_cosine_score": 0.8121783,
    "query_token_count": 13,
    "matched_query_token_count": 2,
    "query_token_coverage": 0.15384615
  },
  "evidence_answerability": {
    "chunk_type_counts": {
      "scenario_summary": 1,
      "entity": 0,
      "fact": 0,
      "relationship": 0,
      "evidence": 0,
      "sigma_finding": 0,
      "mitre_assessment": 3,
      "limitation": 1
    },
    "status_counts": {
      "candidate": 3,
      "inferred": 0,
      "observed": 0,
      "reviewable": 2
    },
    "hits_with_evidence_ids": 2,
    "hits_with_source_references": 3,
    "unique_source_reference_count": 4,
    "mapped_hit_count": 5,
    "seed_node_count": 5,
    "traversal_performed": true,
    "traversal_node_count": 14,
    "traversal_edge_count": 15,
    "traversal_path_count": 27,
    "traversed_evidence_node_count": 2,
    "traversed_limitation_node_count": 1,
    "support_edge_count": 15
  },
  "warnings": [],
  "metadata": {
    "decision_made": false,
    "score_interpretations": {
      "rrf": "reciprocal_rank_fusion_not_probability",
      "bm25": "bm25_relevance_not_probability",
      "cosine": "cosine_similarity_not_probability"
    },
    "topical_signal_count": 10,
    "answerability_signal_count": 14
  }
}
```

## ur-en-weather

Câu hỏi (en): What will the weather be in Hanoi tomorrow?

| Thuộc tính | Giá trị |
| --- | --- |
| Partition | calibration |
| Category | unrelated |
| Expected decision (dataset) | abstain |
| Actual decision | abstain |
| Abstention stage | topical_relevance |
| Reason codes | ["returned_top_cosine_score_below_threshold"] |
| Topical expected label | false |
| Dataset answerable | null |
| Actual context sufficient | null |
| External context basis | outside_scope_answerability_not_applicable |
| Topical actual stage status | failed |
| Answerability actual stage status | not_evaluated |

Đáp án tham chiếu đã duyệt (evaluation only; giữ nguyên nội dung lịch sử):

Câu hỏi dự báo thời tiết nằm ngoài phạm vi ground truth MSHTA–PowerShell; corpus này không cung cấp căn cứ trả lời.

Đối chiếu expected evidence và context thực tế; đây là diagnostic ngoài gate:

```json
{
  "ground_truth_pointers": [],
  "raw_record_references": [],
  "expected_evidence_ids": [],
  "returned_evidence_ids": [
    "evidence-b07a5ff4763e629715e6",
    "evidence-b31714b888d1489a380c"
  ],
  "missing_expected_evidence_ids": [],
  "missing_evidence_diagnostics": [],
  "external_context_sufficiency_basis": "outside_scope_answerability_not_applicable"
}
```

Signals đầy đủ đã cung cấp cho gate:

```json
{
  "schema_version": "graphrag-gate-signals/v1",
  "corpus_id": "retrieval-corpus--631ff39273344120e671693f867fbb47057f029d5de0c982d90c7b27e508d7b9",
  "graph_id": "knowledge-graph--45c9e1a1369012689417635f46b00e25ea0b5be2d39a6cf9375428d302ce27ea",
  "scenario_id": "mshta-powershell",
  "source_ground_truth": {
    "path": "outputs/ground_truth/mshta-powershell/scenario_ground_truth.json",
    "schema_version": "scenario-ground-truth/v1",
    "sha256": "b2e3aa48c2c20e6a49479e765db0a1d660121fdb70472ca36f308b1094ddbc41",
    "scenario_id": "mshta-powershell"
  },
  "query": {
    "text": "What will the weather be in Hanoi tomorrow?",
    "normalized_terms": [
      "what",
      "will",
      "the",
      "weather",
      "be",
      "in",
      "hanoi",
      "tomorrow"
    ],
    "top_k": 5,
    "candidate_k": 20,
    "filters": {
      "chunk_types": null,
      "required_dimensions": null
    }
  },
  "topical_relevance": {
    "retrieval_hit_count": 5,
    "lexical_hit_count": 5,
    "vector_hit_count": 5,
    "joint_lexical_vector_hit_count": 5,
    "returned_top_rrf_score": 0.031778058008,
    "returned_top_bm25_score": 3.83130508,
    "returned_top_cosine_score": 0.73406129,
    "query_token_count": 8,
    "matched_query_token_count": 3,
    "query_token_coverage": 0.375
  },
  "evidence_answerability": {
    "chunk_type_counts": {
      "scenario_summary": 0,
      "entity": 0,
      "fact": 0,
      "relationship": 0,
      "evidence": 0,
      "sigma_finding": 0,
      "mitre_assessment": 3,
      "limitation": 2
    },
    "status_counts": {
      "candidate": 3,
      "inferred": 0,
      "observed": 0,
      "reviewable": 2
    },
    "hits_with_evidence_ids": 2,
    "hits_with_source_references": 2,
    "unique_source_reference_count": 4,
    "mapped_hit_count": 5,
    "seed_node_count": 5,
    "traversal_performed": true,
    "traversal_node_count": 14,
    "traversal_edge_count": 15,
    "traversal_path_count": 27,
    "traversed_evidence_node_count": 2,
    "traversed_limitation_node_count": 2,
    "support_edge_count": 15
  },
  "warnings": [],
  "metadata": {
    "decision_made": false,
    "score_interpretations": {
      "rrf": "reciprocal_rank_fusion_not_probability",
      "bm25": "bm25_relevance_not_probability",
      "cosine": "cosine_similarity_not_probability"
    },
    "topical_signal_count": 10,
    "answerability_signal_count": 14
  }
}
```

## ur-vi-kubernetes-configuration

Câu hỏi (vi): Cần cấu hình Kubernetes thế nào để tự động mở rộng một Deployment?

| Thuộc tính | Giá trị |
| --- | --- |
| Partition | calibration |
| Category | unrelated |
| Expected decision (dataset) | abstain |
| Actual decision | abstain |
| Abstention stage | topical_relevance |
| Reason codes | ["query_token_coverage_below_threshold", "returned_top_cosine_score_below_threshold"] |
| Topical expected label | false |
| Dataset answerable | null |
| Actual context sufficient | null |
| External context basis | outside_scope_answerability_not_applicable |
| Topical actual stage status | failed |
| Answerability actual stage status | not_evaluated |

Đáp án tham chiếu đã duyệt (evaluation only; giữ nguyên nội dung lịch sử):

Cấu hình tự động mở rộng Kubernetes Deployment nằm ngoài phạm vi ground truth MSHTA–PowerShell; corpus không cung cấp căn cứ hướng dẫn.

Đối chiếu expected evidence và context thực tế; đây là diagnostic ngoài gate:

```json
{
  "ground_truth_pointers": [],
  "raw_record_references": [],
  "expected_evidence_ids": [],
  "returned_evidence_ids": [
    "evidence-b07a5ff4763e629715e6",
    "evidence-b31714b888d1489a380c"
  ],
  "missing_expected_evidence_ids": [],
  "missing_evidence_diagnostics": [],
  "external_context_sufficiency_basis": "outside_scope_answerability_not_applicable"
}
```

Signals đầy đủ đã cung cấp cho gate:

```json
{
  "schema_version": "graphrag-gate-signals/v1",
  "corpus_id": "retrieval-corpus--631ff39273344120e671693f867fbb47057f029d5de0c982d90c7b27e508d7b9",
  "graph_id": "knowledge-graph--45c9e1a1369012689417635f46b00e25ea0b5be2d39a6cf9375428d302ce27ea",
  "scenario_id": "mshta-powershell",
  "source_ground_truth": {
    "path": "outputs/ground_truth/mshta-powershell/scenario_ground_truth.json",
    "schema_version": "scenario-ground-truth/v1",
    "sha256": "b2e3aa48c2c20e6a49479e765db0a1d660121fdb70472ca36f308b1094ddbc41",
    "scenario_id": "mshta-powershell"
  },
  "query": {
    "text": "Cần cấu hình Kubernetes thế nào để tự động mở rộng một Deployment?",
    "normalized_terms": [
      "cần",
      "cấu",
      "hình",
      "kubernetes",
      "thế",
      "nào",
      "để",
      "tự",
      "động",
      "mở",
      "rộng",
      "một",
      "deployment"
    ],
    "top_k": 5,
    "candidate_k": 20,
    "filters": {
      "chunk_types": null,
      "required_dimensions": null
    }
  },
  "topical_relevance": {
    "retrieval_hit_count": 5,
    "lexical_hit_count": 0,
    "vector_hit_count": 5,
    "joint_lexical_vector_hit_count": 0,
    "returned_top_rrf_score": 0.016393442623,
    "returned_top_bm25_score": null,
    "returned_top_cosine_score": 0.77706801,
    "query_token_count": 13,
    "matched_query_token_count": 0,
    "query_token_coverage": 0.0
  },
  "evidence_answerability": {
    "chunk_type_counts": {
      "scenario_summary": 0,
      "entity": 2,
      "fact": 0,
      "relationship": 2,
      "evidence": 0,
      "sigma_finding": 0,
      "mitre_assessment": 1,
      "limitation": 0
    },
    "status_counts": {
      "candidate": 1,
      "inferred": 0,
      "observed": 4,
      "reviewable": 0
    },
    "hits_with_evidence_ids": 4,
    "hits_with_source_references": 4,
    "unique_source_reference_count": 4,
    "mapped_hit_count": 5,
    "seed_node_count": 4,
    "traversal_performed": true,
    "traversal_node_count": 12,
    "traversal_edge_count": 20,
    "traversal_path_count": 35,
    "traversed_evidence_node_count": 2,
    "traversed_limitation_node_count": 0,
    "support_edge_count": 14
  },
  "warnings": [
    "lexical: No eligible chunks matched the normalized lexical query terms."
  ],
  "metadata": {
    "decision_made": false,
    "score_interpretations": {
      "rrf": "reciprocal_rank_fusion_not_probability",
      "bm25": "bm25_relevance_not_probability",
      "cosine": "cosine_similarity_not_probability"
    },
    "topical_signal_count": 10,
    "answerability_signal_count": 14
  }
}
```

## ur-vi-literature-learning

Câu hỏi (vi): Làm thế nào phân biệt hình ảnh ẩn dụ và hoán dụ trong một bài thơ?

| Thuộc tính | Giá trị |
| --- | --- |
| Partition | calibration |
| Category | unrelated |
| Expected decision (dataset) | abstain |
| Actual decision | abstain |
| Abstention stage | topical_relevance |
| Reason codes | ["query_token_coverage_below_threshold", "returned_top_cosine_score_below_threshold"] |
| Topical expected label | false |
| Dataset answerable | null |
| Actual context sufficient | null |
| External context basis | outside_scope_answerability_not_applicable |
| Topical actual stage status | failed |
| Answerability actual stage status | not_evaluated |

Đáp án tham chiếu đã duyệt (evaluation only; giữ nguyên nội dung lịch sử):

Phân biệt ẩn dụ và hoán dụ trong thơ nằm ngoài phạm vi ground truth MSHTA–PowerShell; không có chunk liên quan để trả lời.

Đối chiếu expected evidence và context thực tế; đây là diagnostic ngoài gate:

```json
{
  "ground_truth_pointers": [],
  "raw_record_references": [],
  "expected_evidence_ids": [],
  "returned_evidence_ids": [
    "evidence-b07a5ff4763e629715e6",
    "evidence-b31714b888d1489a380c"
  ],
  "missing_expected_evidence_ids": [],
  "missing_evidence_diagnostics": [],
  "external_context_sufficiency_basis": "outside_scope_answerability_not_applicable"
}
```

Signals đầy đủ đã cung cấp cho gate:

```json
{
  "schema_version": "graphrag-gate-signals/v1",
  "corpus_id": "retrieval-corpus--631ff39273344120e671693f867fbb47057f029d5de0c982d90c7b27e508d7b9",
  "graph_id": "knowledge-graph--45c9e1a1369012689417635f46b00e25ea0b5be2d39a6cf9375428d302ce27ea",
  "scenario_id": "mshta-powershell",
  "source_ground_truth": {
    "path": "outputs/ground_truth/mshta-powershell/scenario_ground_truth.json",
    "schema_version": "scenario-ground-truth/v1",
    "sha256": "b2e3aa48c2c20e6a49479e765db0a1d660121fdb70472ca36f308b1094ddbc41",
    "scenario_id": "mshta-powershell"
  },
  "query": {
    "text": "Làm thế nào phân biệt hình ảnh ẩn dụ và hoán dụ trong một bài thơ?",
    "normalized_terms": [
      "làm",
      "thế",
      "nào",
      "phân",
      "biệt",
      "hình",
      "ảnh",
      "ẩn",
      "dụ",
      "và",
      "hoán",
      "trong",
      "một",
      "bài",
      "thơ"
    ],
    "top_k": 5,
    "candidate_k": 20,
    "filters": {
      "chunk_types": null,
      "required_dimensions": null
    }
  },
  "topical_relevance": {
    "retrieval_hit_count": 5,
    "lexical_hit_count": 0,
    "vector_hit_count": 5,
    "joint_lexical_vector_hit_count": 0,
    "returned_top_rrf_score": 0.016393442623,
    "returned_top_bm25_score": null,
    "returned_top_cosine_score": 0.73637269,
    "query_token_count": 15,
    "matched_query_token_count": 0,
    "query_token_coverage": 0.0
  },
  "evidence_answerability": {
    "chunk_type_counts": {
      "scenario_summary": 0,
      "entity": 1,
      "fact": 1,
      "relationship": 2,
      "evidence": 0,
      "sigma_finding": 0,
      "mitre_assessment": 1,
      "limitation": 0
    },
    "status_counts": {
      "candidate": 1,
      "inferred": 0,
      "observed": 4,
      "reviewable": 0
    },
    "hits_with_evidence_ids": 4,
    "hits_with_source_references": 4,
    "unique_source_reference_count": 4,
    "mapped_hit_count": 5,
    "seed_node_count": 5,
    "traversal_performed": true,
    "traversal_node_count": 12,
    "traversal_edge_count": 20,
    "traversal_path_count": 44,
    "traversed_evidence_node_count": 2,
    "traversed_limitation_node_count": 0,
    "support_edge_count": 14
  },
  "warnings": [
    "lexical: No eligible chunks matched the normalized lexical query terms."
  ],
  "metadata": {
    "decision_made": false,
    "score_interpretations": {
      "rrf": "reciprocal_rank_fusion_not_probability",
      "bm25": "bm25_relevance_not_probability",
      "cosine": "cosine_similarity_not_probability"
    },
    "topical_signal_count": 10,
    "answerability_signal_count": 14
  }
}
```

## ur-vi-opaque-token

Câu hỏi (vi): Chuỗi velora_quartz_token_483920761 có ý nghĩa gì?

| Thuộc tính | Giá trị |
| --- | --- |
| Partition | calibration |
| Category | unrelated |
| Expected decision (dataset) | abstain |
| Actual decision | abstain |
| Abstention stage | topical_relevance |
| Reason codes | ["query_token_coverage_below_threshold", "returned_top_cosine_score_below_threshold"] |
| Topical expected label | false |
| Dataset answerable | null |
| Actual context sufficient | null |
| External context basis | outside_scope_answerability_not_applicable |
| Topical actual stage status | failed |
| Answerability actual stage status | not_evaluated |

Đáp án tham chiếu đã duyệt (evaluation only; giữ nguyên nội dung lịch sử):

Chuỗi velora_quartz_token_483920761 không có ngữ cảnh trong corpus MSHTA–PowerShell; không đủ cơ sở gán ý nghĩa cho chuỗi ngoài phạm vi này.

Đối chiếu expected evidence và context thực tế; đây là diagnostic ngoài gate:

```json
{
  "ground_truth_pointers": [],
  "raw_record_references": [],
  "expected_evidence_ids": [],
  "returned_evidence_ids": [
    "evidence-b07a5ff4763e629715e6",
    "evidence-b31714b888d1489a380c"
  ],
  "missing_expected_evidence_ids": [],
  "missing_evidence_diagnostics": [],
  "external_context_sufficiency_basis": "outside_scope_answerability_not_applicable"
}
```

Signals đầy đủ đã cung cấp cho gate:

```json
{
  "schema_version": "graphrag-gate-signals/v1",
  "corpus_id": "retrieval-corpus--631ff39273344120e671693f867fbb47057f029d5de0c982d90c7b27e508d7b9",
  "graph_id": "knowledge-graph--45c9e1a1369012689417635f46b00e25ea0b5be2d39a6cf9375428d302ce27ea",
  "scenario_id": "mshta-powershell",
  "source_ground_truth": {
    "path": "outputs/ground_truth/mshta-powershell/scenario_ground_truth.json",
    "schema_version": "scenario-ground-truth/v1",
    "sha256": "b2e3aa48c2c20e6a49479e765db0a1d660121fdb70472ca36f308b1094ddbc41",
    "scenario_id": "mshta-powershell"
  },
  "query": {
    "text": "Chuỗi velora_quartz_token_483920761 có ý nghĩa gì?",
    "normalized_terms": [
      "chuỗi",
      "velora_quartz_token_483920761",
      "có",
      "ý",
      "nghĩa",
      "gì"
    ],
    "top_k": 5,
    "candidate_k": 20,
    "filters": {
      "chunk_types": null,
      "required_dimensions": null
    }
  },
  "topical_relevance": {
    "retrieval_hit_count": 5,
    "lexical_hit_count": 0,
    "vector_hit_count": 5,
    "joint_lexical_vector_hit_count": 0,
    "returned_top_rrf_score": 0.016393442623,
    "returned_top_bm25_score": null,
    "returned_top_cosine_score": 0.75798392,
    "query_token_count": 6,
    "matched_query_token_count": 0,
    "query_token_coverage": 0.0
  },
  "evidence_answerability": {
    "chunk_type_counts": {
      "scenario_summary": 0,
      "entity": 1,
      "fact": 2,
      "relationship": 2,
      "evidence": 0,
      "sigma_finding": 0,
      "mitre_assessment": 0,
      "limitation": 0
    },
    "status_counts": {
      "candidate": 0,
      "inferred": 0,
      "observed": 5,
      "reviewable": 0
    },
    "hits_with_evidence_ids": 5,
    "hits_with_source_references": 5,
    "unique_source_reference_count": 4,
    "mapped_hit_count": 5,
    "seed_node_count": 5,
    "traversal_performed": true,
    "traversal_node_count": 11,
    "traversal_edge_count": 17,
    "traversal_path_count": 49,
    "traversed_evidence_node_count": 2,
    "traversed_limitation_node_count": 0,
    "support_edge_count": 11
  },
  "warnings": [
    "lexical: No eligible chunks matched the normalized lexical query terms."
  ],
  "metadata": {
    "decision_made": false,
    "score_interpretations": {
      "rrf": "reciprocal_rank_fusion_not_probability",
      "bm25": "bm25_relevance_not_probability",
      "cosine": "cosine_similarity_not_probability"
    },
    "topical_signal_count": 10,
    "answerability_signal_count": 14
  }
}
```

## ur-vi-ransomware-encryption

Câu hỏi (vi): Mã hóa ransomware xử lý các khóa mật mã như thế nào?

| Thuộc tính | Giá trị |
| --- | --- |
| Partition | calibration |
| Category | unrelated |
| Expected decision (dataset) | abstain |
| Actual decision | abstain |
| Abstention stage | topical_relevance |
| Reason codes | ["query_token_coverage_below_threshold", "returned_top_cosine_score_below_threshold"] |
| Topical expected label | false |
| Dataset answerable | null |
| Actual context sufficient | null |
| External context basis | outside_scope_answerability_not_applicable |
| Topical actual stage status | failed |
| Answerability actual stage status | not_evaluated |

Đáp án tham chiếu đã duyệt (evaluation only; giữ nguyên nội dung lịch sử):

Cơ chế quản lý khóa của ransomware nằm ngoài phạm vi MSHTA–PowerShell đang được đánh giá; corpus này không có tri thức để giải thích yêu cầu đó.

Đối chiếu expected evidence và context thực tế; đây là diagnostic ngoài gate:

```json
{
  "ground_truth_pointers": [],
  "raw_record_references": [],
  "expected_evidence_ids": [],
  "returned_evidence_ids": [
    "evidence-b07a5ff4763e629715e6",
    "evidence-b31714b888d1489a380c"
  ],
  "missing_expected_evidence_ids": [],
  "missing_evidence_diagnostics": [],
  "external_context_sufficiency_basis": "outside_scope_answerability_not_applicable"
}
```

Signals đầy đủ đã cung cấp cho gate:

```json
{
  "schema_version": "graphrag-gate-signals/v1",
  "corpus_id": "retrieval-corpus--631ff39273344120e671693f867fbb47057f029d5de0c982d90c7b27e508d7b9",
  "graph_id": "knowledge-graph--45c9e1a1369012689417635f46b00e25ea0b5be2d39a6cf9375428d302ce27ea",
  "scenario_id": "mshta-powershell",
  "source_ground_truth": {
    "path": "outputs/ground_truth/mshta-powershell/scenario_ground_truth.json",
    "schema_version": "scenario-ground-truth/v1",
    "sha256": "b2e3aa48c2c20e6a49479e765db0a1d660121fdb70472ca36f308b1094ddbc41",
    "scenario_id": "mshta-powershell"
  },
  "query": {
    "text": "Mã hóa ransomware xử lý các khóa mật mã như thế nào?",
    "normalized_terms": [
      "mã",
      "hóa",
      "ransomware",
      "xử",
      "lý",
      "các",
      "khóa",
      "mật",
      "như",
      "thế",
      "nào"
    ],
    "top_k": 5,
    "candidate_k": 20,
    "filters": {
      "chunk_types": null,
      "required_dimensions": null
    }
  },
  "topical_relevance": {
    "retrieval_hit_count": 5,
    "lexical_hit_count": 0,
    "vector_hit_count": 5,
    "joint_lexical_vector_hit_count": 0,
    "returned_top_rrf_score": 0.016393442623,
    "returned_top_bm25_score": null,
    "returned_top_cosine_score": 0.7825986,
    "query_token_count": 11,
    "matched_query_token_count": 0,
    "query_token_coverage": 0.0
  },
  "evidence_answerability": {
    "chunk_type_counts": {
      "scenario_summary": 0,
      "entity": 1,
      "fact": 0,
      "relationship": 2,
      "evidence": 2,
      "sigma_finding": 0,
      "mitre_assessment": 0,
      "limitation": 0
    },
    "status_counts": {
      "candidate": 0,
      "inferred": 0,
      "observed": 5,
      "reviewable": 0
    },
    "hits_with_evidence_ids": 5,
    "hits_with_source_references": 5,
    "unique_source_reference_count": 4,
    "mapped_hit_count": 5,
    "seed_node_count": 5,
    "traversal_performed": true,
    "traversal_node_count": 12,
    "traversal_edge_count": 21,
    "traversal_path_count": 52,
    "traversed_evidence_node_count": 2,
    "traversed_limitation_node_count": 0,
    "support_edge_count": 15
  },
  "warnings": [
    "lexical: No eligible chunks matched the normalized lexical query terms."
  ],
  "metadata": {
    "decision_made": false,
    "score_interpretations": {
      "rrf": "reciprocal_rank_fusion_not_probability",
      "bm25": "bm25_relevance_not_probability",
      "cosine": "cosine_similarity_not_probability"
    },
    "topical_signal_count": 10,
    "answerability_signal_count": 14
  }
}
```
