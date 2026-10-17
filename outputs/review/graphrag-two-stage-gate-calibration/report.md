# GRAPHRAG-2D3 — calibration gate hai tầng

Đã hoàn thành calibration chẩn đoán trên 32 cases development với 17 candidate policies. Policy không abstain toàn bộ được chọn để review là `two-stage-dev-5a4b308b106699e0`; **chưa đạt tiêu chí calibration và không đủ điều kiện production/held-out validation**. Dataset confusion matrix là TP=5, TN=15, FP=1, FN=11. False proceed ngoài phạm vi 0/8 = 0.000000 (0.00%); thiếu bằng chứng 1/8 = 0.125000 (12.50%). Coverage 6/32 = 0.187500 (18.75%); tỷ lệ sai trong các case được proceed 1/6 = 0.166667 (16.67%).

Hai giới hạn quyết định: frozen corpus/graph còn diễn đạt cũ rằng PowerShell đã chạy Get-Service thay vì chỉ được khởi chạy với command đó, và chưa có bộ held-out độc lập hợp lệ. Giữ nguyên các consumer theo phạm vi được giao; kết quả dưới đây chỉ là development diagnostics, không được dùng để công bố policy đạt yêu cầu.

## Nhãn, approval và ranh giới dữ liệu

Ground Truth v2, reference answers v2 và manifest v2 ghi nhận approval của `Nguyen Hong Phong`; thời điểm ghi nhận xác nhận từ clock preflight là `2026-10-15T23:36:13+07:00`. Đây không phải suy đoán timestamp của lần duyệt trước đó. `confirmed` chỉ xác nhận human review của tài liệu. Các MITRE mappings vẫn `candidate`/`needs_review`; không chuyển trạng thái approval thành gate signal, decision label hoặc kết luận an ninh. Nội dung đáp án có các câu pending-review lịch sử được bảo toàn; metadata v2 xác định approval hiện tại.

Positive class là `proceed`, negative class là `abstain`. Dataset answerability hỏi dữ liệu có đủ căn cứ cho yêu cầu hay không; context answerability hỏi **những nội dung retrieval/traversal thực sự trả về** có đủ căn cứ hay không. Với câu thiếu bằng chứng, abstain áp dụng cho chi tiết/khẳng định được yêu cầu; giải thích ngắn về giới hạn vẫn có thể trả lời được.

Chỉ query hiện tại được tính query embedding và truy xuất bằng local model đã pin. Không đưa bộ câu hỏi, reference answers, expected labels/decisions hoặc expected evidence vào query embedding, corpus, graph hay runtime signals. Expected evidence chỉ dùng đối chiếu ngoài gate; không dereference raw refs để bù context. Audit cấu trúc và full-string trên toàn corpus/graph không thấy evaluation fields, case IDs, toàn câu hỏi hay toàn đáp án. Đây không phải khẳng định đã phát hiện mọi semantic leakage; dữ kiện log trùng với câu trả lời là evidence được phép.

## Lịch sử và chia tập

Cả 32 IDs đã dùng trong embedding comparison/model selection, hai legacy calibration runs (672 policies mỗi run) và phân tích lỗi/review. Hai sửa wording không xóa lịch sử sử dụng. Tất cả được giữ ở calibration theo [split_manifest.json](split_manifest.json), không chia lại để gọi một phần là held-out độc lập. Semantic groups giữ các câu cùng ý nghĩa/bằng chứng trong cùng partition.

Lịch sử có provenance:

```json
[
  {
    "path": "outputs/evaluation/mshta-powershell/embedding_retrieval_comparison.json",
    "sha256": "687e304ed164dd03a72a0ded81a712d7fc6940f81af2e28a1a2c1ba2c1f3cc32",
    "purpose": "embedding_comparison_for_model_selection",
    "case_count": 32,
    "candidate_count": 2,
    "dataset": {
      "dataset_id": "mshta-relevance-calibration-v1",
      "path": "benchmarks/graphrag/mshta_relevance_calibration.json",
      "scenario_id": "mshta-powershell",
      "schema_version": "graphrag-relevance-calibration-dataset/v1",
      "sha256": "6764dda887c216a8c9fd83590391f2f9079a8fc0f5e0f74959e63e95654f62a4"
    },
    "followed_by": "outputs/evaluation/mshta-powershell/embedding_model_selection.json",
    "selection_decision": "provisional_recommendation",
    "recommended_candidate_id": "multilingual-e5-small"
  },
  {
    "path": "outputs/evaluation/mshta-powershell/graphrag_relevance_calibration.json",
    "sha256": "7806c75c5b20625f6c00fc83936c8e339f9e88433b4a73cca780a996a7d59694",
    "purpose": "legacy_relevance_policy_calibration",
    "case_count": 32,
    "candidate_count": 672,
    "selection_status": "no_eligible_policy",
    "source_dataset": {
      "dataset_id": "mshta-relevance-calibration-v1",
      "path": "benchmarks/graphrag/mshta_relevance_calibration.json",
      "scenario_id": "mshta-powershell",
      "schema_version": "graphrag-relevance-calibration-dataset/v1",
      "sha256": "6764dda887c216a8c9fd83590391f2f9079a8fc0f5e0f74959e63e95654f62a4"
    },
    "all_current_case_ids_used": true
  },
  {
    "path": "outputs/evaluation/mshta-powershell/graphrag_relevance_calibration_e5.json",
    "sha256": "d4427a47676884b9996c353be26318e1b665bb714056f55e811c852835d7efcb",
    "purpose": "legacy_relevance_policy_calibration",
    "case_count": 32,
    "candidate_count": 672,
    "selection_status": "no_eligible_policy",
    "source_dataset": {
      "dataset_id": "mshta-relevance-calibration-v1",
      "path": "benchmarks/graphrag/mshta_relevance_calibration.json",
      "scenario_id": "mshta-powershell",
      "schema_version": "graphrag-relevance-calibration-dataset/v1",
      "sha256": "6764dda887c216a8c9fd83590391f2f9079a8fc0f5e0f74959e63e95654f62a4"
    },
    "all_current_case_ids_used": true
  }
]
```

## Policy và cách chọn

Quy tắc được lưu trước search trong [selection_plan.json](selection_plan.json): ưu tiên ít false proceed ở unrelated và insufficient_evidence; nếu bằng nhau giữ nhiều context-sufficient positives hơn; tiếp đó ít enabled conditions hơn; cuối cùng `policy_id`. Candidate abstain toàn bộ bị loại khỏi selection. Chỉ hiệu chỉnh ba điều kiện từ signals thực tế, không vét cạn 20 fields hoặc hardcode query/case/keyword/answer vào evaluator.

Các grid số thực tế (không dùng nhãn để dựng ngưỡng; cosine: tắt hoặc empirical Q25/Q50/Q75; coverage: 0 hoặc median; source-reference hits: 0 hoặc 1):

```json
{
  "min_returned_top_cosine_score": [
    null,
    0.78163017,
    0.8121783,
    0.84299805
  ],
  "min_query_token_coverage": [
    0,
    0.18181818
  ],
  "min_hits_with_source_references": [
    0,
    1
  ]
}
```

Có 16 candidates không abstain toàn bộ và 1 negative control. Control có ngưỡng cosine cao hơn max observed nên coverage=0; selective error có mẫu số 0 là N/A, không được coi là thành công. Selection rank của policy chọn là `[1, -5, 6, 'two-stage-dev-5a4b308b106699e0']` = `[false_proceed_count, -retained_context_sufficient_positives, enabled_condition_count, policy_id]`; enabled conditions=6.

Policy chọn giữ đủ **8 topical conditions + 12 answerability conditions**, không có hidden defaults; giá trị 0/null biểu diễn điều kiện không ràng buộc theo contract:

```json
{
  "schema_version": "graphrag-two-stage-gate-policy/v1",
  "policy_id": "two-stage-dev-5a4b308b106699e0",
  "topical_relevance": {
    "min_retrieval_hit_count": 1,
    "min_lexical_hit_count": 0,
    "min_vector_hit_count": 0,
    "min_joint_lexical_vector_hit_count": 0,
    "min_query_token_coverage": 0.18181818,
    "min_returned_top_rrf_score": null,
    "min_returned_top_bm25_score": null,
    "min_returned_top_cosine_score": 0.84299805
  },
  "evidence_answerability": {
    "min_hits_with_evidence_ids": 0,
    "min_hits_with_source_references": 0,
    "min_unique_source_reference_count": 0,
    "min_mapped_hit_count": 1,
    "min_seed_node_count": 1,
    "require_traversal": true,
    "min_traversal_node_count": 0,
    "min_traversal_edge_count": 0,
    "min_traversal_path_count": 0,
    "min_traversed_evidence_node_count": 0,
    "min_support_edge_count": 0,
    "max_traversed_limitation_node_count": null
  }
}
```

Lý do tắt các điều kiện còn lại:

| Nhóm điều kiện | Lý do |
| --- | --- |
| other_topical_counts | Counts largely saturate under fixed top5; no justified extra search dimension. |
| rrf_bm25_thresholds | RRF is rank fusion and BM25 language dependent; no additional scale tuning on 32 exposed cases. |
| other_evidence_and_traversal_minima | Graph density/counts do not prove query-specific evidence sufficiency. |
| max_traversed_limitation_node_count | Limitations are necessary context; their presence must not be penalized. |

Count hits/seeds/traversal chỉ chứng minh có cấu trúc truy xuất, không chứng minh đủ nội dung để trả lời query. Vì vậy không đặt thêm các ngưỡng mật độ graph tùy tiện. Limitation nodes có thể là context cần thiết; không phạt sự hiện diện của chúng.

Kết quả của toàn candidate set:

| Policy | Cosine min | Coverage min | Refs hits min | TP/TN/FP/FN | FP unrelated | FP insufficient | Context-good retained | Coverage | Complexity | Selection rank |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| negative-control-all-abstain | 0.9129396200000001 | 0 | 0 | 0/16/0/16 | 0/8 = 0.000000 (0.00%) | 0/8 = 0.000000 (0.00%) | 0 | 0/32 = 0.000000 (0.00%) | 5 | excluded all-abstain |
| two-stage-dev-5a4b308b106699e0 | 0.84299805 | 0.18181818 | 0 | 5/15/1/11 | 0/8 = 0.000000 (0.00%) | 1/8 = 0.125000 (12.50%) | 5 | 6/32 = 0.187500 (18.75%) | 6 | [1, -5, 6, "two-stage-dev-5a4b308b106699e0"] |
| two-stage-dev-86a1f8c641bf2e4f | 0.84299805 | 0.18181818 | 1 | 5/15/1/11 | 0/8 = 0.000000 (0.00%) | 1/8 = 0.125000 (12.50%) | 5 | 6/32 = 0.187500 (18.75%) | 7 | [1, -5, 7, "two-stage-dev-86a1f8c641bf2e4f"] |
| two-stage-dev-08d961a79ba1c6c8 | 0.84299805 | 0 | 0 | 6/13/3/10 | 0/8 = 0.000000 (0.00%) | 3/8 = 0.375000 (37.50%) | 6 | 9/32 = 0.281250 (28.12%) | 5 | [3, -6, 5, "two-stage-dev-08d961a79ba1c6c8"] |
| two-stage-dev-d1b01f874de5c4ff | 0.84299805 | 0 | 1 | 6/13/3/10 | 0/8 = 0.000000 (0.00%) | 3/8 = 0.375000 (37.50%) | 6 | 9/32 = 0.281250 (28.12%) | 6 | [3, -6, 6, "two-stage-dev-d1b01f874de5c4ff"] |
| two-stage-dev-59b5468d488ecd0d | 0.8121783 | 0.18181818 | 0 | 6/12/4/10 | 0/8 = 0.000000 (0.00%) | 4/8 = 0.500000 (50.00%) | 6 | 10/32 = 0.312500 (31.25%) | 6 | [4, -6, 6, "two-stage-dev-59b5468d488ecd0d"] |
| two-stage-dev-b34d1302e3d77f1a | 0.8121783 | 0.18181818 | 1 | 6/12/4/10 | 0/8 = 0.000000 (0.00%) | 4/8 = 0.500000 (50.00%) | 6 | 10/32 = 0.312500 (31.25%) | 7 | [4, -6, 7, "two-stage-dev-b34d1302e3d77f1a"] |
| two-stage-dev-0ed2520e729f326f | 0.78163017 | 0.18181818 | 0 | 8/10/6/8 | 0/8 = 0.000000 (0.00%) | 6/8 = 0.750000 (75.00%) | 8 | 14/32 = 0.437500 (43.75%) | 6 | [6, -8, 6, "two-stage-dev-0ed2520e729f326f"] |
| two-stage-dev-f11ab8fb0344bcfb | 0.78163017 | 0.18181818 | 1 | 8/10/6/8 | 0/8 = 0.000000 (0.00%) | 6/8 = 0.750000 (75.00%) | 8 | 14/32 = 0.437500 (43.75%) | 7 | [6, -8, 7, "two-stage-dev-f11ab8fb0344bcfb"] |
| two-stage-dev-39ad9a0d66a6640e | 0.8121783 | 0 | 0 | 9/8/8/7 | 2/8 = 0.250000 (25.00%) | 6/8 = 0.750000 (75.00%) | 8 | 17/32 = 0.531250 (53.12%) | 5 | [8, -8, 5, "two-stage-dev-39ad9a0d66a6640e"] |
| two-stage-dev-975087cab6130cf9 | null | 0.18181818 | 0 | 9/8/8/7 | 2/8 = 0.250000 (25.00%) | 6/8 = 0.750000 (75.00%) | 8 | 17/32 = 0.531250 (53.12%) | 5 | [8, -8, 5, "two-stage-dev-975087cab6130cf9"] |
| two-stage-dev-6d40eca17ba546f7 | 0.8121783 | 0 | 1 | 9/8/8/7 | 2/8 = 0.250000 (25.00%) | 6/8 = 0.750000 (75.00%) | 8 | 17/32 = 0.531250 (53.12%) | 6 | [8, -8, 6, "two-stage-dev-6d40eca17ba546f7"] |
| two-stage-dev-95170eb3d6a0af80 | null | 0.18181818 | 1 | 9/8/8/7 | 2/8 = 0.250000 (25.00%) | 6/8 = 0.750000 (75.00%) | 8 | 17/32 = 0.531250 (53.12%) | 6 | [8, -8, 6, "two-stage-dev-95170eb3d6a0af80"] |
| two-stage-dev-d326c9918a217191 | 0.78163017 | 0 | 0 | 14/5/11/2 | 3/8 = 0.375000 (37.50%) | 8/8 = 1.000000 (100.00%) | 13 | 25/32 = 0.781250 (78.12%) | 5 | [11, -13, 5, "two-stage-dev-d326c9918a217191"] |
| two-stage-dev-6d32785ac1e5814b | 0.78163017 | 0 | 1 | 14/5/11/2 | 3/8 = 0.375000 (37.50%) | 8/8 = 1.000000 (100.00%) | 13 | 25/32 = 0.781250 (78.12%) | 6 | [11, -13, 6, "two-stage-dev-6d32785ac1e5814b"] |
| two-stage-dev-ecbf583da8ad2782 | null | 0 | 0 | 16/0/16/0 | 8/8 = 1.000000 (100.00%) | 8/8 = 1.000000 (100.00%) | 13 | 32/32 = 1.000000 (100.00%) | 4 | [16, -13, 4, "two-stage-dev-ecbf583da8ad2782"] |
| two-stage-dev-70c82ea7d6641496 | null | 0 | 1 | 16/0/16/0 | 8/8 = 1.000000 (100.00%) | 8/8 = 1.000000 (100.00%) | 13 | 32/32 = 1.000000 (100.00%) | 5 | [16, -13, 5, "two-stage-dev-70c82ea7d6641496"] |

Tiêu chí chấp nhận và trạng thái thực tế:

```json
{
  "acceptance_criteria": {
    "max_false_proceed_unrelated": 0,
    "max_false_proceed_insufficient_evidence": 0,
    "min_retained_context_sufficient_positives": 1,
    "allow_all_abstain_success": false,
    "require_consumer_evidence_consistency": true,
    "require_approved_independent_evaluation": true
  },
  "selection_status": "selected_calibration_candidate",
  "meets_calibration_error_constraints": false,
  "calibration_acceptance_failures": [
    "False proceed remains: insufficient_evidence"
  ],
  "policy_qualified": false
}
```

## Metrics của policy chọn

| Dataset expected \ Actual | proceed | abstain | Tổng |
| --- | --- | --- | --- |
| proceed | 5 | 11 | 16 |
| abstain | 1 | 15 | 16 |

| Dataset metric | Tử số/mẫu số và giá trị |
| --- | --- |
| accuracy | 20/32 = 0.625000 (62.50%) |
| precision | 5/6 = 0.833333 (83.33%) |
| recall | 5/16 = 0.312500 (31.25%) |
| specificity | 15/16 = 0.937500 (93.75%) |
| f1 | 10/22 = 0.454545 (45.45%) |

| Diagnostic | Tử số/mẫu số và giá trị |
| --- | --- |
| False proceed ngoài phạm vi | 0/8 = 0.000000 (0.00%) |
| False proceed thiếu bằng chứng | 1/8 = 0.125000 (12.50%) |
| Coverage = proceed / tất cả cases | 6/32 = 0.187500 (18.75%) |
| Sai trong proceed (theo dataset label) | 1/6 = 0.166667 (16.67%) |
| False abstain khi actual context đủ | 8/13 = 0.615385 (61.54%) |
| Sai trong proceed (theo context eligibility) | 1/6 = 0.166667 (16.67%) |

False proceed còn lại: `ie-en-payload-download-url`. Với policy chọn, nhóm được proceed gồm 5 positive có actual context đủ và 1 câu thiếu bằng chứng. Gate hiện tại chưa phân biệt được yêu cầu URL tải payload với context process creation cùng chủ đề chỉ qua các aggregate signals.

Phân bố ngôn ngữ được join từ approved reference cases **ngoài gate**, không sửa threshold hoặc runtime signals:

| Language | Cases | Proceed | Coverage | False proceed count | False abstain / context-good |
| --- | --- | --- | --- | --- | --- |
| en | 16 | 6 | 6/16 | 1 | 3/8 |
| vi | 16 | 0 | 0/16 | 0 | 5/5 |

Cả 6 cases được proceed đều tiếng Anh; tiếng Việt có coverage 0/16. Đây là hạn chế rõ của candidate hiện tại trên lát cắt song ngữ. Corpus chủ yếu tiếng Anh và lexical query-token coverage có thể làm bất lợi câu tiếng Việt; E5 multilingual không tự khắc phục một topical policy kết hợp lexical coverage. Đây là diagnostic/rủi ro cần kiểm chứng, không phải kết luận nhân quả hoặc lý do tuning tiếp sau khi xem slice. Không chọn ngưỡng riêng theo language.

Có 3 positive theo dataset nhưng context chưa đủ: `rd-vi-reviewed-scope-limitations, rp-vi-final-review-limits, rp-vi-service-action`. Các trường command line gốc và scope limits mở rộng chưa được consumer trả về; không lấy expected evidence để sửa đầu vào. Abstain ở ba case này được ghi là retrieval/context failure, không mặc định là gate false abstain. Theo external rubric còn 13 cases context đủ; gate giữ 5 và abstain 8, tức 8/13 = 0.615385 (61.54%).

| Context eligibility expected \ Actual | proceed | abstain |
| --- | --- | --- |
| eligible | 5 | 8 |
| ineligible | 1 | 18 |

| Context eligibility metric | Tử số/mẫu số và giá trị |
| --- | --- |
| accuracy | 23/32 = 0.718750 (71.88%) |
| precision | 5/6 = 0.833333 (83.33%) |
| recall | 5/13 = 0.384615 (38.46%) |
| specificity | 18/19 = 0.947368 (94.74%) |
| f1 | 10/19 = 0.526316 (52.63%) |

Topical label positive có 24 cases (16 có đáp án + 8 thiếu bằng chứng vẫn cùng chủ đề), negative có 8 unrelated. Không suy mọi abstain là ngoài phạm vi. Answerability có 24 nhãn áp dụng; 8 unrelated để unknown/not-applicable cho tầng này. End-to-end context eligibility vẫn phân loại unrelated là ineligible theo topical scope, không biến chúng thành nhãn answerability false.

### topical_relevance

| Số lượng | Giá trị |
| --- | --- |
| case_count | 32 |
| known_label_count | 32 |
| unknown_label_count | 0 |
| evaluated_known_label_count | 32 |
| not_evaluated_count | 0 |
| known_label_not_evaluated_count | 0 |

Confusion matrix chỉ trên các case có nhãn áp dụng và tầng thực sự được đánh giá:

```json
{
  "tp": 6,
  "tn": 8,
  "fp": 0,
  "fn": 18
}
```

| Metric | Tử số/mẫu số và giá trị |
| --- | --- |
| accuracy | 14/32 = 0.437500 (43.75%) |
| precision | 6/6 = 1.000000 (100.00%) |
| recall | 6/24 = 0.250000 (25.00%) |
| specificity | 8/8 = 1.000000 (100.00%) |
| f1 | 12/30 = 0.400000 (40.00%) |

### evidence_answerability

| Số lượng | Giá trị |
| --- | --- |
| case_count | 32 |
| known_label_count | 24 |
| unknown_label_count | 8 |
| evaluated_known_label_count | 6 |
| not_evaluated_count | 26 |
| known_label_not_evaluated_count | 18 |

Confusion matrix chỉ trên các case có nhãn áp dụng và tầng thực sự được đánh giá:

```json
{
  "tp": 5,
  "tn": 0,
  "fp": 1,
  "fn": 0
}
```

| Metric | Tử số/mẫu số và giá trị |
| --- | --- |
| accuracy | 5/6 = 0.833333 (83.33%) |
| precision | 5/6 = 0.833333 (83.33%) |
| recall | 5/5 = 1.000000 (100.00%) |
| specificity | 0/1 = 0.000000 (0.00%) |
| f1 | 10/11 = 0.909091 (90.91%) |

Answerability `not_evaluated` ở 26/32 cases vì topical gate đã dừng; 18 trong số này có nhãn answerability áp dụng và 8 unrelated không có nhãn tầng này. Metrics answerability tính trên đúng 6 evaluated-known cases, không lấy 32 làm mẫu số và không coi 26 cases chưa đánh giá là pass. Recall answerability có thể 5/5 trong slice đã qua topical, nhưng không thể diễn giải thành recall end-to-end tốt. Mọi metric có mẫu số 0 được ghi N/A; JSON lưu value=null.

## External rubric và sửa lỗi đánh giá

Đánh giá context là conservative AI support rubric ngoài runtime, liên kết đúng object/role và nội dung thực tế. Có evidence ID, raw ref hoặc JSON pointer không chứng minh nội dung cần thiết đã được trả về. Rubric này không thay thế semantic human review hoặc tạo human labels mới.

Một review ngữ nghĩa phát hiện rubric ban đầu yêu cầu quá mức ở `rp-en-technique-review`: assessment trực tiếp đã đủ giải thích trạng thái technique, không cần thêm scenario analysis_status và limitation chung. Đã sửa yêu cầu ngoài gate rồi tính lại adjudication/metrics bằng saved contexts/signals. Approved labels, queries, gate inputs, threshold grids, selected policy và retrieval không đổi; đây là sửa metric rubric, không tuning gate theo kết quả. False abstain context-good cuối là 8/13.

```json
[
  {
    "revision_id": "technique-review-minimal-support-correction-1",
    "previous_audit_sha256": "33662857c8178eb8c204df338b63d32fda9c1663c3eda0cd16262fd56e4ce1c7",
    "affected_case_id": "rp-en-technique-review",
    "previous_minimal_answer_unit_ids": [
      "proxy_assessment",
      "analysis_status",
      "limitation_3"
    ],
    "minimal_answer_unit_ids": [
      "proxy_assessment"
    ],
    "incidental_answer_unit_ids": [
      "analysis_status",
      "limitation_3"
    ],
    "reason": "Read-only semantic review found the external rubric overconstrained the question by requiring scenario-level analysis status and a separate general review limitation. Direct technique assessment fields suffice. This corrects evaluation support requirements, not approved labels or runtime policy.",
    "decision_basis": "Approved question/reference answer and actual returned proxy assessment, independent of policy thresholds or gate decision.",
    "approved_artifacts_changed": false,
    "gate_inputs_changed": false,
    "thresholds_changed": false,
    "replay_required": "Recompute external adjudication and metrics from saved contexts/signals; no retrieval, embedding or threshold change.",
    "remaining_known_context_failures": [
      "rd-vi-reviewed-scope-limitations",
      "rp-vi-final-review-limits",
      "rp-vi-service-action"
    ]
  }
]
```

## Retrieval và provenance đã cố định

Model local `intfloat/multilingual-e5-small`, revision `614241f622f53c4eeff9890bdc4f31cfecc418b3`, dimension=384, cosine với L2 normalization; document prefix `passage: `, query prefix `query: `. Dùng lại provisional E5 recommendation; không chọn hoặc tải model mới. Chỉ chạy query embeddings trong CPU/offline runtime đã lưu.

Cấu hình thực tế được giữ nguyên cho mọi candidate:

```json
{
  "retrieval": {
    "top_k": 5,
    "candidate_k": 20,
    "chunk_types": null,
    "required_dimensions": null
  },
  "fusion": {
    "method": "reciprocal_rank_fusion",
    "rrf_k": 60
  },
  "seed_mapping": "Existing exact ID/JSON-pointer mapping, unchanged",
  "traversal": {
    "direction": "both",
    "max_depth": 2,
    "allowed_edge_types": null,
    "max_nodes": 100,
    "max_edges": 200
  },
  "context_budget": {
    "retrieval_hits": 5,
    "traversal_nodes": 100,
    "traversal_edges": 200,
    "additional_token_truncation": null
  },
  "runtime": {
    "device": "cpu",
    "offline": true,
    "batch_size": 1,
    "show_progress_bar": false
  },
  "query_input_boundary": "Only the current query text is embedded/retrieved; never the question collection, answers, categories, decisions or expected evidence."
}
```

Nguồn dữ liệu cùng SHA-256 (evaluation GT v2 được tách khỏi consumer GT v1):

| Vai trò | Đường dẫn | SHA-256 |
| --- | --- | --- |
| ground_truth | [outputs/review/mshta-ground-truth/scenario_ground_truth.json](../../../outputs/review/mshta-ground-truth/scenario_ground_truth.json) | 8676d7a1df41058e7f4b1460a0d4bf909fca5d8f20992753e63be7d024268461 |
| answers | [outputs/review/mshta-ground-truth/reference_answers.json](../../../outputs/review/mshta-ground-truth/reference_answers.json) | 400026d106b863c4127c57c74d3b7722e672652474638bb9554089d322fba96b |
| manifest | [outputs/review/mshta-ground-truth/review_manifest.json](../../../outputs/review/mshta-ground-truth/review_manifest.json) | 29507fe4f68a1222d93d5626da8d03f29b497d5798be3f2f6786f8911d0eedb4 |
| dataset | [outputs/review/mshta-ground-truth/mshta_relevance_calibration_reviewed.json](../../../outputs/review/mshta-ground-truth/mshta_relevance_calibration_reviewed.json) | a4c0d04078cc3ed74b16b041322f494bf8329820e0833550e29d40aa8187e124 |
| corpus | [outputs/retrieval/mshta-powershell/retrieval_corpus.json](../../../outputs/retrieval/mshta-powershell/retrieval_corpus.json) | 53abc9e44c03c46aaf024cdb79b61ad3381d50feb82689f27074151381b9d0f3 |
| graph | [outputs/graph/mshta-powershell/knowledge_graph.json](../../../outputs/graph/mshta-powershell/knowledge_graph.json) | 892a4c1926178c12bb3878dbd7e5d779d39494b8c11da3ac33864cbdc66c7227 |
| index | [outputs/evaluation/mshta-powershell/vector_index_multilingual_e5_small.json](../../../outputs/evaluation/mshta-powershell/vector_index_multilingual_e5_small.json) | e329f0031b64f255044d47d6162535c5bff3916369987d17e3d37e0b25023e91 |
| consumer_ground_truth | [outputs/ground_truth/mshta-powershell/scenario_ground_truth.json](../../../outputs/ground_truth/mshta-powershell/scenario_ground_truth.json) | b2e3aa48c2c20e6a49479e765db0a1d660121fdb70472ca36f308b1094ddbc41 |

Audit phát hiện các mâu thuẫn/thiếu nội dung cụ thể dưới đây. Chúng đã được báo trước policy selection; không rebuild corpus/graph/index hoặc diễn giải kết quả này thành qualified policy:

```json
[
  {
    "severity": "material_contradiction",
    "artifact": "outputs/retrieval/mshta-powershell/retrieval_corpus.json",
    "pointers": [
      "/chunks/0/content"
    ],
    "old_claims": [
      "PowerShell runs Get-Service sysmon",
      "PowerShell ran Get-Service sysmon."
    ],
    "approved_ground_truth_pointers": [
      "/scenario/description",
      "/summary/observed_behavior/2",
      "/summary/limitations/4"
    ],
    "effect": "Process creation establishes launch command, not successful cmdlet completion; this consumer cannot support a policy-qualified result."
  },
  {
    "severity": "material_contradiction",
    "artifact": "outputs/graph/mshta-powershell/knowledge_graph.json",
    "pointers": [
      "/nodes/14/attributes/description"
    ],
    "old_claims": [
      "PowerShell runs Get-Service sysmon"
    ],
    "approved_ground_truth_pointers": [
      "/scenario/description",
      "/summary/observed_behavior/2",
      "/summary/limitations/4"
    ],
    "effect": "Same stale completion wording as corpus."
  },
  {
    "severity": "missing_approved_evidence_content",
    "artifacts": [
      "outputs/retrieval/mshta-powershell/retrieval_corpus.json",
      "outputs/graph/mshta-powershell/knowledge_graph.json"
    ],
    "missing_approved_ground_truth_pointers": [
      "/facts/0/attributes/source_observations",
      "/facts/1/attributes/source_observations",
      "/summary/limitations/4",
      "/summary/limitations/5",
      "/summary/limitations/6"
    ],
    "effect": "Original CommandLine/process-role fields and expanded scope limits cannot be recovered by dereferencing provenance or adding expected evidence to gate input."
  }
]
```

Các consumer v1-only còn lại, giữ nguyên trong milestone này; evaluation loader đọc và validate GT/answers/manifest v2 riêng, không hạ artifact version:

| File | Contract hiện tại |
| --- | --- |
| [src/threat_hunting/graph/schema.py](../../../src/threat_hunting/graph/schema.py) | SOURCE_GROUND_TRUTH_SCHEMA_VERSION pinned to v1; source provenance validator also v1-only. |
| [src/threat_hunting/retrieval/schema.py](../../../src/threat_hunting/retrieval/schema.py) | SOURCE_GROUND_TRUTH_SCHEMA_VERSION pinned to v1; source provenance validator also v1-only. |
| [src/threat_hunting/graphrag/relevance.py](../../../src/threat_hunting/graphrag/relevance.py) | Shared source provenance validator accepts only v1; gate signal runtime uses it. |
| [src/threat_hunting/evaluation/calibration_schema.py](../../../src/threat_hunting/evaluation/calibration_schema.py) | Legacy calibration report provenance schema map pins GT v1. |
| [src/threat_hunting/graph/builder.py](../../../src/threat_hunting/graph/builder.py) | Builder emits default v1 source provenance; not an evaluation consumer to modify in this milestone. |
| [src/threat_hunting/retrieval/builder.py](../../../src/threat_hunting/retrieval/builder.py) | Builder emits default v1 source provenance; not an evaluation consumer to modify in this milestone. |

## Freeze, replay và held-out

Đã khóa policy, retrieval configuration, split manifest, evaluation code, criteria và saved signals bằng SHA-256. [evaluation_code_hashes.json](evaluation_code_hashes.json) ghi các source files; [policy_freeze.json](policy_freeze.json) giữ binding hashes. Freeze chuẩn bị một thử nghiệm có thể tái lập, không chứng minh đã có held-out đủ điều kiện.

```json
{
  "schema_version": "two-stage-gate-evaluation-freeze/v1",
  "bindings": {
    "policy_sha256": "6756610aacb6e6db3029bd6b458c034c56bec2d5a9e5d32a4dd058dc8c647661",
    "retrieval_configuration_sha256": "2fef5d4eb1ef2ee9a6c243468e21c83af675da525fe6c1af1670f3f7a88dfe22",
    "split_manifest_sha256": "e7e63618907803b6e15dcb9d474597885b8391681c25ffb2b724b4fba9daf75c",
    "evaluation_code_sha256": "d73ac3ff816cdb2c6da326be0f103decccd7b84c8c4b62a3dc8c20caf591e08f",
    "criteria_sha256": "b30092f9455d584191ea8cd2db5f6d5316e50228d8cb49a1aa266ba740a9ab4e",
    "calibration_signals_sha256": "56e3b9228752303c976d69917c91f91e76df201101d96bc5024df876af87f560"
  },
  "lock_sha256": "93674a4516016c20fcbbb0fbfd7f9ea9a920d3880f202af46b43a697271e8f27"
}
```

Replay status: `identical_saved_signal_replay`, independent_experiment=false, heldout_run=false. Đây là replay với cùng saved signals/configuration, không phải lần thử nghiệm độc lập mới và không điều chỉnh threshold sau replay.

```json
{
  "status": "not_run",
  "reasons": [
    "All32 prior cases exposed to development",
    "New AI-proposed stress probes lack human-approved labels and independent-core eligibility",
    "Frozen consumers contain material stale evidence contradiction"
  ],
  "labels_approved": false,
  "heldout_queries_embedded": 0,
  "heldout_gate_calls": 0
}
```

Bộ mới [proposed_test_set.json](proposed_test_set.json) có 11 AI-proposed cases: 5 đủ bằng chứng theo full raw, 3 thiếu bằng chứng và 3 unrelated. Tất cả pending_human_review, reviewer/time null; approval cũ không áp dụng. Chưa embed/query/gate các câu mới, không dùng chúng chọn ngưỡng.

Năm positive probes cần raw ngoài core (conhost, process exit, temporary deletion, background connection và log clearing), không có trong frozen corpus/graph. Không dùng abstain của chúng làm false abstain cho frozen policy. Cùng raw file đã được review và có evidence overlap nên không gọi đây là independent unseen dataset; chi tiết novelty/grouping/eligibility tại [proposed_test_notes.md](proposed_test_notes.md). Hiện vẫn chưa có positive-context held-out độc lập hợp lệ cho frozen experiment.

## Lệnh và kiểm thử thực tế

Nguồn chính xác là [test_results.json](test_results.json). Nội dung sau giữ nguyên các lệnh phase/test, counts, exit codes và failed attempts được ghi nhận; không suy số tests từ baseline hoặc ước lượng. `failed_attempts=[]` nghĩa không có lần test fail trong lượt này, không xóa lịch sử failures của prerequisite.

```json
{
  "runs": [
    {
      "name": "focused",
      "command": ".\\.venv\\Scripts\\python.exe -m pytest -q --tb=short -p no:cacheprovider --basetemp=\"$env:TEMP/rag-two-stage-focused-20261016\" tests/test_two_stage_calibration.py tests/test_two_stage_review.py tests/test_calibrate_two_stage_gate_cli.py tests/test_review_package.py",
      "passed": 124,
      "failed": 0,
      "errors": 0,
      "skipped": 0,
      "seconds": 0.7,
      "exit_code": 0
    },
    {
      "name": "regression",
      "command": ".\\.venv\\Scripts\\python.exe -m pytest -q --tb=short -p no:cacheprovider --basetemp=\"$env:TEMP/rag-two-stage-regression-20261016\" tests/test_two_stage_calibration.py tests/test_two_stage_review.py tests/test_calibrate_two_stage_gate_cli.py tests/test_review_package.py tests/test_graphrag_gate_signals.py tests/test_graphrag_two_stage_gate.py tests/test_graphrag_orchestrator.py tests/test_graphrag_seed_mapping.py tests/test_relevance_calibration.py tests/test_relevance_calibration_dataset.py tests/test_retrieval_schema.py tests/test_vector_retriever.py tests/test_embedding_backend.py",
      "passed": 1289,
      "failed": 0,
      "errors": 0,
      "skipped": 0,
      "seconds": 5.95,
      "exit_code": 0
    },
    {
      "name": "full_suite",
      "command": ".\\.venv\\Scripts\\python.exe -m pytest -q --tb=short -p no:cacheprovider --basetemp=\"$env:TEMP/rag-two-stage-full-20261016\"",
      "passed": 5815,
      "subtests_passed": 6,
      "failed": 0,
      "errors": 0,
      "skipped": 0,
      "seconds": 122.55,
      "exit_code": 0
    }
  ],
  "phase_commands": [
    ".\\.venv\\Scripts\\python.exe -X utf8 scripts/calibrate_two_stage_gate.py --phase prepare",
    ".\\.venv\\Scripts\\python.exe -X utf8 scripts/calibrate_two_stage_gate.py --phase collect",
    ".\\.venv\\Scripts\\python.exe -X utf8 scripts/calibrate_two_stage_gate.py --phase calibrate",
    ".\\.venv\\Scripts\\python.exe -X utf8 scripts/calibrate_two_stage_gate.py --phase freeze-replay"
  ],
  "failed_attempts": [],
  "extra_focused_verification": [
    {
      "file": "tests/test_two_stage_calibration.py",
      "passed": 45,
      "seconds": 0.2
    },
    {
      "file": "tests/test_two_stage_review.py",
      "passed": 25,
      "seconds": 0.26
    },
    {
      "file": "tests/test_review_package.py",
      "passed": 51,
      "seconds": 0.58
    }
  ],
  "notes": [
    "All pytest executions use system temp outside repository and approved escalation due previously verified Windows sandbox temp restrictions.",
    "No rerun of full prerequisite suite before implementation; final full suite is this task final required verification.",
    "One external rubric correction recalculated diagnostics on identical saved contexts/signals; thresholds never changed."
  ]
}
```

## Baseline, giới hạn và bước tiếp theo

Preflight branch `feature/mshta-evidence-extractor`, HEAD `af2243a3ee89c5e5721ec341eea0a8cb06814f41`; staging tại preflight `empty`. Working tree có bốn Markdown và source/tests prerequisite từ trước; không reset, stage, commit hoặc ghi đè các phần đó. Danh sách hashes trước nằm ở [preflight.json](preflight.json); kết quả hashes trước/sau, Git state cuối và ZIP payload verification được ghi trong review_inventory.json của package.

Chưa sửa production CLI, chưa gọi LLM/UI, chưa mở held-out, chưa đổi raw/approved Ground Truth/corpus/graph/index/retrieval outputs. `proceed` chỉ là context eligibility; không xác nhận attack, download, C2, cmdlet completion, service state hoặc technique.

Milestone hiện đạt candidate-policy calibration và review package, chưa đạt verified policy. Bước tiếp theo cần review các diagnostics và nhãn/scope của bộ đề xuất; xác định một tập kiểm tra mới có context bằng chứng phù hợp và độc lập thực chất. Mâu thuẫn consumer cần một thay đổi phạm vi/rebuild được cho phép ở bước riêng trước khi dùng chúng chứng minh chất lượng. Không mặc định approval nhãn mới cho phép thay corpus hoặc chuyển sang CLI/LLM/UI.

Chi tiết đầy đủ từng query, expected/actual decision, stages, reason codes, signals và evidence diagnostics: [per_case_report.md](per_case_report.md).

Hashes của các artifact review trọng yếu lúc render:

| Artifact | SHA-256 |
| --- | --- |
| [calibration_results.json](calibration_results.json) | 4dd266846fd71154f1f1d4d7ebefd5df4f701158e4f3ab6fddf6a416ffb18b2b |
| [external_context_adjudication.json](external_context_adjudication.json) | e3554a91690c15df530fba344564da7eae7e12ffa626556368162b749508dfb9 |
| [consumer_audit.json](consumer_audit.json) | 23a884033a7f3362210c78b870ff24c842fffee5965baa9e3ff6a4075265098b |
| [selected_policy.json](selected_policy.json) | b132df134abbffa8a9ebd2afbb742befc239d4111f63a024b5386fe09d5d447c |
| [candidate_policies.json](candidate_policies.json) | 04bee3a7a15c528702134ebcc6bc142f76d9d088bbe776af870b13903feec515 |
| [selection_plan.json](selection_plan.json) | 60905314a3e068b4a31b6b22b9e5944ac282657680128a77b3960998fe5c2be5 |
| [split_manifest.json](split_manifest.json) | 3f7a2247dc4f5e04dcb18ae4a99e95013a04668162fe081e03cb0fc5c28d8203 |
| [signals.json](signals.json) | 324d89f42381680a2a5878e0617afc64b6ae2874e63a854510c77cdf5fb58ad8 |
| [frozen_retrieval_configuration.json](frozen_retrieval_configuration.json) | dc3e32912f42b6b7703b859502e9fe37fc43e150d8632617e84770320283aa69 |
| [policy_freeze.json](policy_freeze.json) | 68b08c12788766582726bd8340f5cb68e17aacb43b5b21a0584b2d9c8c48d801 |
| [replay_result.json](replay_result.json) | acd4ccdb3b774507b6e7f4758d05ee7f32162e63ab993edfeb9d87e536c82248 |
| [proposed_test_set.json](proposed_test_set.json) | 5da7b7e221e16eddf77475ef1e7403fb358641527237621867d887ec6b976814 |
| [test_results.json](test_results.json) | 18cb88167ab783f3460098f9dc31caf1a806ca047417cf31190f68965842a966 |
