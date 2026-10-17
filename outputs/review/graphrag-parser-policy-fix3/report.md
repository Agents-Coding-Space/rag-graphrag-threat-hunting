# GRAPHRAG-2D3-FIX3 — Kết quả development

Ngày review: 17/10/2026. Branch `feature/mshta-evidence-extractor`; HEAD `af2243a3ee89c5e5721ec341eea0a8cb06814f41`; staging rỗng. Đây là thí nghiệm development trên cùng 32 queries đã exposed, không phải independent validation.

E4 đạt **9/16/0/7 TP/TN/FP/FN**, tăng 7 true positives so với E0 (4 câu VI), giữ cả 2 true positives E0. Coverage 9/32, recall 9/16; còn 7 false abstains và 21 support unknown. Không có false proceed theo approved labels trên tập này. Những con số này chưa đủ để chốt cấu hình production hay tuyên bố đã kiểm chứng riêng.

## Bảo toàn và phạm vi thay đổi

Đã đọc brief, tiến độ và FIX2; xác minh baseline thực tế rồi snapshot 5.528 hashes trước khi sửa. Human approval có sẵn trong approved bundle được giữ nguyên; các dòng pending review lịch sử trong AGENTS/PROJECT_CONTEXT không được hiểu là thu hồi approval. Chỉ thêm 4 modules phiên bản mới, 1 research runner và 5 test files; `PROJECT_PROGRESS.md` chỉ nối thêm. Không sửa bất kỳ source/tests/fixtures cũ, raw data, nhãn/câu hỏi/đáp án/provenance, FIX1 corpus/graph/index, FIX2 artifacts/policies hoặc ZIP cũ.

| File mới | Trách nhiệm |
| --- | --- |
| `src/threat_hunting/graphrag/query_requirements_v2.py` | Clause/request/background, process roles, source spans EN/VI; schema query-requirements/v2 |
| `src/threat_hunting/graphrag/query_context_v2.py` | Inventory exact source identities, coverage raw creation facts, supplementation bounded; context/v2 |
| `src/threat_hunting/graphrag/query_support_v2.py` | Instance-bound chain, source-boundary completeness, exact limitation sets, contradiction guards; support/v2 |
| `src/threat_hunting/graphrag/query_policy.py` | Policy/decision phiên bản riêng, legacy diagnostic-only, source authentication và mandatory guards |
| `scripts/evaluate_parser_policy_fix3.py` | Research runner E0–E4; labels/rubric chỉ ở evaluator |
| 5 `tests/test_*v2.py`, `test_query_policy.py`, `test_parser_policy_fix3_runner.py` | Synthetic development/compatibility/boundary tests; danh sách chính xác tại inventory |

Không rebuild corpus/index, đổi model/revision, gọi embeddings/LLM, mở held-out hoặc chạy 11 proposed probes. Không sửa production CLI/UI; không stage/commit/amend/push.

## Thiết kế khóa trước benchmark

`design_note.md` và `combined_policy.json` được viết trước benchmark. `pre_evaluation_freeze.json` chụp SHA-256 parser/context/support/policy, runner và design trước vòng E0–E4; kiểm tra lại sau vòng. Chỉ một policy design, không sweep thresholds/rules và không sửa runtime sau khi xem kết quả. Mọi lỗi development trong tests được ghi ở `tests.json`.

Hard requirements: >=1 ranked hit thật, finite existing scores và payload đúng runtime corpus/graph/provenance; parser supported và có mandatory requirements; không mismatch/ambiguous scope; tất cả mandatory requirements có evidence thật với field-resolved traces, identity/source anchors; không có completeness gap hoặc conflicting bound values liên quan. Scope unspecified chỉ pass nếu từng requirement có anchor đã authenticate. Missing/unknown/partial support đều block. Source inventory chỉ định boundary/completeness, không bổ sung positive proof ẩn.

Legacy decision, cosine/token-coverage thresholds, graph traversal/counts là diagnostics trong policy mới. Không coi scores là xác suất, không ép traversal cho direct evidence, không chấm score cho supplements. Unrelated cuts chỉ diagnostic khi support/completeness đã đủ. Budget E4: 12 supplementary items, 64 final items, 131072 canonical serialized UTF-8 bytes, depth 8. Giữ nguyên toàn bộ initial evidence nếu vượt budget và báo incomplete.

## Ablation và giới hạn tách nguyên nhân

| Arm | Thay đổi |
| --- | --- |
| E0 | Parser/checker/FIX2 context/AND legacy nguyên bản; replay exact saved FIX2 D |
| E1 | Parser v2 + final_items FIX2 cố định + compatibility checker v2 cho contract mới + AND legacy |
| E2 | Parser/checker v1 + final_items FIX2 cố định + policy mới; independent completeness/contradiction guards ghi riêng |
| E3 | Parser v2 + final_items FIX2 cố định + policy mới |
| E4 | Parser v2 + tính lại unranked supplementation từ cùng nguồn runtime + policy mới |

Mọi arm dùng cùng frozen ranked FIX1 initial_context. E1–E3 chỉ nâng inventory metadata, không đổi final_items. E1 không phải can thiệp parser thuần tuyệt đối: target-only chain/exact identities cần checker compatibility v2; tác động chung này được công bố. E2 giữ nguyên selected support v1, guard mới thuộc policy composition và xuất riêng. Layer metrics trong ablation_results vẫn là legacy-only diagnostics; không diễn giải thành performance các stage mới.

| Arm | TP/TN/FP/FN | Coverage | Selective error | Recall | False abstain / context đủ | FP unrelated / insufficient |
| --- | --- | --- | --- | --- | --- | --- |
| E0 | 2/16/0/14 | 2/32 (6.25%) | 0/2 (0.00%) | 2/16 (12.50%) | 12/14 (85.71%) | 0/8 (0.00%) / 0/8 (0.00%) |
| E1 | 5/16/0/11 | 5/32 (15.62%) | 0/5 (0.00%) | 5/16 (31.25%) | 9/14 (64.29%) | 0/8 (0.00%) / 0/8 (0.00%) |
| E2 | 6/16/0/10 | 6/32 (18.75%) | 0/6 (0.00%) | 6/16 (37.50%) | 9/14 (64.29%) | 0/8 (0.00%) / 0/8 (0.00%) |
| E3 | 8/16/0/8 | 8/32 (25.00%) | 0/8 (0.00%) | 8/16 (50.00%) | 7/14 (50.00%) | 0/8 (0.00%) / 0/8 (0.00%) |
| E4 | 9/16/0/7 | 9/32 (28.12%) | 0/9 (0.00%) | 9/16 (56.25%) | 6/14 (42.86%) | 0/8 (0.00%) / 0/8 (0.00%) |

## Parser, support và ngôn ngữ

| Arm | Parser supported/ambiguous/unsupported | Support supported/missing/unknown | EN TP/TN/FP/FN | VI TP/TN/FP/FN |
| --- | --- | --- | --- | --- |
| E0 | 10/10/12 | 9/1/22 | 2/8/0/6 | 0/8/0/8 |
| E1 | 13/8/11 | 8/3/21 | 5/8/0/3 | 0/8/0/8 |
| E2 | 10/10/12 | 9/1/22 | 2/8/0/6 | 4/8/0/4 |
| E3 | 13/8/11 | 8/3/21 | 5/8/0/3 | 3/8/0/5 |
| E4 | 13/8/11 | 9/2/21 | 5/8/0/3 | 4/8/0/4 |

Counts parser/support là query-level, không phải số requirements. Chi tiết EN/VI và per-requirement completeness/contradiction tại `analysis_metrics.json`:

- E0: `{"en":{"parser":{"ambiguous":5,"supported":4,"unsupported":7},"support":{"missing":1,"supported":3,"unknown":12}},"vi":{"parser":{"ambiguous":5,"supported":6,"unsupported":5},"support":{"supported":6,"unknown":10}}}`; completeness `{"not_in_v1_contract":31}`; contradiction `{"not_in_v1_contract":31}`.
- E1: `{"en":{"parser":{"ambiguous":3,"supported":7,"unsupported":6},"support":{"missing":2,"supported":5,"unknown":9}},"vi":{"parser":{"ambiguous":5,"supported":6,"unsupported":5},"support":{"missing":1,"supported":3,"unknown":12}}}`; completeness `{"complete":2,"incomplete":1,"not_applicable":27,"unknown":2}`; contradiction `{"none_detected":30,"unknown":2}`.
- E2: `{"en":{"parser":{"ambiguous":5,"supported":4,"unsupported":7},"support":{"missing":1,"supported":3,"unknown":12}},"vi":{"parser":{"ambiguous":5,"supported":6,"unsupported":5},"support":{"supported":6,"unknown":10}}}`; completeness `{"complete":1,"not_applicable":27,"unknown":3}`; contradiction `{"none_detected":28,"unknown":3}`.
- E3: `{"en":{"parser":{"ambiguous":3,"supported":7,"unsupported":6},"support":{"missing":2,"supported":5,"unknown":9}},"vi":{"parser":{"ambiguous":5,"supported":6,"unsupported":5},"support":{"missing":1,"supported":3,"unknown":12}}}`; completeness `{"complete":2,"incomplete":1,"not_applicable":27,"unknown":2}`; contradiction `{"none_detected":30,"unknown":2}`.
- E4: `{"en":{"parser":{"ambiguous":3,"supported":7,"unsupported":6},"support":{"missing":2,"supported":5,"unknown":9}},"vi":{"parser":{"ambiguous":5,"supported":6,"unsupported":5},"support":{"supported":4,"unknown":12}}}`; completeness `{"complete":3,"not_applicable":27,"unknown":2}`; contradiction `{"none_detected":30,"unknown":2}`.

Parser sửa được target-only ancestor chain, A-to-B process creation, launch command/passive roles, grounded evidence-limits/follow-up và URL actor/action tách background chain; tests đổi tên entities, phối hợp clauses, phủ định/so sánh và mandatory multi-intents. V1 APIs/fixtures/FIX2 replay giữ nguyên. Trên 32 cases, ba câu EN được cứu bởi parser/compatibility là process-chain và hai spawn-evidence queries. URL-download không còn bị chặn bằng parser unknown.

## Context, supplementation và completeness

| Arm | Min/max/mean UTF-8 bytes | Tổng/max supplements | Incomplete contexts |
| --- | --- | --- | --- |
| E0 | 26582/62927/51345.3125 | 16/6 | 0 |
| E1 | 26582/62927/51345.3125 | 16/6 | 0 |
| E2 | 26582/62927/51345.3125 | 16/6 | 0 |
| E3 | 26582/62927/51345.3125 | 16/6 | 0 |
| E4 | 26582/60995/51389.1875 | 18/6 | 0 |

Không cut budget trên 32 contexts. Không đồng nhất incomplete_context=false với mọi requirement đủ: chain thiếu target/source boundary vẫn unknown, limitations phải đủ exact requested identity set. Chuỗi không nối bằng basename/PID xuyên lifetime; cycle/depth/unresolved source coverage không được coi là complete. Right-count/wrong-identity limitations bị chặn trong synthetic tests.

E3→E4 cứu thêm `rd-vi-proxy-technique-assessment`: parser v2 sinh thêm review_status requirement; fixed context thiếu scenario analysis_status, E4 lấy source-associated scenario item. E2 đã cho proceed vì parser v1 không sinh requirement này; vì vậy có 1 TP của E2 bị mất tạm ở E3 rồi phục hồi ở E4. Đây là khác biệt contract cần review: review_status facet hiện mô tả scenario.analysis_status; technique review_status thực tế được verifier technique_assessment kiểm riêng. Clause continuation chưa bind chắc nghĩa review-status về đúng đối tượng nên không được khẳng định parser đã hiểu hoàn hảo câu đó.

## Các quyết định thay đổi và đối chiếu ngoài runtime

`changed_cases.md`/`.json` ghi đầy đủ 7 cases có thay đổi trong bất kỳ arm: requirements và exact query spans, quotation tới final context field/item/source identities/raw references, guards, lý do evidence hỗ trợ, phần chưa chứng minh và approved label ngoài runtime. Không tạo span giả cho v1. Tất cả quotes được đối chiếu lại, không lấy checker output làm nhãn chính nó.

- E1 so E0: cứu 3 dataset positives, gồm 0 VI; mất 0 baseline TP; FP 0.
- E2 so E0: cứu 4 dataset positives, gồm 4 VI; mất 0 baseline TP; FP 0.
- E3 so E0: cứu 6 dataset positives, gồm 3 VI; mất 0 baseline TP; FP 0.
- E4 so E0: cứu 7 dataset positives, gồm 4 VI; mất 0 baseline TP; FP 0.

E4 cứu EN: `rd-en-process-chain`, `rd-en-initial-spawn-evidence`, `rd-en-final-spawn-evidence`; VI: `rd-vi-proxy-technique-assessment`, `rd-vi-reviewed-scope-limitations`, `rd-vi-initial-relation-provenance`, `rp-vi-service-action`. Không mất TP E0; FP unrelated và insufficient-evidence đều 0/8 trên tập exposed này.

**Bất đồng rubric cần giữ nguyên:** `rp-vi-service-action` có launch-command evidence (`-noexit -command Get-Service sysmon`) và expected proceed, nhưng external context_sufficient vẫn **null** vì thiếu exact limitation_4 về completion/output/service state. Không đổi rubric/label và không cộng trường hợp này vào 14 contexts được rubric xác nhận đủ. Trace chỉ chứng minh command line khi launch, không chứng minh cmdlet hoàn tất hoặc Sysmon service state. E4 giữ 8 context-sufficient positives và thêm 1 dataset-positive/context-unknown; false abstain/context đủ còn 6/14. Đây là giới hạn guard/scope của checker, không dùng FP=0 che khuất.

**URL-download:** requirement duy nhất actor=`powershell.exe`, action=`download`, field=`url`; phần MSHTA chain là background. Parser supported, verifier **missing** (`bound_actor_action_endpoint_not_returned`), quyết định abstain trực tiếp trong E1/E3/E4. Không suy ra download không xảy ra ở toàn hệ thống. C2-address cũng missing bound network evidence. URL trong command/reference không đủ chứng minh download.

## False abstains còn lại và bước review

7 dataset positives E4 vẫn abstain:

- `rd-vi-scripting-technique-status`: parser ambiguous; support unknown; `negation_scope_not_resolved, unrecognized_requested_clause, recognized_clause_local_requirements, query_requirement_analysis_not_supported`.
- `rp-en-intermediate-utility`: parser unsupported; support unknown; `unrecognized_requested_clause, unsupported_information_request`.
- `rp-en-shell-creator`: parser ambiguous; support unknown; `unresolved_cross_clause_pronoun, unrecognized_requested_clause, unsupported_information_request`.
- `rp-en-technique-review`: parser ambiguous; support unknown; `unresolved_cross_clause_pronoun, recognized_clause_local_requirements, query_requirement_analysis_not_supported`.
- `rp-vi-launch-order`: parser supported; support unknown; `recognized_clause_local_requirements, chain_target_not_bound`.
- `rp-vi-observation-provenance`: parser supported; support unknown; `recognized_clause_local_requirements, chain_target_not_bound`.
- `rp-vi-final-review-limits`: parser unsupported; support unknown; `unrecognized_requested_clause, unsupported_information_request`.

Các nhóm còn yếu: anaphora/implicit process roles (final shell/intermediate utility), continuation câu kỹ thuật tiếng Việt và negation punctuation, chain không nêu target, provenance cho toàn bộ hai groups (verifier cũ chỉ trả observation đại diện), follow-up diễn đạt mở không có evidence/review anchor rõ. Parser còn có thể tạo requirement thừa từ từ khóa background như command-line trong câu technique assessment. Các trường hợp này được giữ ambiguous/unsupported/unknown, chưa thêm rules sau khi xem benchmark.

Deterministic subset đã cải thiện nhưng chưa đủ để khóa cấu hình cho kiểm chứng riêng: recall 56.25%, parser unresolved 19/32 và support unknown 21/32, còn bất đồng rubric và review-status object binding. Đề xuất review contract/coverage theo nhóm ngôn ngữ và annotated semantic requirements độc lập; chỉ sau một quyết định riêng mới triển khai hướng parser có grammar chặt hơn hoặc semantic parser với strict validation. Không mở thêm tầng heuristic/tune trên 32 cases trong FIX3; chưa thực hiện đề xuất tiếp theo.

## Tests, hashes và package

| Scope | Passed | Subtests | Failed | Skipped |
| --- | --- | --- | --- | --- |
| focused | 221 | 0 | 0 | 0 |
| related regression | 2883 | 0 | 0 | 0 |
| full suite | 6342 | 6 | 0 | 0 |

Exact commands đã chạy (Windows TEMP dùng vì workspace ACL, không phải dependency/model download):

```powershell
.\.venv\Scripts\python.exe -B -m pytest tests/test_query_requirements_v2.py tests/test_query_context_v2.py tests/test_query_support_v2.py tests/test_query_policy.py tests/test_parser_policy_fix3_runner.py -q -p no:cacheprovider --basetemp="$env:TEMP/rag-fix3-focused-final-20261017" > outputs/experiments/graphrag-2d3-fix3/focused_final.log 2>&1
```

```powershell
.\.venv\Scripts\python.exe -B -m pytest tests/test_query_requirements.py tests/test_query_context.py tests/test_query_support.py tests/test_query_aware_gate.py tests/test_query_aware_ablation.py tests/test_retrieval_builder.py tests/test_retrieval_schema.py tests/test_vector_index_builder.py tests/test_vector_index_schema.py tests/test_vector_retriever.py tests/test_hybrid_retriever.py tests/test_knowledge_graph_builder.py tests/test_knowledge_graph_schema.py tests/test_knowledge_graph_traversal.py tests/test_graphrag_seed_mapping.py tests/test_graphrag_orchestrator.py tests/test_graphrag_relevance.py tests/test_graphrag_gate_signals.py tests/test_graphrag_two_stage_gate.py tests/test_relevance_calibration_schema.py tests/test_ground_truth_schema.py tests/test_ground_truth_builder.py tests/test_ground_truth_approval.py tests/test_ground_truth_v2_provenance_consumers.py tests/test_graph_ground_truth_v2.py tests/test_retrieval_ground_truth_v2.py tests/test_two_stage_calibration.py tests/test_two_stage_review.py -q -p no:cacheprovider --basetemp="$env:TEMP/rag-fix3-regression-final-20261017" > outputs/experiments/graphrag-2d3-fix3/regression_final.log 2>&1
```

```powershell
.\.venv\Scripts\python.exe -B -m pytest -q -p no:cacheprovider --basetemp="$env:TEMP/rag-fix3-full-final-20261017" > outputs/experiments/graphrag-2d3-fix3/full_final.log 2>&1
```

Experiment command: `.\.venv\Scripts\python.exe -B scripts/evaluate_parser_policy_fix3.py`. Replay audit là consistency check của saved outputs, không thêm experiment/independent sample. `validation_results.json` ghi số contexts/decisions/field quotes được kiểm tra và frozen hashes. `protected_hashes_after.json` ghi SHA-256 trước/sau toàn bộ 5.528 baseline paths; `protected_hash_summary.md` ghi raw inputs, approved bundle, FIX1, FIX2 và ZIPs cũ. Chỉ PROJECT_PROGRESS thay đổi theo append-only prefix.

Package `outputs/review/graphrag_parser_policy_fix3_review.zip` chứa source/tests/dependency closure, frozen configs/design, requirements/contexts/support traces/decisions, E0–E4 metrics, per-case analysis, actual test logs, hashes và `review_inventory.json`. `zip_verification.json` bên ngoài ghi archive/inventory SHA-256, unique safe regular entries, CRC/testzip và payload sizes/hashes. Dừng chờ review FIX3.
