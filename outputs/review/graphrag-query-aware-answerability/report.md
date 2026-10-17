# GRAPHRAG-2D3-FIX2 — Query-aware retrieval và evidence answerability

Triển khai và ablation: 16/10/2026; hoàn tất kiểm chứng và đóng gói: 17/10/2026. Trạng thái: **chờ người dùng review kết quả FIX2**.

FIX2 bổ sung context có giới hạn và chặn được hai false proceed của FIX1 trên 32 development cases. Đổi lại, số true proceed giảm từ 5 xuống 2, false abstain theo nhãn tăng từ 11 lên 14 trên 16 câu hỏi có đáp án. Coverage chỉ còn 6,25%; kết quả này chưa đủ để chấp nhận policy production hay tiến tới kiểm chứng độc lập với kiến trúc hiện tại.

Các con số trong báo cáo lấy từ [ablation_results.json](../../experiments/graphrag-2d3-fix2/ablation_results.json), [case_transitions.json](../../experiments/graphrag-2d3-fix2/case_transitions.json) và artifacts thực tế. [Per-case report](per_case_report.md) ghi query, quyết định, lý do, context và support trace. `supported` của checker mới là chẩn đoán runtime trong contract công bố; nó không thay thế nhãn đã được người dùng duyệt hoặc rubric đánh giá bên ngoài.

## Phạm vi và các thành phần mới

Branch nền: `feature/mshta-evidence-extractor`; HEAD nền: `af2243a3ee89c5e5721ec341eea0a8cb06814f41`. Working tree có thay đổi từ các milestone trước. Snapshot đầu FIX2 và bản sao các file có sẵn được lưu trong `outputs/experiments/graphrag-2d3-fix2/`; không yêu cầu working tree sạch.

[Design note](../../experiments/graphrag-2d3-fix2/design_note.md) được viết trước triển khai. Bốn API mới hoạt động trên JSON trong bộ nhớ: `analyze_query_requirements`, `enrich_query_context`, `assess_evidence_support`, `assess_query_aware_gate`. Luồng thử nghiệm giữ riêng legacy decision, requirements/scope, support assessment, ranked signals và final experimental decision. Source, tests và dependency closure được đóng trong ZIP review; [inventory](review_inventory.json) ghi phạm vi thay đổi so với working tree đầu lượt.

Parser deterministic hỗ trợ một tập EN/VI giới hạn: process relationship, launch command, command completion, service state, network URL/endpoint, evidence/provenance, review limitations và technique assessment. Public vocabulary nhận diện platform/mechanism, executable names và các aliases; không nhận case IDs, labels, reference answers hoặc expected evidence. Những cấu trúc chưa phân giải được được ghi `ambiguous`/`unsupported`; scope chưa xác định không tự trở thành mismatch.

Support checker chỉ đọc items thực sự nằm trong final context. Trace ghi item ID, field/context pointer, source pointer, quote và subject/action/object khi cần. Nó phân biệt launch với completion/output/service state; URL đơn lẻ với quan hệ actor–action–endpoint; quan hệ có identity/role với hai tên cùng xuất hiện; candidate MITRE với confirmed. `missing` chỉ có nghĩa thiếu evidence trong context đã kiểm tra. Không có kết luận an ninh hoặc câu trả lời LLM được sinh ra.

## Thiết kế ablation và cấu hình cố định

| Arm | Context evidence | Quyết định |
| --- | --- | --- |
| A | Context FIX1 đã đóng băng | Legacy policy |
| B | Context FIX1 + enrichment | Legacy policy, ngưỡng giữ nguyên |
| C | Context FIX1 | Query-aware scope/support **AND** legacy proceed |
| D | Context FIX1 + enrichment | Query-aware scope/support **AND** legacy proceed |

Cả bốn arms dùng cùng ranked contexts FIX1. Không chạy lại embedding, retrieval ranking, seed mapping hoặc traversal; không rebuild index. Model/index nền vẫn là `intfloat/multilingual-e5-small`, revision `614241f622f53c4eeff9890bdc4f31cfecc418b3`, 384 dimensions, L2/cosine, prefixes `passage: ` và `query: `. `top_k=5`, `candidate_k=20`, RRF `k=60`, traversal depth 2, direction `both` giữ nguyên. Milestone FIX2 có **0 model calls**, **0 threshold candidates**, **0 proposed probes**, không mở held-out.

Policy `two-stage-dev-5a4b308b106699e0` vẫn yêu cầu query token coverage ít nhất `0.18181818`, top cosine ít nhất `0.84299805`, mapped hit/seed và traversal theo cấu hình cũ. C/D không bypass legacy topical failure. Supplementary items không thuộc ranking: không có BM25/cosine/RRF giả, không tạo graph edges/paths. B/D tính lại ranked legacy signals từ `initial_context` nguyên trạng trong final envelope, đồng thời tính diagnostics riêng từ toàn bộ final items. Vì old policy chỉ đọc ranked signals, **A/B có cùng 32 quyết định**; enrichment được đo qua coverage của context, không được giả thành một thay đổi chất lượng ranking.

## Kết quả theo nhãn dataset

TP/TN/FP/FN dùng `proceed` là lớp dương. Coverage = số proceed/32; selective error = FP/số proceed, theo nhãn dataset.

| Arm | TP | TN | FP | FN | Coverage | Selective error | FP unrelated | FP insufficient evidence | False abstain trên context đủ theo rubric ngoài |
| --- | ---: | ---: | ---: | ---: | --- | --- | --- | --- | --- |
| A | 5 | 14 | 2 | 11 | 7/32 = 21,88% | 2/7 = 28,57% | 1/8 | 1/8 | 8/13 = 61,54% |
| B | 5 | 14 | 2 | 11 | 7/32 = 21,88% | 2/7 = 28,57% | 1/8 | 1/8 | 9/14 = 64,29% |
| C | 2 | 16 | 0 | 14 | 2/32 = 6,25% | 0/2 = 0% | 0/8 | 0/8 | 11/13 = 84,62% |
| D | 2 | 16 | 0 | 14 | 2/32 = 6,25% | 0/2 = 0% | 0/8 | 0/8 | 12/14 = 85,71% |

D so với A có 5 chuyển `proceed→abstain`: 2 false proceeds được chặn và 3 true proceeds bị mất. Hai cases còn proceed là `rd-en-shell-parent` và `rp-en-retained-scripting-label`. 25 cases đã abstain vẫn abstain; không có `abstain→proceed`. C và D cũng có cùng quyết định, dù final contexts khác nhau.

Các layer summaries trong JSON giữ đúng ý nghĩa **legacy stages**, không được diễn giải lại thành quality của checker mới. Legacy topical pass 7/32 và answerability pass cả 7 cases đó. Final C/D gồm 21 abstentions tại `query_requirements`, 8 tại `topical_relevance`, 1 tại `evidence_answerability`, và 2 proceed. Các blockers khác vẫn hiện đầy đủ trong trace, kể cả khi blocker đầu tiên đã đủ để abstain.

## Tiếng Anh và tiếng Việt

| Arm | Ngôn ngữ | TP/TN/FP/FN | Coverage | Selective error | False abstain/context đủ |
| --- | --- | --- | --- | --- | --- |
| A | EN, 16 cases | 5/6/2/3 | 7/16 = 43,75% | 2/7 = 28,57% | 3/8 |
| B | EN, 16 cases | 5/6/2/3 | 7/16 = 43,75% | 2/7 = 28,57% | 3/8 |
| C | EN, 16 cases | 2/8/0/6 | 2/16 = 12,5% | 0/2 = 0% | 6/8 |
| D | EN, 16 cases | 2/8/0/6 | 2/16 = 12,5% | 0/2 = 0% | 6/8 |
| A | VI, 16 cases | 0/8/0/8 | 0/16 | Không xác định (0/0) | 5/5 |
| B | VI, 16 cases | 0/8/0/8 | 0/16 | Không xác định (0/0) | 6/6 |
| C | VI, 16 cases | 0/8/0/8 | 0/16 | Không xác định (0/0) | 5/5 |
| D | VI, 16 cases | 0/8/0/8 | 0/16 | Không xác định (0/0) | 6/6 |

Không arm nào trả proceed cho tiếng Việt. Parser nhận supported 6/16 câu VI nhưng legacy quality vẫn chặn cả các câu VI có support. Đây là hạn chế cần giải quyết trước khi áp dụng cho người dùng tiếng Việt; số FP thấp không bù cho coverage bằng 0.

## Requirements, scope và support

| Chẩn đoán trên 32 queries | Số lượng |
| --- | ---: |
| Parser supported | 10 (31,25%) |
| Parser ambiguous | 10 (31,25%) |
| Parser unsupported | 12 (37,5%) |
| Scope in_scope / mismatch / unspecified | 1 / 1 / 30 |
| Support supported / missing / unknown, C và D | 9 / 1 / 22 |

Unsupported + ambiguous chiếm 22/32 = 68,75%; support unknown cũng là 22/32. EN có parser supported/ambiguous/unsupported = 4/5/7; VI = 6/5/5. Các nhóm này là diagnostics của implementation, không phải nhãn đánh giá mới. Chưa có tiêu chuẩn chấp nhận các tỷ lệ này được thống nhất; không thể coi mức unsupported 37,5% và false abstain 14/16 là đạt yêu cầu sử dụng.

`ur-en-linux-cron` chuyển từ proceed ở A/B sang abstain ở C/D tại topical stage với `requested_scope_mismatch`. Public source scope là Windows/process creation; parser nhận Linux và cron như platform/mechanism. Đây là mismatch rõ ràng của yêu cầu. Các trường hợp phủ định, so sánh và nhiều scope trong synthetic development tests được giữ ambiguous khi chưa phân giải được; không tuyên bố rằng mọi câu có chữ Linux đều bị loại. Bộ 32 queries chỉ có một mismatch rõ ràng, nên chưa đủ đo chất lượng scope checks nói chung.

`ie-en-payload-download-url` cũng chuyển proceed sang abstain, nhưng lý do thực tế là `query_requirements_ambiguous` và `required_evidence_unknown` tại parsing stage. Parser gán actor của yêu cầu download là `null`, đồng thời diễn giải phần chain thành quan hệ chưa đúng vai trò. Checker không chạy một phép xác minh download đầy đủ cho query này. **Đây là abstention an toàn khi parser chưa hiểu, chưa phải bằng chứng rằng URL case đã được giải quyết bằng direct missing-evidence verification.** Synthetic tests riêng chứng minh checker không nhận URL sai actor/action hoặc URL trong command/reference làm download evidence; chúng không thay thế kết quả còn unknown của query thực tế.

Case `ie-en-c2-address` có parser supported và support `missing`, với `bound_actor_action_endpoint_not_returned`; đây là case thực tế có kiểm tra thiếu actor–action–endpoint. Nó vốn đã bị legacy quality chặn, nên không tạo thêm thay đổi quyết định A→D.

## Enrichment và context coverage

Budget mặc định là tối đa 12 supplementary items, 64 final items và **131072 bytes UTF-8 của canonical serialized `final_items`**. Đây là byte count, không phải token count và cũng không phải kích thước toàn bộ envelope có bản sao `initial_context`. Items được giữ nguyên toàn bộ; không cắt chuỗi command/provenance. Nếu baseline đã quá budget, API giữ baseline và báo rõ; trường hợp đó được kiểm thử bằng synthetic data.

Thực nghiệm bổ sung 16 items cho 7/32 contexts, nhiều nhất 6 items/query. Không có cut do budget ở B/D. Final evidence bytes tăng từ min/max/mean `26582/60183/50761.6875` lên `26582/62927/51345.3125`. A/C có 7 contexts báo incomplete vì enrichment được tắt và có candidate chưa thêm; đây không phải 7 budget failures. B/D có 0 incomplete contexts theo selection/budget contract. Completeness này chỉ nói các candidates được cơ chế hiện tại chọn đã được trả; không bảo đảm parser đã tìm đúng mọi thông tin cần thiết.

| Query có supplementation | Items thêm | Source objects chính |
| --- | ---: | --- |
| `rd-vi-scripting-technique-status` | 1 | candidate-status limitation |
| `rd-vi-reviewed-scope-limitations` | 6 | scenario metadata và limitations 1, 2, 4, 5, 6 |
| `rp-en-technique-review` | 3 | hai relationship chunks và candidate-status limitation |
| `rp-en-retained-scripting-label` | 1 | candidate-status limitation |
| `rp-vi-observation-provenance` | 2 | hai relationship chunks |
| `ie-en-payload-download-url` | 2 | hai relationship chunks, không phải download evidence |
| `ie-vi-decoding-proof` | 1 | candidate-status limitation |

Rubric ngoài runtime giữ nguyên tiêu chí. Source adapter chỉ đưa items thực tế đã trả về về shape mà rubric cũ đọc được. Context sufficient `True` tăng 13→14; `False` giữ 9; `None` giảm 10→9. Trong `None` có 8 unrelated cases mà answerability không áp dụng. Đây là conservative AI rubric chưa được người dùng duyệt như semantic evaluator; các paraphrase/prose chưa có support chính xác vẫn có thể ở trạng thái unknown.

Ba gaps được theo dõi từ FIX1 cho kết quả khác nhau:

| Case | Approved source và consumers FIX1 | Context A/C → B/D | Kết quả còn lại |
| --- | --- | --- | --- |
| `rd-vi-reviewed-scope-limitations` | Cả 7 limitations có sẵn trong GT/corpus/graph | Ban đầu chỉ có limitations 0 và 3; thêm 5 limitations còn thiếu cùng `/scenario`. Rubric ngoài `None→True`, đủ cả 7 units | Support hiện `supported`, vẫn abstain vì top cosine dưới ngưỡng legacy |
| `rp-vi-final-review-limits` | Scenario analysis status và limitations có trong consumers | Parser `unsupported`; không có supplementation. Rubric vẫn `False`, thiếu source-associated analysis status và nhiều limitation units | Không khắc phục được coverage; support unknown và legacy quality cùng chặn |
| `rp-vi-service-action` | Original PowerShell CommandLine và limitation 4 có trong consumers | Launch command đã có ở `/facts/1`; không thêm item. Rubric vẫn `None` vì limitation 4 chưa được trả | Checker hỗ trợ launch command đúng scope, không suy completion/service state; legacy quality vẫn chặn |

Ba true positives bị mất là `rd-en-process-chain`, `rd-en-initial-spawn-evidence`, `rd-en-final-spawn-evidence`. Context của cả ba đủ theo rubric ngoài cả trước/sau. Parser chưa xử lý được target-only chain hoặc cấu trúc “A to B process creation relationship”, trả `ambiguous`/`unresolved_entity_roles`; checker giữ unknown thay vì coi query đã hiểu. Việc tăng FN này là lỗi về coverage/role binding của parser, không phải thiếu dữ liệu trong ba contexts.

## Provenance, tests và giới hạn xác nhận

Có hai vòng chạy development. Sau vòng đầu, review code tìm thấy các invariant chung chưa được giữ: nhiều process identities có thể bị rút thành wildcard chain; `chain`/`chuỗi` không có process anchor bị nhận như process relationship; một từ provenance có thể che phần khẳng định tích cực hoặc kết luận an ninh mà parser chưa hỗ trợ. Các invariant đó được sửa bằng synthetic development tests, không điều chỉnh ngưỡng hoặc thêm proposed/held-out queries. Các artifacts vòng đầu được giữ tại [iterations/initial](../../experiments/graphrag-2d3-fix2/iterations/initial/iteration_manifest.json).

Vòng đầu có parser supported/ambiguous/unsupported = 13/7/12; vòng cuối là 10/10/12. Support unknown tăng 19→22. Matrices A/B/C/D và số supplementary items không đổi. Manifest vòng đầu ghi rõ runtime source hashes chưa được chụp ngay tại thời điểm chạy; artifact hashes được giữ, còn source closure cuối được inventory ghi lại. Không coi hai vòng development này là hai phép kiểm chứng độc lập hoặc che việc parser đã thay đổi sau review.

Các input FIX1 được tái sử dụng theo hash sau; policy, model và index giữ nguyên. Không đưa approval reviewer/timestamp, benchmark labels/answers hoặc rubric vào runtime evidence content.

| Input | SHA-256 |
| --- | --- |
| Approved Ground Truth v2 | `8676d7a1df41058e7f4b1460a0d4bf909fca5d8f20992753e63be7d024268461` |
| FIX1 corpus | `b57ffad3d1e3b797e1b5fae7360b605a67acbecede8fb98ce8faf6f993cc695c` |
| FIX1 graph | `04d6efd2ca47388689ad376766f96f9136a9a8f4ef22403b4bc1ed4ff30ae443` |
| FIX1 vector index | `2182baefb9598609c5e1e9a92ac370b366e0fcab79e8d672ac64adcb7717ae78` |
| Fixed policy | `b132df134abbffa8a9ebd2afbb742befc239d4111f63a024b5386fe09d5d447c` |
| FIX1 frozen contexts | `da3a0e30053d7579025b442d3c68799b7d6df3a0a9d286e99a3d1b3354952258` |

[review_inventory.json](review_inventory.json) ghi đầy đủ protected hashes trước/sau, raw data, approved bundle, FIX1 artifacts/ZIP, baseline working-tree snapshot, diff checks và phạm vi source mới. [tests.json](tests.json) là bản ghi exact commands/counts cho focused, regression và full suite cuối cùng; không suy số tests từ baseline 5900. Các synthetic cases dùng trong phát triển là development tests. Không chạy 11 proposed probes hoặc held-out; 32 queries đã tham gia development từ các milestone trước, nên không phải independent validation.

Kiểm chứng cuối ngày 17/10: focused **221 passed** (1.46s), regression liên quan **2.541 passed** (14.85s), full suite **6.121 passed + 6 subtests passed** (143.05s), **0 failed/skipped**. Exact commands và terminal output được lưu trong `tests.json` cùng ba log UTF-8 ở thư mục experiment. Một phiên regression trước khi tiếp tục không còn trả được kết quả từ tool, nên đã chạy lại và dùng kết quả có log cuối, không suy đoán count của phiên đó.

ZIP review tại `outputs/review/graphrag_query_aware_answerability_review.zip`; [zip_verification.json](zip_verification.json) là sidecar cho archive hash, inventory hash, safe unique entries, `testzip() == None` và payload sizes/hashes. Sidecar nằm ngoài archive để tránh vòng self-hash. [protected_hash_summary.md](protected_hash_summary.md) liệt kê hashes chính trước/sau; bảng đầy đủ nằm trong `protected_hashes_after.json` của experiment. Nội dung tiến độ cũ được giữ nguyên bytes và chỉ nối checkpoint FIX2.

Đối chiếu 5.279 baseline files xác nhận toàn bộ source/tests/fixtures có sẵn, raw inputs, approved bundle, FIX1 artifacts và các ZIP cũ giữ nguyên hash. Sau append checkpoint, chỉ `PROJECT_PROGRESS.md` đổi hash và giữ nguyên toàn bộ bytes cũ làm prefix. Đã replay saved outputs cả bốn arms, kiểm tra 444 trace field quotations/item IDs khớp actual final context và kiểm tra source/runner hashes đúng configuration cuối; đây là consistency checks, không phải một thí nghiệm độc lập. Branch/HEAD giữ nguyên, staging rỗng và `git diff --check` sạch.

## Những việc cần review trước bước tiếp theo

Context coverage đã cải thiện cho câu tổng hợp reviewed-scope limitations, nhưng hai gaps còn lại chưa được giải quyết. Scope checks chặn mismatch Linux cron rõ ràng; khả năng xử lý phủ định/so sánh trong ngôn ngữ tự nhiên vẫn có giới hạn. Support checker có guard về role, identity, action, provenance và mức chắc chắn, nhưng URL benchmark hiện bị chặn vì parsing unknown; không được gộp hai điều này thành một thành công semantic verification.

Trước independent evaluation cần xem xét role/actor binding theo clause, target-only chain và provenance của quan hệ; cách nhận diện các paraphrase review/launch limits ngoài lexicon hiện tại; và cách ràng buộc completeness của câu hỏi limitations với subrequirements thật sự. Đồng thời cần một cấu hình chất lượng retrieval phù hợp EN/VI và enrichment mà vẫn giữ provenance của ranked/supplementary signals tách biệt. Thay đổi điều kiện legacy phải thành policy/version thử nghiệm tường minh sau review; không tự bypass ngưỡng trong FIX2.

Cần thống nhất mức chấp nhận FP/FN, coverage và unsupported/unknown; review độc lập một semantic rubric và đóng băng kiến trúc/policy trước khi sử dụng một tập chưa bị development chạm tới. Lượt này không thực hiện các thay đổi kiến trúc/calibration đề xuất đó. Production defaults, CLI, LLM/UI, raw data và approved labels giữ nguyên; kết quả dừng tại review FIX2.
