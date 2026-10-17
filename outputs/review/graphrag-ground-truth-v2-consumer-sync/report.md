# GRAPHRAG-2D3-FIX1 — Đồng bộ evidence consumers với Ground Truth v2

Ngày báo cáo: **16/10/2026**. Đã xây corpus, knowledge graph và vector index thử nghiệm từ Ground Truth v2 được duyệt, bằng builders thực tế và provenance đúng nguồn. Việc đồng bộ nguồn và bảo toàn evidence đã đạt ở cấp artifact; đường runtime vẫn chưa trả đủ nội dung cho ba development cases cần kiểm tra. Gate giữ policy cố định và có regression: **TP=5, TN=14, FP=2, FN=11**, so với **5/15/1/11** trước đó. Chưa đủ điều kiện xác nhận policy production hoặc held-out validation.

## Phạm vi và baseline

Baseline được chụp trước khi sửa tại [preflight.json](../../experiments/graphrag-2d3-fix1/preflight.json): branch `feature/mshta-evidence-extractor`, HEAD đầy đủ `af2243a3ee89c5e5721ec341eea0a8cb06814f41`, staging rỗng. Snapshot lưu working tree và hashes để phân biệt thay đổi có sẵn với FIX1. Các Markdown và thay đổi prerequisite/calibration có sẵn được bảo toàn; phần cập nhật tiến độ được append riêng. Không reset, stash, checkout, stage, commit, amend hoặc push.

Phạm vi code của FIX1 gồm sáu file nguồn: `retrieval/schema.py`, `retrieval/builder.py`, `graph/schema.py`, `graph/builder.py`, `graphrag/relevance.py` và `evaluation/calibration_schema.py` dưới `src/threat_hunting/`; thêm `scripts/sync_ground_truth_v2_consumers.py` và bốn test files mới: `test_retrieval_ground_truth_v2.py`, `test_graph_ground_truth_v2.py`, `test_ground_truth_v2_provenance_consumers.py`, `test_sync_ground_truth_v2_consumers.py`. Không sửa legacy fixtures để làm tests pass. Danh sách thay đổi thực tế so với snapshot, kết quả protected-hash checks và trạng thái Git cuối nằm trong [review_inventory.json](review_inventory.json).

Current request cho phép sửa compatibility, rebuild thử nghiệm và chạy lại 32 development cases; quyền này cụ thể hơn checkpoint cũ trong `AGENTS.md`/`PROJECT_CONTEXT.md`. Không mở rộng sang LLM, UI, production CLI/defaults, scenario mới hoặc positive probes ngoài core.

## Nguồn đã duyệt và ranh giới approval

Đã đọc bundle bằng `load_approved_evaluation_bundle`: validate schema thực tế của Ground Truth/reference answers/manifest v2, dependency hashes và cùng sự kiện phê duyệt của `Nguyen Hong Phong`, thời điểm `2026-10-15T23:36:13+07:00`. Không sửa nội dung, nhãn, câu hỏi, đáp án hoặc approval của bundle này.

| Approved artifact | SHA-256 |
| --- | --- |
| `scenario_ground_truth.json` | `8676d7a1df41058e7f4b1460a0d4bf909fca5d8f20992753e63be7d024268461` |
| `reference_answers.json` | `400026d106b863c4127c57c74d3b7722e672652474638bb9554089d322fba96b` |
| `review_manifest.json` | `29507fe4f68a1222d93d5626da8d03f29b497d5798be3f2f6786f8911d0eedb4` |

`confirmed` chỉ xác nhận human review của tài liệu. Không copy approval metadata vào evidence text, embeddings, graph claims, gate signals hoặc security status. `scenario.analysis_status` vẫn là `draft_reviewable`; các MITRE assessments vẫn `candidate`/`needs_review`, với mức hỗ trợ hiện có. Các ghi chú pending-review mang tính lịch sử trong nguồn được giữ nguyên theo yêu cầu bảo toàn, không được dùng làm gate input.

Builders chỉ nhận Ground Truth. Facts, entities, relationships, observations, Sigma/MITRE assessments, summary và limitations từ nguồn được phép đi vào evidence consumers. Benchmark questions, case IDs, reference answers, expected decisions và rubric chỉ xuất hiện trong artifacts đánh giá ngoài runtime. Structural/full-string checks không phát hiện các nội dung đánh giá này trong corpus/graph; đây là phạm vi kiểm tra cụ thể, không phải tuyên bố phát hiện mọi semantic leakage.

## Compatibility và nội dung được sửa

Các provenance validators nhận đúng hai source versions `scenario-ground-truth/v1` và `scenario-ground-truth/v2`; phiên bản khác bị từ chối. Builders ghi `schema_version` từ nguồn thực tế, cùng path/hash/scenario ID, không mặc định v1 hoặc đổi string để lách validator. Cấu trúc downstream không đổi nên vẫn dùng `retrieval-corpus/v1`, `knowledge-graph/v1`, `vector-index/v1` và các schema gate/report hiện có. Hành vi v1 và golden fixtures được kiểm chứng riêng.

Ngoài golden fixtures, đã chạy lại builders trên Ground Truth v1 thực tế với source path/hash cũ: kết quả corpus và graph giống hệt nội dung artifacts baseline, không ghi đè các file đó.

Summary mới mô tả **PowerShell được khởi chạy với command line chứa `Get-Service sysmon`**. Không còn wording cũ khẳng định “PowerShell ran/runs Get-Service sysmon”. Process creation không chứng minh cmdlet hoàn tất/thành công, output hoặc trạng thái dịch vụ Sysmon. Những giới hạn này được giữ rõ trong source và consumers.

Facts bảo toàn đầy đủ `attributes.source_observations`, gồm giá trị `CommandLine` gốc, các trường parent/child process và định danh có trong nguồn, `source_file` và `raw_record_ref`. Corpus giữ cả cấu trúc metadata và giá trị serialized trong content được embedding; graph giữ nested attributes để traversal trả về. Đây không chỉ là tên trường hoặc một địa chỉ provenance.

Cả bảy limitations được đưa vào chunks/nodes riêng. Ba limitations bổ sung gồm: không suy kết quả cmdlet/service state; xung đột `TimeCreated`/`UtcTime` và timezone chưa giải quyết; `conhost`, log clearing, temporary-file deletion nằm ngoài core và không bị coi là vắng mặt toàn file hoặc tự động là destructive payload. Không thêm causal edge từ timestamp proximity hoặc nối limitation nodes bằng quan hệ mới chỉ để tăng context coverage.

## Rebuild riêng và embedding bindings

Outputs mới chỉ nằm trong `outputs/experiments/graphrag-2d3-fix1/`. [Build manifest](../../experiments/graphrag-2d3-fix1/build_manifest.json) ghi nguồn, counts, hashes, model/config và kiểm tra deterministic. Corpus/graph cùng trỏ nguồn v2 ở đường dẫn review được duyệt. Index trỏ đúng bytes/hash/ID của corpus mới; 22 chunk IDs được index đúng một lần, không thiếu/thừa vector hoặc sai dimensions. Graph giữ reference integrity; số edges không tăng.

| Artifact | Baseline calibration | FIX1 |
| --- | --- | --- |
| Corpus | 19 chunks | 22 chunks |
| Graph | 17 nodes, 21 edges | 20 nodes, 21 edges |
| Index | 19 vectors | 22 vectors, dimension 384 |

| Consumer | Hash baseline được bảo toàn | Hash FIX1 |
| --- | --- | --- |
| Corpus | `53abc9e44c03c46aaf024cdb79b61ad3381d50feb82689f27074151381b9d0f3` | `b57ffad3d1e3b797e1b5fae7360b605a67acbecede8fb98ce8faf6f993cc695c` |
| Graph | `892a4c1926178c12bb3878dbd7e5d779d39494b8c11da3ac33864cbdc66c7227` | `04d6efd2ca47388689ad376766f96f9136a9a8f4ef22403b4bc1ed4ff30ae443` |
| Calibration E5 index | `e329f0031b64f255044d47d6162535c5bff3916369987d17e3d37e0b25023e91` | `2182baefb9598609c5e1e9a92ac370b366e0fcab79e8d672ac64adcb7717ae78` |

Giữ model `intfloat/multilingual-e5-small`, revision `614241f622f53c4eeff9890bdc4f31cfecc418b3`, cosine, L2 normalization, dimension 384, document prefix `passage: `, query prefix `query: `. Dùng snapshot local đã pin, CPU/offline/batch_size=1/show_progress_bar=false. Không tải/đổi/promote model.

Có **22 document cache misses, 0 cache hits**, không tái sử dụng old vectors. Một determinism replay dùng lại đúng 22 inputs/vectors vừa tạo trong cùng run sau kiểm tra exact input; không phải lần model inference thứ hai hoặc cache nguồn cũ. Có **32 query cache misses, 0 hits**; contexts/signals được tính lại từ bundle mới. Build manifest lưu hash từng embedding input. Không gắn vectors cũ vào chunk text đã thay đổi.

## Thiết kế so sánh cố định

Policy giữ nguyên bytes và ID `two-stage-dev-5a4b308b106699e0`; không search thresholds hoặc thay evaluator. [Experiment configuration](../../experiments/graphrag-2d3-fix1/experiment_configuration.json), [fixed policy](../../experiments/graphrag-2d3-fix1/fixed_policy.json) và [comparison.json](../../experiments/graphrag-2d3-fix1/comparison.json) ghi các bindings.

Retrieval vẫn `top_k=5`, `candidate_k=20`, không chunk/dimension filters; hybrid RRF `k=60`; exact seed mapping; traversal `direction=both`, depth=2, max_nodes=100, max_edges=200, không edge filter. Context budget vẫn 5 hits/100 nodes/200 edges, không thêm token truncation. Topical policy yêu cầu ít nhất một retrieval hit, query-token coverage `0.18181818` và returned top cosine `0.84299805`; các topical minima khác là 0/null. Answerability yêu cầu mapped_hit>=1, seed>=1 và traversal; những count minima khác là 0, max limitations=null. Giữ đầy đủ 8 topical settings và 12 answerability settings.

Thay đổi có chủ đích chỉ là nguồn/version Ground Truth, content corpus/graph/index được đồng bộ và compatibility cần thiết. Chạy đúng 32 development cases đã dùng ở các lần trước, giữ approved labels. Không chạy 11 proposed probes, không chia lại 32 cases thành held-out và không tuyên bố có kiểm chứng độc lập.

## Kết quả trước/sau

Positive class là `proceed`, negative class là `abstain`. Confusion matrix theo nhãn dataset:

| Expected / Actual | Baseline proceed | Baseline abstain | FIX1 proceed | FIX1 abstain |
| --- | ---: | ---: | ---: | ---: |
| proceed | 5 | 11 | 5 | 11 |
| abstain | 1 | 15 | 2 | 14 |

| Metric | Baseline | FIX1 |
| --- | ---: | ---: |
| Accuracy | 20/32 = 62.50% | 19/32 = 59.38% |
| Precision | 5/6 = 83.33% | 5/7 = 71.43% |
| Recall | 5/16 = 31.25% | 5/16 = 31.25% |
| Specificity | 15/16 = 93.75% | 14/16 = 87.50% |
| F1 | 10/22 = 45.45% | 10/23 = 43.48% |
| False proceed unrelated | 0/8 = 0% | 1/8 = 12.50% |
| False proceed insufficient_evidence | 1/8 = 12.50% | 1/8 = 12.50% |
| Coverage | 6/32 = 18.75% | 7/32 = 21.88% |
| Selective error, theo dataset | 1/6 = 16.67% | 2/7 = 28.57% |
| False abstain, context đủ theo rubric | 8/13 = 61.54% | 8/13 = 61.54% |

Coverage tăng do thêm một false proceed ngoài phạm vi; không có true positive mới. Trong 32 cases, 6 giữ `proceed`, 25 giữ `abstain`, 1 chuyển `abstain→proceed`, 0 chuyển `proceed→abstain`. Có 31/32 ordered hit-source lists thay đổi. Mỗi returned evidence-ID list giữ nguyên trước/sau; các IDs chỉ thuộc hai core evidence groups, không khẳng định mọi context đều chứa cả hai. Sự hiện diện của ID không chứng minh đủ nội dung đáp ứng câu hỏi. [Per-case report](per_case_report.md) ghi query, layers, reasons, hits, evidence và signal deltas của từng case.

Case chuyển duy nhất là `ur-en-linux-cron`, expected `abstain`. Returned top cosine tăng `0.81452207→0.84683677`, token coverage tăng `0.15384615→0.23076923`, vượt cả hai ngưỡng cố định. Top-5 mới gồm `/facts/0`, `/facts/1`, `/mitre_assessments/1`, `/summary/limitations/6`, `/scenario`. Gate chỉ đọc các tín hiệu tổng hợp nên vẫn qua answerability dù câu hỏi ngoài phạm vi Linux cron. Không hardcode case ID/query/keyword để sửa kết quả này.

### Hai tầng gate

| Tầng / trạng thái thực tế | Baseline | FIX1 |
| --- | ---: | ---: |
| Topical passed / failed | 6 / 26 | 7 / 25 |
| Answerability passed / failed / not_evaluated | 6 / 0 / 26 | 7 / 0 / 25 |

| Confusion matrix trên evaluated-known labels | Baseline TP/TN/FP/FN | FIX1 TP/TN/FP/FN |
| --- | --- | --- |
| Topical relevance | 6/8/0/18 | 6/7/1/18 |
| Evidence answerability | 5/0/1/0 | 5/0/1/0 |

Topical có 32 known labels, tất cả được đánh giá. Answerability baseline có 24 known/8 unknown labels, 6 evaluated-known và 26 not_evaluated; FIX1 có 22 known/10 unknown, 6 evaluated-known và 25 not_evaluated. Có **7** cases thực tế qua answerability nhưng chỉ **6** có nhãn tầng này áp dụng; case unrelated mới qua gate có answerability label unknown. Không đưa case đó vào answerability confusion matrix như một true positive. Recall answerability 5/5 chỉ mô tả slice evaluated-known, không biểu diễn recall end-to-end. `not_evaluated` không phải pass hoặc fail.

### Context sufficiency và sự khác nhau giữa false/null

Rubric chẩn đoán cũ giữ nguyên tiêu chí; không dùng đáp án/expected evidence để bù context. Rubric là conservative AI support screen ngoài runtime, chưa phải nhãn human semantic evaluation mới. Với approved positive cases, kết quả trước là **13 true, 3 false, 0 null**; sau là **13 true, 1 false, 2 null**. Toàn bộ 32 cases sau có 13 true, 9 false (gồm 8 insufficient-evidence), 10 null (gồm 8 unrelated không áp dụng answerability).

Hai positives `rd-vi-reviewed-scope-limitations` và `rp-vi-service-action` đổi false→null. Baseline có factual marker `known_absent_from_frozen_consumers` do audit chứng minh nội dung vắng mặt trong consumers cũ. Nội dung hiện đã có trong consumers mới nên marker cũ không còn áp dụng. Actual context vẫn chưa có exact limitation support theo rubric, nên kết quả là **unassessed/null**, không được coi đã đủ hoặc biến thành false theo nhãn dataset. Không đổi tiêu chí rubric và không gộp hai unknown vào nhóm đủ context.

End-to-end context eligibility dùng 30 known/2 unknown cases sau FIX1: unrelated vẫn known ineligible nhờ topical scope dù answerability không áp dụng. Confusion matrix eligibility là TP=5/TN=15/FP=2/FN=8 trên 30 known cases; baseline là 5/18/1/8 trên 32. Accuracy tương ứng 20/30 = 66.67% và 23/32 = 71.88%; mẫu số khác nhau nên cần đọc cùng unknown counts. `dataset_answerable_context_failure_count` giảm 3→1 là giảm số **known false** cùng hai kết quả chuyển sang unknown, không phải sửa thành công cả ba context failures.

## Ba cases thiếu context: nguồn → consumers → runtime

[Focus analysis](../../experiments/graphrag-2d3-fix1/focus_case_analysis.json) kiểm tra riêng ba cấp. Full-consumer audit dùng ngoài gate để xác nhận dữ liệu hiện diện; không được truyền full corpus/graph hoặc expected units vào runtime.

| Case | Nguồn đã duyệt | Payload corpus/graph đầy đủ | Actual returned context | Gate |
| --- | --- | --- | --- | --- |
| `rd-vi-reviewed-scope-limitations` | Đủ cả 7 required limitations | Đủ theo rubric | Chỉ thỏa limitation 0 và 3; 1/2/4/5/6 unassessed | abstain, topical cosine thấp |
| `rp-vi-final-review-limits` | Đủ analysis_status và limitations 0–4 | Đủ theo rubric | Không trả `/scenario` analysis_status và không trả các limitation chunks cần thiết; known false | abstain, coverage và cosine thấp |
| `rp-vi-service-action` | Đủ original launch CommandLine và limitation 4 | Đủ theo rubric | CommandLine gốc đã được trả; limitation 4 chưa có exact support; null | abstain, coverage và cosine thấp |

Runtime hits của scope-limitations là limitations 0/3 và ba MITRE assessments; các limitation nodes khác không được chọn làm seeds. Case final-review-limits chỉ có ba MITRE assessments và hai facts, nên không nhận scenario/limitations cần thiết. Case service-action nhận `/scenario`, hai facts và hai MITRE assessments; original CommandLine trong `/facts/1/attributes/source_observations` được trả đúng giá trị/raw reference. Phần giới hạn về successful completion/output/service state vẫn chưa được rubric xác nhận đầy đủ từ context đó.

Graph hiện có limitation/scenario nodes không tự nối thêm edges; traversal từ core evidence không bảo đảm tới mọi limitation. Với top-5 cố định, một nội dung có trong corpus/graph vẫn có thể vắng trong actual context. Giới hạn này là retrieval/context coverage cần xử lý tiếp sau review, không phải lý do chèn expected evidence hoặc mở core sang proposed probes.

Kiểm tra toàn bộ 32 actual contexts cho thấy **mọi limitation đều đã đi được qua đường runtime ở ít nhất một query**. Số contexts trả limitation 0–6 lần lượt là **2, 3, 3, 2, 3, 1, 13**; fact 0 xuất hiện trong 32/32 contexts, fact 1 trong 30/32. Đây là bằng chứng transport hoạt động; không chứng minh từng query nhận đúng hoặc đủ các limitations mà query cần. [validation_results.json](../../experiments/graphrag-2d3-fix1/validation_results.json) lưu các counts cùng JSON/validator checks và saved context→signals→decision replay; replay đó không phải thí nghiệm độc lập.

## Case URL và cơ chế answerability còn thiếu

`ie-en-payload-download-url` vẫn `proceed`, context_sufficient=false theo nhãn câu hỏi thiếu bằng chứng. Top cosine sau rebuild `0.85918457` và coverage `0.53846154` đều qua ngưỡng. Top-5 mới trả scenario, T1218.005 assessment, hai facts và limitation 6; không có evidence xác lập payload-download URL. Đổi content/provenance đúng không tự sửa khả năng phân biệt yêu cầu này.

Answerability hiện chỉ kiểm tra cấu trúc như mapped hits, seeds và traversal; các count này không xác định evidence có đáp ứng yêu cầu **URL** hay không. Cần bổ sung cơ chế answerability theo yêu cầu câu hỏi, có liên kết giữa requested claim/field và evidence thực sự trả về, đồng thời tiếp tục xử lý false topical acceptance của câu ngoài phạm vi. Đây là kết luận từ development diagnostics, chưa triển khai cơ chế mới, không đề xuất một blacklist case ID/từ khóa hoặc threshold mới trong FIX1.

## Kiểm thử, hashes và giao nộp

Các lệnh build/compare đã chạy:

```powershell
.\.venv\Scripts\python.exe scripts/sync_ground_truth_v2_consumers.py --phase build
.\.venv\Scripts\python.exe scripts/sync_ground_truth_v2_consumers.py --phase compare
```

Focused tests, regression và full suite cùng exact commands/counts/failed attempts được ghi tại [tests.json](tests.json). Không lấy historical counts làm số tests của lượt FIX1. Bộ tests mới kiểm tra v1 compatibility/v2 provenance, unsupported versions, approval isolation, original fields tới actual context, stale bindings, graph references, determinism và overwrite protection. Integration tests dùng synthetic data/fake vectors, không gọi model thật.

Focused cuối: **85 passed**, 0 failed/skipped, 7.81s. Regression liên quan: **2.541 passed**, 0 failed/skipped, 66.91s. Full suite cuối: **5.900 passed + 6 subtests passed**, **0 failed/skipped**, 607.97s. Exact commands và các lượt trước nằm trong `tests.json`.

[Review inventory](review_inventory.json) là nguồn cho snapshot thay đổi, hashes trước/sau của raw data, approved bundle, old corpus/graph/index, old review artifacts/ZIP, Git staging/working tree, diff checks và ZIP payload validation. Các hashes FIX1 ở bảng trên là hashes build output thực tế. Gói giao nộp là `outputs/review/graphrag_ground_truth_v2_consumer_sync_review.zip`; không thay ZIP cũ.

Đối chiếu cuối ghi nhận **5.055 baseline files: 5.048 giữ nguyên hash, đúng sáu compatibility source files và phần append `PROJECT_PROGRESS.md` thay đổi**. Toàn bộ bytes cũ của file tiến độ được bảo toàn làm prefix. Raw inputs, approved bundle, old corpus/graph/index và review artifacts/ZIP cũ giữ nguyên bytes. Các outputs/tests/scripts mới không được tính như một file baseline đã đổi. [Bảng hashes chính](protected_hash_summary.md) ghi SHA-256 trước/sau; bảng đầy đủ 5.055 files nằm trong `protected_hashes_after.json` ở thư mục experiment.

Gói ZIP được kiểm tra entries an toàn/duy nhất, regular files, không symlink/path traversal, `testzip() == None` và payload sizes/hashes khớp nguồn. [zip_verification.json](zip_verification.json) ghi hash archive/inventory và từng entry; sidecar nằm ngoài ZIP để tránh vòng self-hash. `git diff --check` sạch, staging rỗng, branch/HEAD giữ nguyên.

**Trạng thái cuối:** sync source/version và evidence payload đã đạt; runtime context coverage và policy quality chưa đạt. Việc sửa dữ liệu giữ 5 true positives và làm tăng false proceed từ 1 lên 2, không có bằng chứng cải thiện gate. Cần review các runtime gaps cùng regression, sau đó quyết định bước thiết kế answerability theo yêu cầu và cơ chế retrieval trả limitations phù hợp. Dừng để review; chưa tích hợp production CLI/LLM/UI, chưa chạy proposed probes hoặc held-out validation.
