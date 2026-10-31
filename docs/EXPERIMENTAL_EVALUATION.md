# Experimental checkpoint và đánh giá regression

> **Trạng thái hiện tại — đã đóng thực nghiệm.** Hai lượt live đã được tổng hợp tại `outputs/review/rag_graphrag_combined_semantic_20261027/`; recheck tại `rag_gate_contract_recheck_20261027/` chỉ xác minh tái lập offline. Các lệnh `--live`, cap12/pilot và câu “chưa thực thi live” bên dưới thuộc kế hoạch lịch sử, **không còn là bước cần chạy hoặc yêu cầu trước khi nộp**. Không chạy thêm pilot/full live, calibration hoặc generation. Dùng [kết quả đã chốt](EXPERIMENTAL_RESULTS.md), [demo saved outputs](EXPERIMENTAL_DEMO.md) và [checklist tích hợp](EXPERIMENTAL_SUBMISSION_CHECKLIST.md) cho công việc hiện tại. Giữ nội dung lịch sử để truy vết.

Ngày chốt: 27/10/2026, Asia/Bangkok. Thư mục review được tạo ngày 26/10 và giữ tên `outputs/review/experimental_checkpoint_20261026/`. Đây là kiểm tra triển khai hiện có theo yêu cầu hiện tại; mô tả LLM/UI chưa triển khai trong `PROJECT_CONTEXT.md` ngày 14/10 là lịch sử. Không nâng approval hoặc technique labels.

## Thiết kế được giữ cố định

Hai nhánh dùng cùng effective `server.SCENARIO_REGISTRY`, corpus/index, 15 queries nguyên bản, local E5 revision, hybrid BM25 + cosine/RRF, top_k=5/candidate_k=20, prompt/schema, model/provider, generation config và strict validator. RAG chỉ nhận retrieval hits; GraphRAG bổ sung seed mapping và traversal both/depth=2/nodes=100/edges=200. Validator nhận đúng context mà generator nhận, không nhận toàn graph hoặc GT bổ sung cho RAG. Corpus có relationship/fact/evidence chunks nên baseline là hybrid RAG trên evidence corpus có cấu trúc.

Policy không đổi, hiện yêu cầu seeds và traversal. Vì vậy RAG retrieval-only bị chặn theo cấu trúc. **Đây là blocker cho kết luận so sánh chất lượng câu trả lời RAG–GraphRAG end-to-end.** Giữ báo cáo retrieval/context tách khỏi gate/generation; không coi RAG abstain là bằng chứng GraphRAG vượt trội. Không tạo seeds giả, không bỏ gate để cải thiện điểm. Harness dùng scope anchors corpus-only chung cho hai nhánh, khác POST production vốn đọc cả corpus và graph; công khai khác biệt này.

Context có cùng giới hạn 262144 canonical UTF-8 bytes; messages có cùng giới hạn 294912 bytes, không gọi là token count. Không truncate tùy ý. Vượt budget thì final eligibility abstain, lưu `eligibility.json`; giữ nguyên policy decision trong `gate.json`. Model/provider giữ `generic_openai` / `openrouter/gemma-4-31b-it`, temperature 0, max_tokens 2048, timeout 120s theo cấu hình thực tế. Manifest lưu config an toàn; không chứa key, headers hoặc nội dung environment file.

## Chấm bốn phần riêng

Giữ nguyên `outputs/review/live_llm_functional_smoke/cases.json`, SHA-256 `d5e54b9396e43ffdf4dcdf27989537bfe55d5186d6ab9074a661dece8435fad3`. Có 9 answerable, 3 overreach, 3 out_of_scope. Đây là regression benchmark đã dùng để sửa lỗi, không phải held-out/independent validation. Lịch sử và rubric không đưa vào runtime prompt/gate. PS01/RG01 còn criteria host lịch sử mâu thuẫn corrected artifacts; ghi conflict khi review, không sửa lại bộ cũ hoặc ép model dùng host sai.

1. **Retrieval/context:** điền `manual_review.json` trên bản sao: relevance từng hit; sufficiency cho đúng câu hỏi; coverage của factual anchors/limits; nguồn và fields hỗ trợ. Mẫu số relevance là số hits đã review, sufficiency là số context đã review; báo riêng các ca bị scope chặn trước retrieval. Không coi exact citation ID tồn tại là semantic support. `paired_retrieval_audit.json` chỉ xác minh hai nhánh có cùng ranked hits, không chứng minh hits đúng. `context.json` giữ scores, metadata, nodes/edges/paths; các counts và dung lượng không thay thế chấm nội dung.
2. **Gate:** mandatory accuracy = (TP+TN)/12; false abstain = FN/9 answerable; false proceed = FP/3 out_of_scope. Báo cả assessed/planned để runtime errors không biến mất khỏi mẫu số. Ba overreach cho phép abstain hoặc proceed với câu trả lời giới hạn bằng chứng, nên báo riêng, không ép thành negative. Báo policy coverage và final eligibility coverage trên 15 câu/nhánh, tách budget rejection.
3. **Answer/citation:** chỉ `accepted_draft` là đầu ra qua structured validation, vẫn cần review toàn prose/verdict/recommendations. Dùng nguyên pass/partial/fail/needs_human_review và supported/partial/unsupported/missing/not_applicable/needs_human_review của rubric cũ. Answer accuracy = số pass / số accepted drafts được chấm đủ, báo số partial/fail/unreviewed riêng. Citation accuracy = số supported / số accepted drafts có yêu cầu citation và được chấm; N/A loại khỏi mẫu số và công khai count. Successful supported coverage = số accepted drafts được review là pass và citation phù hợp / 15 planned cases. Không tính rejected output, fallback hoặc provider errors là LLM success. Trong dry-run không có generation nên accuracy để null/pending; accepted coverage 0 chỉ nói chưa sinh câu trả lời.
4. **Provider/time:** đếm từng outcome và HTTP attempt; tỷ lệ provider/rate-limit failures trên số attempts, báo attempts/planned/eligible. `end_to_end_seconds` gồm local loading/query embedding/retrieval/gate/prompt/generation/validation và ghi artifacts trước result; warmup model báo riêng. Dry-run latency không phải LLM latency hoặc latency browser. Protocol/connection/timeout là provider_error; JSON/schema/guardrail rejection là validation_failed. Không gộp hai loại thành evidence insufficiency.

Lưu `raw_model_output.json` và `raw_report_before_sanitize.json` trước schema/guardrail cho lượt tương lai; key được redact nếu model vô tình trả lại. `validation.json` giữ pre/post-sanitize, issues/reference checks và unverified_fields; JSON/schema failure có diagnostic riêng. MS01 lịch sử vẫn thiếu giá trị trước sanitize, không thể phân định model hay validator sai bằng replay sanitized report. Giữ rejection đó.

`accepted_draft`, `validation_failed`, `abstain`, `provider_error`, `rate_limited`, `fallback`, `dry_run_no_generation`, `runtime_error`, `not_run_request_limit`, `not_run_after_stop` được phân biệt. Harness này không sinh fallback. Semantic metrics chưa chấm giữ null, không lấy constants từ benchmark demo.

## Phạm vi dữ liệu và kết luận

MSHTA chỉ có hai behavior groups và bốn observations cốt lõi; VBScript không thành JavaScript; launch không chứng minh completion/output/service state. PurpleSharp hiện là launch slice và bốn `/t` arguments, không chứng minh spraying/Kerberoasting hoặc toàn playbook thành công; verdict SUSPICIOUS của PS02 còn cần human review. Regsvr32 chỉ hỗ trợ selected process/connection evidence, không chứng minh HTTP completion, transferred content, exfiltration/bytes hoặc mục đích C2. Giữ timestamp conflicts, candidate mappings và approval metadata hiện có.

Cả 10 original Mordor/Sigma/STIX inputs hiện không tìm thấy trong checkout. Chỉ kiểm tra lại pinned derived consumers/canonical provenance có sẵn; không thay input tương tự và không tuyên bố fresh raw audit. MSHTA approved bundle hiện có được giữ nguyên; corrected PurpleSharp/Regsvr32 vẫn pending_human_review. Không nâng trạng thái từ technical tests.

Loại hoàn toàn `scripts/evaluate_rag_triad_benchmark.py` (hardcoded quality metrics), `GET /api/hunt/stream` (sample_analysis/fixed verdict), kết quả demo và lịch sử corrective runs khỏi điểm phép đo mới. Không xóa hoặc sửa các artifacts lịch sử đó.

## Lệnh CMD

Từ CMD, dùng thư mục output mới; harness cố ý từ chối ghi đè kết quả cũ. Không cần bật production backend để chạy harness trực tiếp.

```bat
cd /d D:\rag-graphrag-friend
.venv\Scripts\python.exe scripts\evaluate_rag_graphrag.py --config configs\evaluation\experimental_comparison.json --output outputs\experiments\rag-graphrag-regression-offline-01
```

Lệnh trên là offline, tối đa **0 request LLM**, cần E5 revision đã cache cục bộ. Không download model.

Chỉ dùng lệnh sau khi người dùng quyết định thực hiện lượt live sau này; **chưa chạy trong nhiệm vụ này**. Router/provider đã cấu hình tại `http://127.0.0.1:20128/v1` cần đang hoạt động; không đổi provider/model hoặc environment file.

```bat
cd /d D:\rag-graphrag-friend
.venv\Scripts\python.exe scripts\evaluate_rag_graphrag.py --config configs\evaluation\experimental_comparison.json --output outputs\experiments\rag-graphrag-regression-live-01 --live --max-requests 12
```

Giới hạn lệnh là **12 HTTP attempts LLM tổng cộng**, tuần tự, một attempt/eligible case, không retry hoặc fallback. Checkpoint hiện có 12 eligible GraphRAG và 0 eligible RAG; 18 nhánh abstain không gọi LLM. Trần lý thuyết của harness là 30 (15×2), nhưng lệnh này không vượt 12. 401/403/429 dừng toàn lượt, lưu reason và đánh các ca còn lại not_run_after_stop; không sleep/retry 429. Other provider errors được ghi riêng rồi đi tiếp tới ca kế, vẫn trong cap. Không quan sát được retry nội bộ router/upstream và không suy bằng 0.

Khởi động lại UI QA replay an toàn nếu cần:

```bat
cd /d D:\rag-graphrag-friend
.venv\Scripts\python.exe scripts\serve_ui_replay.py --port 8001
```

Mở `http://127.0.0.1:8001/qa.html?case=MS01`. Dịch vụ phục vụ build và fixtures; không có POST LLM hoặc SSE. Hướng dẫn tám trạng thái và chụp thủ công tại `outputs/review/experimental_checkpoint_20261026/ui/manual_screenshots.md`. Browser automation bị URL policy của Cốc Cốc chặn, nên chưa kiểm tra click/download/layout trong browser và chưa có ảnh thật. Không đổi nhãn replay thành live.

Tái tạo inventory/package ở đường dẫn mới bằng `scripts\checkpoint_experimental.py --output <new-review-dir>\manifest.json` và `scripts\package_experimental_checkpoint.py --output <new-review-dir>\experimental_source_artifacts.zip`. ZIP không gồm environment file, credentials hoặc model weights. Giữ pin/revision trong manifest và dùng keys hiện có riêng, không đưa chúng vào package.


## Cập nhật source-evidence contract — 27/10/2026

Kế hoạch gate/cap12 ở các mục trên mô tả checkpoint legacy, được giữ làm lịch sử. Review mới: outputs/review/rag_gate_contract_20261027/report.md và per_case_report.md. Experimental source contract mới áp dụng cùng requirements và witness/provenance checks cho cả hai nhánh; không giả nodes/traversal cho RAG. Production gate file, topical cosine/hit thresholds, prompt/schema/guardrail và old config giữ nguyên. Dùng explicit configs/evaluation/experimental_comparison_evidence.json để chọn contract mới; default cũ vẫn replay được legacy semantics.

Offline30 cuối: RAG8 proceed/7 abstain, GraphRAG9/6; 17 eligible branches tổng cộng,0 LLM requests. 24 contexts/messages và12 paired hybrid retrievals không đổi so checkpoint. MS03 thiếu core boundary; RG02 RAG có URL summary nhưng thiếu actor-bound raw command fields; PS04/RG04 thiếu explicit limit witnesses theo contract máy mặc dù rubric cũ cho phép scoped limited answer. Không đồng nhất mọi rejection với thiếu nội dung thật, và không coi gate proceed là answer correctness.

Pilot chọn trước: PS02,RG03, tối đa4 requests, kiểm tra vận hành; pilot_dry_run xác minh4 branches eligible với0 LLM attempts. CMD từ D:\rag-graphrag-friend: .venv\Scripts\python.exe scripts\evaluate_rag_graphrag.py --config configs\evaluation\experimental_comparison_evidence.json --case-ids PS02,RG03 --live --max-requests 4 --output outputs\experiments\rag-graphrag-pilot-source-contract-01 . Chưa thực thi live. Gate chặn thì không gọi và không thay ca;401/403/429 dừng, không retry/fallback.

Cap12 không đủ17 eligible branches của full set. Source-contract live từ chối cap nhỏ hơn số planned branches của tập case pairs chọn trước, trước retrieval/provider; không cắt12 nhánh đầu. Full15 pairs có thể dùng cap30 (checkpoint này dự kiến17 actual attempts), hoặc subset đầy đủ pairs được xác định trước. Không auto-resume. Lệnh offline đầy đủ: .venv\Scripts\python.exe scripts\evaluate_rag_graphrag.py --config configs\evaluation\experimental_comparison_evidence.json --output outputs\experiments\rag-graphrag-source-contract-offline-01 .

Rubric review kỹ thuật nằm ngoài runtime, vẫn cần human review; không independent validation, không kết luận chất lượng generation hơn-kém. 284 relevant tests passed, không full suite/build frontend vì không đổi frontend. Không tạo ZIP mới, không đổi environment/model/provider/approval.
