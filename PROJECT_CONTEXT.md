> Distribution note: this is the staged handover copy. Inputs are now included under data/. See START_HERE.md and packaging/path_migration.json for portable paths; dated instructions below describe earlier tasks.

# HỒ SƠ TRẠNG THÁI ĐỒ ÁN TỐT NGHIỆP

**Cập nhật gần nhất:** 31/10/2026 — hồ sơ bàn giao, Asia/Bangkok

**Sinh viên:** Nguyễn Hồng Phong  
**Mã sinh viên:** AT190540  
**Lớp theo đề cương chính thức:** AT19ET  
**Ngành:** An toàn thông tin - Mã ngành 7.48.02.02  
**Cơ sở đào tạo:** Học viện Kỹ thuật Mật mã  
**Giảng viên hướng dẫn:** TS. Phạm Văn Hưởng, Khoa Công nghệ thông tin  
**Tên đề tài hiện tại:** **Nghiên cứu mô hình kết hợp RAG, GraphRAG, LLM và ứng dụng truy tìm mối đe dọa ATTT**

> Tài liệu này là hồ sơ làm việc thống nhất để tiếp tục đồ án. Khi có xung đột, ưu tiên theo thứ tự: văn bản chính thức mới nhất → tài liệu mô hình/triển khai → quyết định rõ ràng của sinh viên trong trao đổi → đề xuất tham khảo. Các lựa chọn chưa được chốt được ghi riêng, không coi là phần đã hoàn thành.

## 1. Phạm vi được xác nhận

Đồ án hiện tại tập trung xây dựng và đánh giá một **hệ thống/trợ lý hỗ trợ truy tìm mối đe dọa an toàn thông tin** bằng cách kết hợp:

- **RAG:** truy xuất tài liệu và tri thức bảo mật có liên quan.
- **GraphRAG:** truy xuất các quan hệ nhiều bước giữa thực thể trong log và tri thức bảo mật.
- **LLM:** tổng hợp ngữ cảnh, phân tích, diễn giải, ánh xạ MITRE ATT&CK và gợi ý điều tra.

Đồ án **không nhằm huấn luyện lại LLM**. LLM được dùng như thành phần phân tích và sinh câu trả lời dựa trên ngữ cảnh đã được truy xuất.

**Hiện trạng ngày 31/10/2026:** đã có integrated consumers cho cả ba kịch bản, MITRE/Sigma/CTI, E5 retrieval, graph, evidence gate, generation/validation và dashboard ba cột. Bộ cuối v7 chưa hoàn tất: 8 abstain, 1 provider_error, 15 not_run; chưa có generated answer. Working source hiện khác pin v7. Xem trạng thái và kiến trúc dưới đây cùng [HANDOVER.md](HANDOVER.md).

Các dự án NIDS/CIC-IDS-2017, SOC lab, Solana, Hyperledger Fabric/OpenSSL và IAM/Keycloak **không thuộc phạm vi đồ án hiện tại**, trừ khi sau này sinh viên đưa ra quyết định tích hợp rõ ràng. Trong đó, dự án học sâu chống truy cập mạng trái phép hiện được xem là một dự án riêng, không gộp vào đề tài RAG/GraphRAG/LLM.

## 2. Bài toán và lý do chọn đề tài

- Threat Hunting cần chủ động tìm hành vi tấn công có thể chưa bị cơ chế cảnh báo truyền thống phát hiện.
- Dữ liệu log, cảnh báo và tài liệu tình báo mối đe dọa có khối lượng lớn, làm phân tích thủ công tốn thời gian và phụ thuộc mạnh vào kinh nghiệm chuyên gia.
- LLM có khả năng phân tích và diễn giải bằng ngôn ngữ tự nhiên nhưng có ba hạn chế chính: tri thức có thể không cập nhật, nguy cơ hallucination và khó khai thác quan hệ phức tạp giữa nhiều thực thể bảo mật.
- RAG bổ sung tri thức ngoài mô hình; GraphRAG bổ sung khả năng truy vấn quan hệ và suy luận nhiều bước; LLM tổng hợp hai nguồn ngữ cảnh để tạo kết quả dễ hiểu.
- Trọng tâm nghiên cứu không chỉ là tạo chatbot, mà là kiểm chứng xem mô hình kết hợp có hỗ trợ phân tích mối đe dọa tốt hơn hay không.

## 3. Mục tiêu

### 3.1. Mục tiêu tổng quát

Nghiên cứu, đề xuất và xây dựng hệ thống thử nghiệm kết hợp RAG, GraphRAG và LLM cho bài toán truy tìm mối đe dọa ATTT; sau đó thực nghiệm và đánh giá mô hình trên các kịch bản cụ thể.

### 3.2. Mục tiêu cụ thể

1. Nghiên cứu nền tảng LLM, RAG, GraphRAG và Threat Hunting.
2. Đề xuất kiến trúc kết hợp RAG + GraphRAG + LLM.
3. Xây dựng quy trình xử lý log, kho tri thức bảo mật và đồ thị tri thức.
4. Xây dựng hệ thống thử nghiệm triển khai mô hình.
5. Thử nghiệm trên các kịch bản truy tìm mối đe dọa.
6. Đánh giá độ chính xác, tính đầy đủ, khả năng giải thích và mức độ hỗ trợ chuyên viên phân tích.

## 4. Đề cương ba chương hiện tại

### Chương 1. Tổng quan về RAG, GraphRAG, LLM và truy tìm mối đe dọa ATTT

**1.1. Bài toán truy tìm mối đe dọa an toàn thông tin**

- 1.1.1. Khái niệm và vai trò của truy tìm mối đe dọa trong SOC
- 1.1.2. Nguồn tri thức và dữ liệu phục vụ phân tích mối đe dọa

**1.2. Mô hình ngôn ngữ lớn và kỹ thuật RAG**

- 1.2.1. Khả năng và hạn chế của LLM trong miền ATTT
- 1.2.2. Kiến trúc và quy trình hoạt động của RAG
- 1.2.3. Vai trò của RAG trong bổ sung tri thức chuyên ngành

**1.3. Đồ thị tri thức và GraphRAG**

- 1.3.1. Biểu diễn tri thức ATTT dưới dạng đồ thị
- 1.3.2. Cơ chế truy xuất quan hệ trong GraphRAG
- 1.3.3. So sánh RAG truyền thống và GraphRAG trong phân tích bảo mật

**1.4. Giải pháp kết hợp LLM, RAG, GraphRAG để truy tìm mối đe dọa ATTT**

- 1.4.1. Sự cần thiết của việc kết hợp
- 1.4.2. Khung ý tưởng ứng dụng mô hình kết hợp

**Kết luận Chương 1**

### Chương 2. Phân tích và thiết kế hệ thống truy tìm mối đe dọa ATTT sử dụng mô hình kết hợp RAG, GraphRAG, LLM

**2.1. Phân tích bài toán và thiết kế kiến trúc**

- 2.1.1. Phạm vi, đối tượng và yêu cầu hệ thống
- 2.1.2. Kiến trúc tổng thể của hệ thống
- 2.1.3. Luồng xử lý dữ liệu và phân tích mối đe dọa

**2.2. Thiết kế dữ liệu và cơ sở tri thức**

- 2.2.1. Thu thập và chuẩn hóa dữ liệu log
- 2.2.2. Xây dựng nguồn tri thức từ MITRE ATT&CK, Sigma Rule và CTI report
- 2.2.3. Thiết kế đồ thị tri thức phục vụ truy tìm mối đe dọa

**2.3. Thiết kế mô hình phân tích kết hợp RAG, GraphRAG và LLM**

- 2.3.1. Thiết kế RAG pipeline
- 2.3.2. Thiết kế GraphRAG pipeline
- 2.3.3. Cơ chế phối hợp truy xuất giữa RAG và GraphRAG
- 2.3.4. Thiết kế prompt và định dạng đầu ra phân tích

**Kết luận Chương 2**

### Chương 3. Xây dựng, thử nghiệm và đánh giá hệ thống

**3.1. Môi trường triển khai và dữ liệu thực nghiệm**

- 3.1.1. Công nghệ và công cụ sử dụng
- 3.1.2. Bộ dữ liệu log và nguồn tri thức sử dụng

**3.2. Xây dựng các thành phần của hệ thống**

- 3.2.1. Module xử lý log và trích xuất thực thể
- 3.2.2. Module RAG và GraphRAG
- 3.2.3. Module phân tích kết quả bằng LLM

**3.3. Thực nghiệm trên các kịch bản truy tìm mối đe dọa**

- 3.3.1. Brute force và đăng nhập bất thường
- 3.3.2. Thực thi PowerShell nghi vấn
- 3.3.3. Kết nối mạng bất thường hoặc nghi vấn C2

**3.4. Đánh giá kết quả thực nghiệm**

- 3.4.1. Đánh giá kết quả truy tìm mối đe dọa
- 3.4.2. Đánh giá độ chính xác, tính đầy đủ và khả năng giải thích
- 3.4.3. Đánh giá khả năng hỗ trợ chuyên viên phân tích ATTT
- 3.4.4. Ưu điểm, hạn chế và hướng cải tiến

**Kết luận Chương 3**

## 5. Trạng thái hiện hành và các phiên bản


**Bộ cuối chưa hoàn tất nghiệm thu.** Cấu hình so sánh mới nhất là [integrated_final_direct_v7.json](configs/evaluation/integrated_final_direct_v7.json), generation pin là [runtime_pin.json](outputs/final/20261031_direct_v7/runtime_pin.json). Bộ này dùng consumers **v5**, gate `source-evidence-contract/v2` và generation `source-meaning/v3`; số v7 không có nghĩa là có consumers v7.

**Working source đã khác pin:** đọc hash hiện tại thấy bốn tệp thay đổi: [run_final_experiment.py](scripts/run_final_experiment.py), [experimental_comparison.py](src/threat_hunting/evaluation/experimental_comparison.py), [final_experiment.py](src/threat_hunting/evaluation/final_experiment.py), [client.py](src/threat_hunting/llm/client.py); thêm [error_diagnostics.py](src/threat_hunting/llm/error_diagnostics.py) chưa có trong pin. Code mới có chẩn đoán lỗi đã lọc, stop HTTP402, continuation và xác nhận vận hành sau HTTP402. [http402_recovery_20261031_v1](outputs/offline/http402_recovery_20261031_v1/) hiện chỉ có `before_hashes.json`, chưa thấy execution delta pin/báo cáo/test results hoàn tất. Không gọi phần sửa này là đã kiểm chứng hoặc tự quay lui các thay đổi của người dùng.

Do kiểm tra full code manifest, **lệnh CLI/dashboard ghép working source hiện tại với pin v7 cũ sẽ bị chặn**. Báo cáo v7 mô tả code tại thời điểm khóa pin, không chứng minh source hiện tại khớp pin. Cần hoàn thiện migration pin ở công việc 1 bên dưới; không bỏ kiểm tra hash để chạy.

| Lớp kiểm chứng | Kết quả và giới hạn |
| --- | --- |
| Đã triển khai | Parser/normalization; evidence/correlation ba kịch bản; safe Sigma/STIX; CTI ingestion; corpus/JSON graph/E5 index; hybrid retrieval, graph traversal, evidence gate; LLM client/prompt/validation; harness/ledger; dashboard ba cột. |
| Đã kiểm chứng offline tại checkpoint | V7 preflight 24 nhánh, 16 eligible, 8 abstain, 0 HTTP attempts; RAG 5 eligible, GraphRAG 11. Đây là eligibility, không phải semantic accuracy. |
| Live v7 thực tế | Một request AUTH-DIRECT/RAG trả HTTP402, không có model text; dừng thủ công trước request 2. Checkpoint gốc chỉ có **1 row**. |
| Closeout dẫn xuất v7 | 24 rows/12 pairs: **0 accepted_draft, 0 validation_failed, 8 abstain, 1 provider_error, 15 not_run**. Generation quality/citation score: **N/A**. |
| Dashboard | V5 có ảnh/QA thật trong artifacts lịch sử; v7 có HTTP/replay QA 24 trạng thái, chưa visual QA/screenshot của profile cuối. Không khẳng định localhost còn chạy ở thời điểm nhận bàn giao. |
| Chưa nghiệm thu | Working source/pin migration mới, generation end-to-end nhất quán, review nội dung/citation, holdout độc lập, dashboard cuối và báo cáo luận văn đồng bộ. |

Nguồn: [report.md](outputs/final/20261031_direct_v7/report.md), [results.json](outputs/final/20261031_direct_v7/results.json), [results.csv](outputs/final/20261031_direct_v7/results.csv), [live checkpoint](outputs/experiments/integrated-final-direct-v7-live-01/results.json), [operational_stop.json](outputs/final/20261031_direct_v7/operational_stop.json), [request_budget.json](outputs/final/20261031_direct_v7/request_budget.json). Ledger giữ **1/20** attempts (initial 1/16, recovery 0/4), không reset. Error body của request cũ không được lưu; chưa có bằng chứng kết luận nguyên nhân chi tiết của HTTP402.

### Các bộ thực nghiệm không được trộn

Số dưới đây được đọc riêng từ `results.json` của từng thư mục trong [outputs/experiments](outputs/experiments/). `planned` không đồng nghĩa mọi nhánh đã gọi LLM.

| Thư mục | Trạng thái thực tế |
| --- | --- |
| `rag-graphrag-pilot-source-contract-01` | Live 4 requests, 4 provider_error; diagnostic lịch sử. |
| `rag-graphrag-pilot-source-contract-02` | Live 4/4 branches, 4 accepted_draft; vẫn cần semantic review. |
| `rag-graphrag-remaining-source-contract-01` | Đủ 26 status rows: 26 planned, 13 eligible/requests, **9 accepted_draft, 4 validation_failed, 13 abstain**. |
| `integrated-12x2-live-v5` | 24 rows, 16 requests: 4 accepted_draft, 8 abstain, 12 provider_error. |
| `integrated-12x2-v5-provider-recovery-01` | Recovery 12 planned, 10 requests: 8 accepted_draft, 1 validation_failed, 1 provider_error, 2 not_run; dừng HTTP503. Không cộng như 12 câu hỏi mới. |
| `integrated-v5-pending-three-live-02` | 3 planned, 2 requests: 1 validation_failed, 1 provider_error, 1 not_run; dừng HTTP503. |
| `integrated-v6-fix-validation-dryrun`, `integrated-v6-targeted-delivery-dryrun` | Mỗi bộ 5 eligible/0 requests; chưa phải live v6. |
| `integrated-final-direct-v7-dryrun-01` | 24 planned/16 eligible/0 requests. |
| `integrated-final-direct-v7-live-01` | Partial: 1 request/1 provider_error, chưa hoàn tất 24 status rows ở checkpoint gốc. |

Các thư mục v5 có tên `recovery-dryrun`, `checkpoint-recovery-dryrun-v2`, `pending-three-final-dryrun`, `three-delivery-dryrun` đều là dry-run 0 attempts. [Integrated v1–v4](outputs/integrated/) là diagnostic builds/preflights; v5 là nền consumers; v6 là corrective source-meaning checkpoint, không phải một benchmark generation mới hoàn tất. Các `graphrag-2d3-fix1/fix2/fix3` là nghiên cứu gate cũ. Không dùng metric hardcode từ [evaluate_rag_triad_benchmark.py](scripts/evaluate_rag_triad_benchmark.py) hoặc trang demo làm kết quả đo.

## 6. Kiến trúc, dữ liệu và bản đồ dự án

Ba nguồn OTRF Security Datasets/Mordor là `purplesharp_ad_playbook_I_2020-10-22042947.json` (25.993 records), `cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json` (1.127) và `empire_launcher_sct_regsvr32_2020-07-21232741.json` (2.390). Cả ba JSONL và canonical hashes/counts được kiểm lại ở lượt bàn giao, tổng 29.510 → 29.510, dropped=0. Mười external inputs gồm ba logs, sáu SigmaHQ được liệt kê trong AGENTS và một ATT&CK bundle. Nguồn MITRE STIX2.1 được pin **v19.1**, commit `6c3719993d0401de199203ecc3f369544d9e091c`, SHA-256 `bdf1ce86a4e604214c5076d37ae4dcb322678afc528df8492e6fdc1b554f5da3`.

Canonical `canonical-event/v2` giữ source_file/raw_record_ref, event/provider/host/timestamps, user roles, process/parent IDs/GUIDs/commands và network/file/registry/DNS khi source hỗ trợ; absent scalar dùng null. Mapping phụ thuộc provider+Event ID, không ép Sysmon10 source/target thành parent-child. Các raw authentication/ticket fields bổ sung do survey/extractor giữ lại. Correlation password-spray đã triển khai với derived rule, không còn chỉ là ý tưởng. Ba CTI sources thực tế là Red Canary MSHTA, Microsoft password spraying và Uptycs Regsvr32, mỗi source có snapshot/text hashes và citation offsets.

Luồng kiến trúc: raw/canonical → evidence và inferred correlations → candidate Sigma/MITRE assessments cùng CTI riêng → reviewable GT → corpus/JSON graph/E5 index → cùng hybrid retrieval → RAG returned chunks hoặc GraphRAG seeds/traversal → source-evidence gate → prompt → LLM client → structured/bounded narrative validation → draft/rejected và source artifacts → dashboard. Không dùng vector/graph database service. `source-evidence-contract/v2` xét supplied source objects cho cả hai nhánh; legacy topology gate là diagnostic ở integrated path. `source-meaning/v3` là generation contract của v7. Tên file policy “production” không thay nghiệm thu độc lập.

| Vị trí | Vai trò |
| --- | --- |
| [src/threat_hunting](src/threat_hunting/) | `mordor`, `schemas`, normalizer/discovery; `evidence` authentication/process_network/integrated; `sigma`, `mitre`, `ground_truth`, `cti`; `retrieval`, `graph`, `graphrag`; `llm`, `evaluation`, `server`. |
| [scripts](scripts/) | Inspection/normalization; builders cho ba scenario và integrated consumers; query/calibration; evaluation/final runner; pinning và dashboard server. Script builder/verify có thể ghi outputs: đọc trước khi chạy. |
| [pyproject.toml](pyproject.toml) | Python >=3.11; PyYAML 6.0.3, sentence-transformers 6.1.0, pytest 9.1.1; python-dotenv hiện chưa pin trong file. FastAPI/uvicorn/pydantic chưa được khai báo trực tiếp ở đây. |
| [frontend/package.json](frontend/package.json), [package-lock.json](frontend/package-lock.json) | React/TypeScript/Vite, Cytoscape; giữ lockfile. Python package 0.1.0/frontend 2.0.0 không thay thế runtime SHA-256. |
| [mordor_selected_v2.json](configs/experiments/mordor_selected_v2.json), [canonical manifest](outputs/canonical/mordor-selected-v2/manifest.json) | Ba raw JSONL 25.993 + 2.390 + 1.127 → 29.510 canonical, dropped=0. Inputs gốc nằm ngoài checkout; xem packaging. |
| [mitre manifest](configs/knowledge/mitre_enterprise_attack.json) | ATT&CK STIX 2.1 v19.1, commit và bundle hash đã khóa. Sáu SigmaHQ YAML là external inputs; [derived correlation](configs/knowledge/derived/win_security_password_spray_correlation.yml) thuộc đồ án. |
| [requirements gap](outputs/offline/requirements_gap_20261030_v1/) | Authentication survey/correlation v2 và CTI Red Canary/Uptycs: HTML snapshots, extracted text, metadata/offsets. |
| [integrated v5](outputs/integrated/20261030_v5/), [v1 CTI snapshot](outputs/integrated/20261030_v1/cti_auth_sources/) | Full Regsvr32 survey; Microsoft password-spray CTI corpus/text ở `v5/cti_auth/`, HTML ở v1. Không bỏ v1 chỉ vì consumers đang dùng v5. |
| [runtime registry v5](configs/runtime_artifacts_integrated_v5.json) | Chọn đúng GT/corpus/graph/index cho ba scenario; registry mặc định [runtime_artifacts.json](configs/runtime_artifacts.json) thuộc đường cũ, không tự đồng nhất với integrated profile. |
| [gate policy](configs/gate/two_stage_production_policy.json) | Pin gate; nhánh integrated dùng evidence contract v2 để admission; legacy gate giữ làm diagnostic. Tên “production” không chứng minh đã độc lập nghiệm thu. |
| [scenarios_12_v1.json](benchmarks/integrated/scenarios_12_v1.json) | 12 câu/rubric evaluation-only: mỗi scenario direct, correlation, CTI và limits; không phải evidence runtime. |
| [tests](tests/), [fixtures](tests/fixtures/) | Giữ cả synthetic fixtures, tests provenance/schema, contracts/guardrails, recovery/budget/dashboard. Không có tổng tests mới trong lượt bàn giao này. |
| [docs](docs/), [PROJECT_PROGRESS.md](PROJECT_PROGRESS.md) | Thiết kế, lịch sử, chương thực nghiệm cũ; phải đọc cùng version tương ứng. README/HUONG_DAN_CHAY có thông tin cũ và chuỗi giống credential, cần làm sạch bản phân phối. |

Consumers thực tế đều ở `outputs/integrated/20261030_v5/consumers/<scenario_id>/`, gồm `scenario_ground_truth.json`, `retrieval_corpus.json`, `knowledge_graph.json`, `vector_index_e5.json`:

| scenario_id | Corpus/index records | Graph nodes/edges | CTI chunks |
| --- | ---: | ---: | ---: |
| `purplesharp-ad` | 43 | 37/52 | 1 |
| `mshta-powershell` | 25 | 24/24 | 2 |
| `regsvr32-c2` | 33 | 29/39 | 2 |

Embedding: `intfloat/multilingual-e5-small`, revision `614241f622f53c4eeff9890bdc4f31cfecc418b3`, dimension 384, L2/cosine, `query: `/`passage: `. Query cần local model cache ngoài dự án. Retrieval chung BM25 + cosine/RRF, top_k=5/candidate_k=20; GraphRAG thêm exact seed mapping/traversal both/depth2/100nodes/200edges. Corpus RAG cũng chứa facts/relationships/evidence chunks, nên baseline này không chỉ là tài liệu văn bản. Không dùng vector/graph database service.

Luồng: raw/canonical → observed evidence và inferred correlation → candidate Sigma/MITRE assessments + CTI riêng → GT/corpus/graph/index → retrieval → source gate → prompt → client → structured + bounded narrative validation → draft/rejected/source artifacts → dashboard. Gate chỉ xét context trả về; `proceed` không xác nhận hành vi hoặc câu trả lời. Gate không dùng human approval để cho phép draft.

### Nguồn dữ liệu, rubric và approval

[Bundle MSHTA cũ](outputs/review/mshta-ground-truth/) có human approval metadata ngày `2026-10-15T23:36:13+07:00` của `Nguyen Hong Phong`, xem [human_approval.md](docs/human_approval.md). Các notes pending còn trong đó là lịch sử được giữ nguyên. Ba integrated GT mới đều `draft_reviewable/pending_human_review`; approval cũ không tự chuyển sang consumers mới. `confirmed` ở review metadata xác nhận việc duyệt tài liệu, không nâng mọi evidence/technique thành confirmed.

GT là tập facts/relationships/assessments có trạng thái và provenance, không phải mọi nhận định đều đã xác nhận. Reference answers/expected decisions/rubric chỉ phục vụ chấm; không đưa vào corpus, gate input hoặc messages. CTI là bối cảnh bên ngoài, không chứng minh actor/compromise/C2 trên host trong log.

Các điểm nội dung phải giữ: 4625/4776 là hai views, không đếm đôi; timestamp canonical/anchor span không phải thời gian tấn công vật lý. MSHTA lines 4/275 là cmd tạo MSHTA, 30/398 là MSHTA tạo PowerShell; launch `Get-Service sysmon` không chứng minh completion/output/service state. Giữ clock conflict khoảng bốn giờ, không tự sửa timezone. Regsvr32 URL `/i:http://…/launcher.sct` có `/n`, không phải remote UNC/missing-/n anomaly; network endpoint không chứng minh HTTP completion, response content, confirmed C2 hay exfiltration. Telemetry deletion/log clearing ngoài MSHTA core vẫn tồn tại.

## 7. LLM/provider và cấu hình kết nối


Model/provider tại checkpoint v7 là **cấu hình tại thời điểm bàn giao**: `generic_openai`, endpoint OpenRouter trực tiếp, requested model `google/gemma-4-31b-it`, temperature 0, max_tokens 2048, timeout 120s, single attempt. Không bắt buộc Gemma, OpenRouter hoặc 9Router; người nhận được chọn local/API phù hợp.

Chỉnh kết nối ở `.env` theo [.env.example](.env.example) và [LLMConfig](src/threat_hunting/llm/config.py): `LLM_PROVIDER`, `LLM_MODEL`, `LLM_BASE_URL`, `LLM_API_KEY`, các generation settings; provider `ollama` dùng `OLLAMA_HOST` và nối `/v1`. Loader hiện `load_dotenv(..., override=True)`, nên `.env` trong project ghi đè biến trùng tên của shell. Chưa phải sửa `.env` là có pin hợp lệ.

Khi đổi LLM/params, tạo **config/preflight/pin/output version mới**, không sửa pin hoặc kết quả lịch sử; cả RAG/GraphRAG trong một bộ phải cùng LLM và tham số generation liên quan. Không quy khác biệt giữa hai LLM cho retrieval. Tiếp tục chính study v7 phải giữ ledger và các điều kiện vận hành có trong runner; không tự tạo receipt xác nhận. Study mới phải có provenance riêng.


## 8. Công việc và nghiệm thu còn lại

Danh sách ưu tiên, modules, hành động, điều kiện hoàn thành, sản phẩm và lệnh chạy nằm trong [HANDOVER.md](HANDOVER.md). Trọng tâm: hoàn thiện cấu hình generation và source/pin migration; kiểm end-to-end; review citation/source semantics; rà retrieval/gate; khóa bộ đánh giá nhất quán; chấm từng answer/timing; nghiệm thu dashboard; đồng bộ chương 3 và hướng dẫn tái lập. Correct abstain vẫn hợp lệ; tests passed hoặc accepted draft không thay semantic review. Không tự tuyên bố hoàn thành100% hoặc GraphRAG tốt hơn.

## 9. Phạm vi và lịch sử của hồ sơ

Yêu cầu bàn giao hiện tại thay các chỉ dẫn triển khai cũ bằng trạng thái actual files, không tạo human approval hoặc nâng nhãn. Các đề mục 3.3 dùng cách gọi trong yêu cầu bàn giao; password spraying/Kerberoasting, MSHTA và Regsvr32 là các lát cắt cụ thể, giữ nguyên đề tài và cấu trúc ba chương. Không thêm scenario thứ tư.

Chỉ sửa tài liệu và .env.example; không sửa Word, code/config/pin/outputs hoặc gọi LLM. Lệnh, kiểm chứng và đóng gói: xem HANDOVER và [PACKAGING_CHECKLIST.md](PACKAGING_CHECKLIST.md). Lịch sử đầy đủ ở [PROJECT_PROGRESS.md](PROJECT_PROGRESS.md); bản tổng kết cuối mới là điểm bắt đầu hiện hành. Các sections20–22 dưới đây giữ nội dung gốc tại thời điểm lịch sử, không phải điều kiện dừng công việc triển khai thông thường.

## 20. Nhật ký quyết định

Các mục có ngày dưới đây giữ trạng thái tại thời điểm quyết định, không thay thế tiến độ hiện tại ở mục 15. Ví dụ nhận định “normalization chưa triển khai” ngày 16/07/2026 là checkpoint lịch sử.

### 12/07/2026 - Chốt dữ liệu cho ba kịch bản

- Chốt 3 file Mordor JSON: PurpleSharp AD Playbook cho brute force, Empire Launcher SCT/Regsvr32 cho C2 và PowerShell HTTP Listener cho PowerShell nghi vấn.
- Chốt 13 Sigma rule: 3 brute force, 5 C2/Regsvr32 và 5 PowerShell.
- Quyết định này đã được thay thế một phần bởi cập nhật ngày 16/07/2026 sau khi kiểm tra telemetry và Sigma match thực tế.

### 16/07/2026 - Cập nhật bộ dữ liệu và Sigma sau kiểm tra thực tế

- Giữ `purplesharp_ad_playbook_I_2020-10-22042947.json` và `empire_launcher_sct_regsvr32_2020-07-21232741.json`.
- Thay `psh_powershell_httplistener_2020-11-0204130683.json` bằng `cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json`.
- Chốt 6 SigmaHQ: 1 cho Kerberoasting, 3 cho Regsvr32 và 2 cho MSHTA.
- Quyết định xây thêm `win_security_password_spray_correlation.yml` làm derived artifact của đồ án.
- Ghi nhận 7 failed-logon targets, 5 Kerberos RC4 matches, 3 Regsvr32 rule matches và 2 MSHTA rule matches với raw record references cụ thể.
- Loại các rule tạo 0 match hoặc cần telemetry không tồn tại khỏi active experiment; không xóa raw/reference files.
- Trạng thái tiếp theo: cập nhật experiment config, chạy lại inspection trên bộ ba mới, xây evidence extraction và tạo ground truth để người dùng duyệt.

### 16/07/2026 - Hoàn thành structural inspection v2

- Chạy `mordor-selected-v2` trên đúng ba raw JSONL đã chọn; toàn bộ baseline khớp và raw SHA-256 không thay đổi.
- Nâng report lên `mordor-inspection/v2` và canonical schema lên `canonical-event/v2` proposed/reviewable.
- Thay mapping theo alias/coverage toàn file bằng proposal phụ thuộc `provider + Event ID`; sửa semantic của Security `4688`, authentication user roles, registry, DNS và network fields.
- Ghi nhận Sysmon Event ID `10` source/target process roles là `context_specific_unmapped`, không ép thành quan hệ parent-child.
- Bổ sung thống kê timestamp conflict, cảnh báo timezone-naive và transformation port string-to-integer cần validation.
- Trạng thái tiếp theo: review schema/mapping; normalization, evidence extraction và ground truth chưa triển khai.

## 21. Quy tắc cập nhật hồ sơ

Mỗi quyết định mới nên ghi kèm:

- Ngày quyết định.
- Nội dung đã chốt.
- Lý do chọn.
- Tệp/code/kết quả liên quan.
- Phần nào của đề cương hoặc kiến trúc bị ảnh hưởng.

Không chuyển mục “chưa chốt” sang “đã hoàn thành” nếu chưa có bằng chứng như mã nguồn chạy được, ảnh kết quả, log thực nghiệm hoặc bảng đánh giá.

## 22. Checkpoint review kỹ thuật ngày 14/10/2026

Theo yêu cầu thực hiện bước review ground truth MSHTA và đáp án tham chiếu, Codex đã đối chiếu toàn bộ 1.127 raw records với canonical events, kiểm tra hai Sigma rules và STIX objects từ ATT&CK v19.1. Các source hashes giữ nguyên; 3 entities, 2 facts, 2 relationships và 4 evidence references của core có căn cứ.

Bản sửa và báo cáo nằm tại `outputs/review/mshta-ground-truth/`. `scenario_ground_truth.json` bổ sung original fields trong fact attributes và sửa khẳng định “PowerShell ran Get-Service sysmon” thành “PowerShell was launched with -noexit -command Get-Service sysmon”. Log process creation không chứng minh cmdlet hoàn tất hoặc trạng thái dịch vụ. Timestamp `TimeCreated`/`UtcTime` còn lệch khoảng 4 giờ; không tự xác nhận timezone.

32 đáp án tham chiếu giữ 16 proceed, 8 insufficient_evidence và 8 unrelated. Hai câu được làm rõ: câu về launch command và câu về bằng chứng payload cố ý phá hoại. Raw file có record xóa tệp tạm và event-log clearing ngoài hai nhóm process-creation core, nên không được khẳng định toàn dataset không có thao tác xóa hoặc tự coi thao tác đó là destructive payload. Không thêm scenario hoặc positive attack label.

Review kỹ thuật hoàn thành với 592 relevant tests passed, validation/readback/provenance và raw immutability checks. Reviewer là Codex, không phải người dùng; ground truth vẫn `draft_reviewable`/`pending_human_review`. T1218.005 có hỗ trợ hành vi, T1059.007 không được command VBScript hỗ trợ và T1140 còn not_assessed; tất cả giữ candidate.

Mã nguồn và output hiện có đã có prototype retrieval và GraphRAG cho MSHTA như tiến độ ở mục 15. Các consumer hiện có pin ground truth cũ; bản sửa là version riêng, chưa tự động áp dụng vào corpus/graph/indexes/evaluation. Bước tiếp theo sau khi người dùng duyệt bản sửa là rebuild consumer với provenance mới và kiểm chứng gate hai tầng. Đáp án tham chiếu chỉ dùng để đánh giá, không đưa vào retrieval corpus hoặc runtime gate input. LLM/UI và pipeline evidence đầy đủ cho PurpleSharp/Regsvr32 vẫn chưa hoàn thành.
