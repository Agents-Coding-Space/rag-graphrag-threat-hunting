> Distribution note: this is the staged handover copy. Inputs are now included under data/. See START_HERE.md and packaging/path_migration.json for portable paths; dated instructions below describe earlier tasks.

# Hồ sơ bàn giao dự án

Đối chiếu ngày **31/10/2026, Asia/Bangkok**. Lượt này chỉ đọc, kiểm tra offline và cập nhật tài liệu; không sửa code/config/pin/outputs, không generation, không tạo ZIP. Đọc tiếp [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md), bản tổng kết cuối [PROJECT_PROGRESS.md](PROJECT_PROGRESS.md) và [PACKAGING_CHECKLIST.md](PACKAGING_CHECKLIST.md).

## 1. Mục tiêu và phạm vi phải giữ

Giữ đề tài **Nghiên cứu mô hình kết hợp RAG, GraphRAG, LLM và ứng dụng truy tìm mối đe dọa ATTT**, cấu trúc ba chương và các đề mục:

- **3.3.1 Brute force và đăng nhập bất thường:** PurpleSharp, password spraying/Kerberoasting và tương quan authentication.
- **3.3.2 Thực thi PowerShell nghi vấn:** chuỗi MSHTA–PowerShell.
- **3.3.3 Kết nối mạng bất thường hoặc nghi vấn C2:** Regsvr32, scriptlet HTTP và process-bound network.

Giữ tích hợp thực tế MITRE ATT&CK, Sigma, CTI reports và dashboard ba cột hiện có. Không thêm kịch bản thứ tư, huấn luyện LLM hoặc đưa dự án khác vào phạm vi.

## 2. Điểm bắt đầu và trạng thái thực tế

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

## 3. Bản đồ dự án và dữ liệu

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

## 4. Công việc còn lại theo ưu tiên

| Ưu tiên, vấn đề | Files/modules | Hành động cụ thể | Điều kiện hoàn thành và sản phẩm |
| --- | --- | --- | --- |
| **1. Hoàn thiện cấu hình generation và kiểm chứng end-to-end** | `.env`, `.env.example`; `llm/config.py`, `client.py`, `error_diagnostics.py`; `evaluation/final_experiment.py`; final config/pin | Review bốn thay đổi + module mới chưa pin; kiểm chứng mock/offline; hoàn thiện execution delta hợp lệ nếu tiếp tục study cũ, hoặc tạo config/preflight/pin mới nếu đổi LLM. Cấu hình kết nối hoạt động theo điều kiện triển khai. | Config/pin/source manifest khớp; ledger cũ giữ nguyên; receipt vận hành nếu tiếp tục HTTP402 study phản ánh xác nhận thật; cả eligible và abstain có đường end-to-end truy vết được. Giao pin/config mới, test evidence, run artifacts và operational notes không secrets. |
| **2. Review nghĩa nguồn và citation** | `llm/generation_contract*.py`, `guardrail.py`, `schema.py`; `evidence/authentication.py`, `process_network.py`; surveys và source artifacts | Kiểm exact Sigma UUID `rule_id` so với finding/node IDs; actor/action/raw refs; clock semantics; command text vs process creation vs completion; telemetry vs CTI. Dùng lỗi cũ làm regression, không mặc định chúng còn trong bản đã sửa. | Từng claim/citation trong output được đối chiếu nguồn; unsupported/unknown còn đúng trạng thái. Giao bảng review từng nhánh và các regression cần thiết. |
| **3. Kiểm retrieval/gate hai nhánh** | `retrieval/*`, `graphrag/*`, `evaluation/evidence_contract_v2.py`; preflight v7 | Review từng abstain: từ chối đúng, thiếu companion trong top5, hay checker gap. V5 ghi năm answerable RAG abstains do coverage; đây là giả thuyết phải kiểm theo version. | Có bảng reason/context sufficiency cho cả hai; correct abstain vẫn hợp lệ, không ép mọi câu proceed. Nếu sửa policy/retrieval, tạo study/version mới. Giao per-case context/gate audit. |
| **4. Khóa bộ đánh giá cuối nhất quán** | `benchmarks/integrated/*`, `configs/evaluation/*`, pinning/harness/final runner | Chốt questions/rubric, split và giới hạn trước run; dùng cùng LLM/params/context budgets cho RAG và GraphRAG. Tách corrective development khỏi independent test set. | Đủ status rows/pairs với hashes, run scope và reasons cho mọi missing/not_run; không lấp bằng model/version khác. Giao frozen config/pin, manifests, results và paired table. |
| **5. Chấm nội dung, citation và thời gian** | `semantic_review.*`, `results.csv`, `paired_details.csv`; manual review templates | Chấm context/gate/final prose riêng; ghi người review/tiêu chí/mẫu số. Tách provider_error, abstain, rejection, not_run; không gọi dry-run timing là model latency. | Metrics có nguồn và denominator, missing là N/A; accepted_draft không tự là đúng. Giao per-answer review, quality/outcome/timing tables và giới hạn. |
| **6. Nghiệm thu dashboard ba cột** | `frontend/src`, `server/experimental.py`, `serve_experimental_ui.py`, saved-results manifest | Ghép đúng config/pin cuối; thử cả ba scenario, citations/CTI/graph/export và accepted/rejected/abstain/error/not_run/replay. Kiểm không lẫn lịch sử với live. | Có HTTP + browser QA và ảnh demo thật của đúng profile; xuất kết quả giữ provenance. Giao screenshots, exports, QA log, hướng dẫn mở. |
| **7. Đồng bộ chương 3 và báo cáo** | `docs/THUYET_MINH_DO_AN_TOT_NGHIEP_KMA.md`, tài liệu luận văn do chủ dự án cung cấp; `thesis_facts.md` | Đối chiếu từng bảng/hình/claim với config/run; cập nhật chương 3, kết luận và references. Giữ đề tài/mục lục. | Không dùng hardcoded metrics hoặc claim ưu thế chưa được đo; có trace bảng/hình → artifacts. Giao bản báo cáo và bảng đối chiếu khi có nhiệm vụ sửa luận văn riêng. Lượt này không sửa Word. |
| **8. Cài đặt, tái lập và bảo vệ** | `pyproject.toml`, frontend lockfile, handover/packaging, tests/fixtures | Khai báo/pin dependencies còn thiếu trong công việc triển khai tiếp theo; thử trên máy/thư mục mới, xử lý external inputs/cache/absolute paths, chuẩn bị demo và phương án saved replay. | Máy nhận kiểm hash và chạy được theo tài liệu, không lệ thuộc secret hoặc đường máy cũ. Giao environment lock/install guide, reproducibility log và kịch bản bảo vệ. |

## 5. LLM/provider được thay thế

Model/provider tại checkpoint v7 là **cấu hình tại thời điểm bàn giao**: `generic_openai`, endpoint OpenRouter trực tiếp, requested model `google/gemma-4-31b-it`, temperature 0, max_tokens 2048, timeout 120s, single attempt. Không bắt buộc Gemma, OpenRouter hoặc 9Router; người nhận được chọn local/API phù hợp.

Chỉnh kết nối ở `.env` theo [.env.example](.env.example) và [LLMConfig](src/threat_hunting/llm/config.py): `LLM_PROVIDER`, `LLM_MODEL`, `LLM_BASE_URL`, `LLM_API_KEY`, các generation settings; provider `ollama` dùng `OLLAMA_HOST` và nối `/v1`. Loader hiện `load_dotenv(..., override=True)`, nên `.env` trong project ghi đè biến trùng tên của shell. Chưa phải sửa `.env` là có pin hợp lệ.

Khi đổi LLM/params, tạo **config/preflight/pin/output version mới**, không sửa pin hoặc kết quả lịch sử; cả RAG/GraphRAG trong một bộ phải cùng LLM và tham số generation liên quan. Không quy khác biệt giữa hai LLM cho retrieval. Tiếp tục chính study v7 phải giữ ledger và các điều kiện vận hành có trong runner; không tự tạo receipt xác nhận. Study mới phải có provenance riêng.

## 6. Lệnh đã đối chiếu

Lệnh dưới đây cho **PowerShell, từ thư mục dự án**. Lượt bàn giao chỉ chạy ba lệnh `--help` và kiểm tra đọc/hash; không cài dependencies, build, khởi động server, dry-run mới hoặc live. Các đường `handover-*` là **output mới dự kiến**, không phải artifacts đã tồn tại. Chọn tên mới nếu đã có thư mục.

### Môi trường

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python.exe -m pip install -e '.[test]'
.venv\Scripts\python.exe -m pip install fastapi==0.162.0 uvicorn==0.54.0 pydantic==2.14.1 python-dotenv==1.2.4
Set-Location frontend
npm.cmd ci
npm.cmd run build
Set-Location ..
```

Python >=3.11 được hỗ trợ; 3.12 là môi trường đang có. Các version bổ sung trên là distribution versions đọc từ `.venv` hiện tại, chưa phải dependency lock đã tái lập trên máy sạch. Cần hoàn tất công việc 8. Không gửi `.venv` như bản cài đặt portable. Frontend build được server phục vụ trực tiếp; Vite dev proxy hiện trỏ experimental API về port8002, không tự đi theo port8010.

### Kiểm tra đọc và CLI

```powershell
Test-Path outputs\final\20261031_direct_v7\runtime_pin.json
Test-Path outputs\integrated\20261030_v5\consumers\purplesharp-ad\vector_index_e5.json
Get-FileHash configs\evaluation\integrated_final_direct_v7.json -Algorithm SHA256
.venv\Scripts\python.exe -B scripts\run_final_experiment.py --help
.venv\Scripts\python.exe -B scripts\evaluate_rag_graphrag.py --help
.venv\Scripts\python.exe -B scripts\serve_experimental_ui.py --help
```

Kiểm đủ mười inputs, các GT `input_provenance`, 12 registry hashes, canonical manifest và CTI offsets theo [source_verification.json](outputs/final/20261031_direct_v7/source_verification.json); `Test-Path` riêng lẻ chưa đủ. Pin còn cần so khớp tập code, gồm file mới, không chỉ các file pin cũ liệt kê.

### Dry-run và dashboard: đang có điều kiện provenance chưa đáp ứng

Hai mẫu sau đúng flags/path hiện có, **chưa chạy được với working source + pin cũ đang lệch**. Chỉ sử dụng sau công việc 1 đã hoàn tất tương thích source/pin. Nếu tạo version mới, thay đồng bộ config, pin, preflight; không ghi đè bản v7. Không tự thêm `--execution-pin` với một file chưa được lập/kiểm chứng. Dashboard hiện không có flag này.

```powershell
.venv\Scripts\python.exe -B scripts\run_final_experiment.py --config configs\evaluation\integrated_final_direct_v7.json --pin outputs\final\20261031_direct_v7\runtime_pin.json --preflight outputs\final\20261031_direct_v7\preflight --output outputs\experiments\handover-v7-dryrun-new
.venv\Scripts\python.exe -B scripts\serve_experimental_ui.py --config configs\evaluation\integrated_final_direct_v7.json --pin outputs\final\20261031_direct_v7\runtime_pin.json --port 8010 --output outputs\demo\handover-v7-dashboard-new
```

Dashboard mở `http://127.0.0.1:8010/`; profile v7 chỉ offline/replay, không dùng UI live để vượt ledger. Ngay cả khi chỉ replay, session vẫn kiểm full code pin và LLM config. Model query cần E5 revision cache; `.env.example` là mẫu, không tự khớp model của pin lịch sử.

Lệnh đánh giá live dùng cùng `scripts/run_final_experiment.py` và thêm `--live` **sau khi** config/pin/ledger và điều kiện kết nối hợp lệ; output phải là thư mục experiment mới. Tiếp tục task cũ còn có các flags đã xác minh `--resume-from`, `--continue-task`, `--execution-pin`, `--balance-confirmation`. Chưa có execution pin/receipt hợp lệ để cung cấp một lệnh continuation sẵn chạy; không bịa đường dẫn. `scripts/pin_integrated_runtime.py --config ... --preflight ... --output ...` là công cụ tạo pin mới sau preflight; đây là bước ghi artifacts trong milestone tiếp theo, không chạy ở lượt tài liệu này.

## 7. Tiêu chí nghiệm thu

- [ ] Mười external inputs đúng filename/hash; canonical đủ 29.510 records, dropped=0; source refs và clock caveats truy ngược được.
- [ ] Ba scenario dùng consumers đúng registry/pin; MITRE/Sigma/CTI có nguồn/version/offsets; không đưa rubric vào evidence.
- [ ] Source/config/pin khớp; generation và validation chạy end-to-end với LLM được chọn, single-attempt/budget/stop policy rõ ràng; không tự nâng labels/approval.
- [ ] Cả hai nhánh có status cho toàn bộ bộ câu hỏi; not_run không bị ghi thành đạt/sai; các abstain có review context sufficiency.
- [ ] Từng answer/citation được đánh giá nội dung; outcomes, quality và timing có mẫu số, phiên bản và source artifacts. Correct abstain được chấp nhận.
- [ ] Có bộ đánh giá nhất quán và nêu rõ có/không independent validation; không đặt accuracy100% hoặc khẳng định sạch mọi lỗi.
- [ ] Dashboard ba cột sử dụng được với cả ba scenario, export đúng, ảnh/demo thật đúng config cuối; saved replay được gắn nhãn.
- [ ] Báo cáo, bảng/hình, kết luận và references khớp implementation/artifacts; hướng dẫn cài và tái lập được kiểm trên môi trường nhận.

## 8. Phạm vi xác minh của lượt bàn giao

Đã đọc lại JSON, đếm streaming cả ba raw JSONL, đối chiếu canonical counts/hashes, xác minh 21 provenance entries, 12 consumers và ba CTI snapshot/text hashes/citation offsets. Đã kiểm `--help` của ba entry points, tìm code manifest delta và đường dẫn ngoại vi. Không chạy runtime test suite mới; các test counts trong progress/report là checkpoints lịch sử, có chồng lặp, không cộng thành unique total. Không có `.git` trong checkout, nên không thể dùng `git status/diff` để kết luận working tree sạch. Kiểm bảo toàn bằng hashes, với các cache/test-temp không đọc được được nêu trong tổng kết progress.

Kiểm cuối: 148 liên kết cục bộ trong phần tài liệu hiện hành đều tồn tại; snapshot 7.428 files ngoài sáu file được phép sửa/tạo có cùng aggregate SHA-256 trước/sau. Prefix 69.881 bytes lịch sử của PROJECT_PROGRESS giữ nguyên hash. Tài liệu mới không có chuỗi credential theo mẫu đã rà; `.env.example` để key rỗng. Những output/cache bị access denied không nằm trong phạm vi khẳng định này.
