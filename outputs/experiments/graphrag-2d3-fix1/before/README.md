# RAG, GraphRAG và LLM cho Threat Hunting

Đồ án nghiên cứu mô hình kết hợp RAG, GraphRAG và LLM nhằm hỗ trợ truy tìm mối đe dọa an toàn thông tin. Mục tiêu là liên kết bằng chứng từ log với tri thức bảo mật như Sigma và MITRE ATT&CK, sau đó tạo kết quả phân tích có thể truy vết và được con người kiểm duyệt.

## Trạng thái hiện tại

**Cập nhật: 14/10/2026.** Repository có pipeline xử lý log và prototype retrieval/GraphRAG cho **MSHTA–PowerShell**. Review kỹ thuật ground truth cùng 32 đáp án tham chiếu đã hoàn thành; human approval còn pending. Hệ thống kết hợp đầy đủ với LLM và giao diện chưa hoàn thành.

| Thành phần | Kết quả đã có | Phạm vi/trạng thái |
| --- | --- | --- |
| Discovery và inspection | JSONL, JSON array/object; streaming, schema statistics, context-aware mapping và raw references | Hoàn thành trên cả 3 dataset của `mordor-selected-v2` |
| Canonical normalization | 29.510 raw records → 29.510 `canonical-event/v2` events, dropped=0 | Có issue reporting, giữ nguyên SHA-256 raw; chưa giải quyết hết timestamp conflicts |
| MSHTA evidence | 3 process entities, 2 facts/relationships, 2 evidence groups, 4 raw references | Core là `cmd.exe → mshta.exe → powershell.exe`, không phải toàn bộ process inventory |
| Sigma evaluation | 4 observation matches → 2 behavior matches trên 1.127 events | Evaluator giới hạn `windows/process_creation`, fail-closed; matches còn candidate |
| MITRE resolution | STIX 2.1, ATT&CK v19.1; exact-match, pinned provenance | Resolve object không tự xác nhận technique đã xảy ra |
| Ground truth và đáp án | Bản draft, bản sửa sau review, 32 đáp án; sửa 2 câu hỏi, giữ nhãn | Review kỹ thuật bởi Codex; `pending_human_review` |
| Phần truy xuất RAG | Corpus 19 chunks; BM25, vector cosine và hybrid RRF; local Sentence Transformers | Prototype trên bản ground truth baseline |
| GraphRAG | Graph baseline 17 nodes/21 edges; hybrid retrieval → exact seed mapping → graph traversal | Có CLI tạo context và provenance; chưa hoàn thành production gate |
| Embedding và calibration | So sánh MiniLM/E5 trên 32 câu Việt/Anh; provisional recommendation cho `multilingual-e5-small` | Hai calibration reports thử 672 cấu hình/report, đều `no_eligible_policy` |
| Gate hai tầng | Module và tests cho topical relevance → evidence answerability | Chưa tích hợp vào CLI hoặc kiểm chứng/chọn production policy |
| LLM, UI, database service | Có thiết kế | Chưa triển khai; vector/graph hiện dùng JSON artifacts và xử lý in-memory |

MITRE review cho MSHTA giữ `T1218.005` ở mức `supported_by_observed_behavior`, `T1059.007` ở mức `not_supported_by_observed_command` vì command dùng VBScript, và `T1140` ở mức `not_assessed`. Các assessment vẫn `candidate`; không có label promotion thành `confirmed`.

Bản sửa và kết quả kiểm tra cục bộ:

- [Review report](outputs/review/mshta-ground-truth/review_report.md)
- [Ground truth đã sửa](outputs/review/mshta-ground-truth/scenario_ground_truth.json)
- [32 đáp án tham chiếu](outputs/review/mshta-ground-truth/reference_answers.md)
- [Review manifest](outputs/review/mshta-ground-truth/review_manifest.json) và [verification](outputs/review/mshta-ground-truth/verification.json)

Các liên kết `outputs/` có trên máy đã chạy pipeline; generated artifacts không được commit. Corpus, graph, indexes và evaluation reports hiện có vẫn pin hash ground truth cũ. Bản sửa review được lưu riêng, chưa được áp dụng vào các consumer này.

Ba kịch bản đã chọn:

1. Password spraying và Kerberoasting từ `purplesharp_ad_playbook_I_2020-10-22042947.json`.
2. C2 thông qua Regsvr32 từ `empire_launcher_sct_regsvr32_2020-07-21232741.json`.
3. PowerShell nghi vấn thông qua MSHTA từ `cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json`.

Inspection và normalization đã chạy cho cả ba; evidence/retrieval/GraphRAG đang tập trung vào MSHTA. PurpleSharp và Regsvr32 chưa có evidence pipeline đầy đủ. Password-spraying correlation của đồ án chưa được triển khai.

## Cấu trúc repository

```text
configs/                Cấu hình experiment và baseline record count
benchmarks/             Calibration cases và retrieval relevance judgments
data/raw/               Dataset cục bộ, không commit
data/processed/         Dữ liệu dẫn xuất cục bộ, không commit
data/knowledge/         MITRE ATT&CK, Sigma và CTI cục bộ, không commit
outputs/                Báo cáo sinh ra, không commit
scripts/                CLI chạy pipeline
src/threat_hunting/     Parsing, normalization, evidence, Sigma/MITRE,
                        ground truth, retrieval, graph, GraphRAG và evaluation
tests/                  Unit tests và fixture nhỏ được phép commit
AGENTS.md               Quy tắc làm việc của repository
PROJECT_CONTEXT.md      Hồ sơ và quyết định hiện tại của đồ án
PROJECT_PROGRESS.md     Trạng thái milestone, bằng chứng và việc còn thiếu
```

## Chuẩn bị dữ liệu

Dataset không được lưu trong Git. Đặt ba file Mordor có tên chính xác như danh sách trên vào các thư mục phù hợp bên dưới `data/raw/`. Mỗi filename phải chỉ xuất hiện một lần trong repository để discovery không bị mơ hồ. Baseline record count được khai báo tại `configs/experiments/mordor_selected_v2.json`.

Các nguồn MITRE ATT&CK và Sigma hiện được đọc từ `data/knowledge/`; danh sách CTI bổ sung chưa được chốt. Experiment chọn 3 Mordor logs, 6 SigmaHQ rules và 1 `enterprise-attack.json`. Password-spraying correlation là derived rule dự kiến, không tính là external input. ATT&CK production snapshot được pin ở v19.1 trong `configs/knowledge/mitre_enterprise_attack.json`.

Toàn bộ `data/raw/`, `data/processed/`, `data/knowledge/` và `outputs/` đã được loại khỏi Git bằng `.gitignore`. Raw Mordor, Sigma và MITRE được giữ read-only; output ghi vào thư mục dẫn xuất riêng.

## Cài đặt

Yêu cầu Python 3.11 trở lên. Ví dụ trên Windows PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[test]"
```

Direct dependencies hiện pin `PyYAML==6.0.3` và `sentence-transformers==6.1.0`; extra `test` pin `pytest==9.1.1`. Model/revision và embedding prefixes được ghi trong config/index provenance. Vector retrieval cần đúng model snapshot tương ứng với index.

## Chạy inspection

Sau khi chuẩn bị inputs, chạy từ repository root:

```powershell
python scripts/inspect_mordor.py
```

Output được tách khỏi output cũ tại `outputs/mordor_inspection/mordor-selected-v2/`. `summary.md` cung cấp báo cáo structural inspection ngắn gọn; `manifest.json`, `canonical_schema.json` và từng `files/*/inspection.json` giữ chi tiết máy đọc được. Report hiện dùng `mordor-inspection/v2`; canonical schema `canonical-event/v2` đã được dùng để tạo 29.510 canonical events.

Xem toàn bộ tùy chọn:

```powershell
python scripts/inspect_mordor.py --help
```

## Normalization và các CLI tiếp theo

```powershell
python scripts/normalize_mordor.py
```

Normalization mặc định ghi vào `outputs/canonical/mordor-selected-v2/` theo contract 1:1, không filtering/deduplication. Inspection và normalization đều hỗ trợ `--output-dir` để chọn thư mục dẫn xuất khác và `--overwrite` để thay report của cùng run.

| Bước | CLI đã có |
| --- | --- |
| Evidence/Sigma/MITRE MSHTA | `extract_mshta_evidence.py`, `evaluate_mshta_sigma.py`, `resolve_mshta_mitre.py` |
| Ground truth, corpus và graph | `build_mshta_ground_truth.py`, `build_retrieval_corpus.py`, `build_knowledge_graph.py` |
| Vector index | `build_vector_index.py` |
| Truy vấn | `query_retrieval_corpus.py`, `query_vector_index.py`, `query_hybrid_retrieval.py`, `query_knowledge_graph.py`, `query_graphrag_context.py` |
| Đánh giá | `compare_embedding_retrieval_models.py`, `select_embedding_model.py`, `calibrate_graphrag_relevance.py`, `diagnose_graphrag_relevance.py` |

Các CLI build/query dùng input paths và expected hashes theo contract riêng; xem `python scripts/<filename> --help`. `query_graphrag_context.py` trả context có source references, không sinh câu trả lời bằng LLM.

Ví dụ truy vấn lexical trên corpus baseline đã có:

```powershell
python scripts/query_retrieval_corpus.py --corpus outputs/retrieval/mshta-powershell/retrieval_corpus.json --query "Which process is the parent of powershell.exe?" --top-k 5
```

Tái lập bản sửa kỹ thuật bằng package cục bộ hiện có:

```powershell
.\.venv\Scripts\python.exe -X utf8 outputs/review/mshta-ground-truth/assemble_review.py
```

Package review có pinned input hashes và cần các upstream artifacts/audit files. Đáp án tham chiếu được tách khỏi corpus và runtime gate input.

## Chạy tests

```powershell
python -m pytest
```

Lượt review **14/10/2026** chạy 6 test files về ground truth và reference dataset: **592 passed**. Đây là relevant checks của lượt review, không phải số lượng hoặc kết quả full suite hiện tại. Mốc full suite 319 passed thuộc milestone MITRE ngày 16/09/2026; lịch sử xem [PROJECT_PROGRESS.md](PROJECT_PROGRESS.md).

JSON schema/readback, 32 answer cases, source pointers/hashes, deterministic rebuild, Unicode và raw immutability của bản review đã được kiểm tra trong `verification.json`.

## Giới hạn hiện tại

- PowerShell được khởi chạy với `-noexit -command Get-Service sysmon`; process creation không chứng minh cmdlet hoàn tất hoặc trạng thái dịch vụ.
- Timestamp canonical theo `TimeCreated`; Sysmon `UtcTime` có lệch khoảng 4 giờ và timezone chưa được xác nhận.
- `OriginalFileName` có trong raw nhưng chưa được canonical mapping. Sigma evaluator giới hạn `windows/process_creation`.
- Hai evidence groups của core không đại diện toàn bộ dataset. File còn có conhost creation, log clearing và temporary-file deletion; không tự gán destructive intent hay khẳng định toàn dataset không có hành vi đó.
- Ground truth và MITRE assessments còn chờ human review. Chưa có holdout benchmark độc lập hoặc production gate đạt tiêu chí.
- RAG/GraphRAG mới có prototype retrieval/context; LLM, giao diện, database service và tích hợp cuối chưa hoàn thành.
- PurpleSharp/Regsvr32 chưa có pipeline evidence đầy đủ; vẫn thuộc ba scenario đã chọn.

## Bước tiếp theo

1. Người dùng duyệt bản ground truth sửa và 32 đáp án tham chiếu.
2. Rebuild corpus/graph/indexes và judgments phù hợp với provenance mới của bản được duyệt.
3. Hiệu chỉnh và kiểm chứng gate hai tầng trên câu hỏi có nhãn, dùng tập kiểm tra độc lập với calibration set.
4. Tích hợp policy đạt tiêu chí vào CLI GraphRAG, lưu kết quả và so sánh với RAG trên cùng dữ liệu/câu hỏi.
5. Tích hợp LLM/giao diện và mở rộng hai scenario còn lại theo milestone đã duyệt.

Xem [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md) cho phạm vi/thiết kế và [PROJECT_PROGRESS.md](PROJECT_PROGRESS.md) cho bằng chứng tiến độ. Quy tắc dữ liệu và làm việc được giữ trong [AGENTS.md](AGENTS.md).
