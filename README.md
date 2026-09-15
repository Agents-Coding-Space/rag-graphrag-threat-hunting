# RAG, GraphRAG và LLM cho Threat Hunting

Đồ án nghiên cứu mô hình kết hợp RAG, GraphRAG và LLM nhằm hỗ trợ truy tìm mối đe dọa an toàn thông tin. Mục tiêu là liên kết bằng chứng từ log với tri thức bảo mật như Sigma và MITRE ATT&CK, sau đó tạo kết quả phân tích có thể truy vết và được con người kiểm duyệt.

## Trạng thái hiện tại

Repository hiện có pipeline structural inspection v2 read-only cho log Mordor ở định dạng JSON Lines, JSON array hoặc JSON object. Công cụ tìm file theo tên chính xác, kiểm tra định dạng, đọc toàn bộ bản ghi, thống kê schema, phát hiện timestamp conflict và sinh đề xuất canonical mapping theo context `provider + Event ID`. Experiment `mordor-selected-v2` đã chạy thành công trên đúng ba dataset, giữ nguyên SHA-256 của raw input và tạo 29.510 canonical events theo contract một raw record tạo một canonical event.

MSHTA evidence extractor đã chạy production trên toàn bộ 1.127 canonical events, tạo 3 process entities, 2 `process_spawn` relationships, 2 evidence items và 4 unique source references trong output `scenario-evidence/v1` có trạng thái `draft_reviewable`. Output đã được kiểm tra deterministic. Full test suite hiện có 250 tests đạt, 0 failed và 0 skipped.

Ba kịch bản đã chọn:

1. Password spraying và Kerberoasting từ `purplesharp_ad_playbook_I_2020-10-22042947.json`.
2. C2 thông qua Regsvr32 từ `empire_launcher_sct_regsvr32_2020-07-21232741.json`.
3. PowerShell nghi vấn thông qua MSHTA từ `cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json`.

## Cấu trúc repository

```text
configs/                Cấu hình experiment và baseline record count
data/raw/               Dataset cục bộ, không commit
data/processed/         Dữ liệu dẫn xuất cục bộ, không commit
data/knowledge/         MITRE ATT&CK, Sigma và CTI cục bộ, không commit
outputs/                Báo cáo sinh ra, không commit
scripts/                CLI chạy pipeline
src/threat_hunting/     Mã nguồn discovery, parser, inspection và reporting
tests/                  Unit tests và fixture nhỏ được phép commit
AGENTS.md               Quy tắc làm việc của repository
PROJECT_CONTEXT.md      Hồ sơ và quyết định hiện tại của đồ án
```

## Chuẩn bị dữ liệu

Dataset không được lưu trong Git. Đặt ba file Mordor có tên chính xác như danh sách trên vào các thư mục phù hợp bên dưới `data/raw/`. Mỗi filename phải chỉ xuất hiện một lần trong repository để discovery không bị mơ hồ. Baseline record count được khai báo tại `configs/experiments/mordor_selected_v2.json`.

Các nguồn MITRE ATT&CK, Sigma và CTI phục vụ các giai đoạn sau được đặt trong `data/knowledge/`. Toàn bộ `data/raw/`, `data/processed/`, `data/knowledge/` và `outputs/` đã được loại khỏi Git bằng `.gitignore`.

## Cài đặt

Yêu cầu Python 3.11 trở lên. Ví dụ trên Windows PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[test]"
```

Runtime hiện chỉ dùng Python standard library; extra `test` cài `pytest` để chạy test suite.

## Chạy inspection

Sau khi code được duyệt, chạy experiment mặc định:

```powershell
python scripts/inspect_mordor.py
```

Output được tách khỏi output cũ tại `outputs/mordor_inspection/mordor-selected-v2/`. `summary.md` cung cấp báo cáo structural inspection ngắn gọn; `manifest.json`, `canonical_schema.json` và từng `files/*/inspection.json` giữ chi tiết máy đọc được. Report hiện dùng `mordor-inspection/v2`; canonical schema `canonical-event/v2` đã được dùng để tạo 29.510 canonical events.

Xem toàn bộ tùy chọn:

```powershell
python scripts/inspect_mordor.py --help
```

## Chạy tests

```powershell
python -m pytest
```

Kết quả gần nhất: 250 tests passed, 0 failed và 0 skipped.

## Giới hạn hiện tại

Production normalization và MSHTA evidence extraction đã hoàn thành. PurpleSharp và Regsvr32 evidence extractors chưa hoàn thành. Sigma execution, MITRE ATT&CK resolution, ground truth, RAG, GraphRAG, LLM, vector database, graph database và giao diện người dùng chưa được triển khai.

Bước tiếp theo là hoàn thiện ground truth cho kịch bản MSHTA–PowerShell, sau đó xây dựng và so sánh RAG, GraphRAG trên kịch bản này. Kiến trúc được thiết kế để tiếp tục mở rộng sang PurpleSharp và Regsvr32 trong các giai đoạn sau.
