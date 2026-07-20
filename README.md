# RAG, GraphRAG và LLM cho Threat Hunting

Đồ án nghiên cứu mô hình kết hợp RAG, GraphRAG và LLM nhằm hỗ trợ truy tìm mối đe dọa an toàn thông tin. Mục tiêu là liên kết bằng chứng từ log với tri thức bảo mật như Sigma và MITRE ATT&CK, sau đó tạo kết quả phân tích có thể truy vết và được con người kiểm duyệt.

## Trạng thái hiện tại

Repository hiện có pipeline structural inspection v2 read-only cho log Mordor ở định dạng JSON Lines, JSON array hoặc JSON object. Công cụ tìm file theo tên chính xác, kiểm tra định dạng, đọc toàn bộ bản ghi, thống kê schema, phát hiện timestamp conflict và sinh đề xuất canonical mapping theo context `provider + Event ID`. Experiment `mordor-selected-v2` đã chạy thành công trên đúng ba dataset và giữ nguyên SHA-256 của raw input.

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

Output được tách khỏi output cũ tại `outputs/mordor_inspection/mordor-selected-v2/`. `summary.md` cung cấp báo cáo structural inspection ngắn gọn; `manifest.json`, `canonical_schema.json` và từng `files/*/inspection.json` giữ chi tiết máy đọc được. Report hiện dùng `mordor-inspection/v2`; canonical schema là `canonical-event/v2` ở trạng thái proposed/reviewable, chưa tạo canonical events.

Xem toàn bộ tùy chọn:

```powershell
python scripts/inspect_mordor.py --help
```

## Chạy tests

```powershell
python -m pytest
```

## Giới hạn hiện tại

Repository chưa triển khai normalization, canonical event generation, evidence extraction, Sigma matching, MITRE mapping, ground truth cuối, RAG, GraphRAG, LLM, vector database, graph database hoặc giao diện người dùng. Output inspection hiện chỉ là dữ liệu structural trung gian để kiểm tra và duyệt trước các giai đoạn đó.
