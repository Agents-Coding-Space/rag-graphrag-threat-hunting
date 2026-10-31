# Bắt đầu từ đây — ZIP bàn giao 31/10/2026

Đây là bản phân phối source, tests, tài liệu và artifacts, kèm **đủ 10 inputs gốc**. Dự án gốc không bị sửa. Gói không chứa `.env`, credential databases, môi trường ảo, node_modules, browser profiles hoặc ZIP lồng/trùng. `.env.example` để key rỗng. Model cache E5 không đóng kèm; xem [E5_MODEL.md](E5_MODEL.md).

## Kiểm gói sau giải nén

Mở PowerShell tại thư mục chứa file này, dùng Python >=3.11:

```powershell
py -3 -B verify_package.py
```

Lệnh chỉ đọc file: kiểm inventory SHA-256, 10 inputs, raw/canonical counts, historical provenance qua path map, cả hai bộ consumers và ba CTI snapshots/citation offsets. Không truy cập mạng, không load embedding, không gọi LLM hoặc benchmark. Kết quả mong đợi `status: passed`, raw/canonical đều 29510, selected_inputs_verified=10. [packaging/prearchive_verification.json](packaging/prearchive_verification.json) ghi lần kiểm trước đóng gói; kết quả CRC/giải nén nằm trong báo cáo kiểm tra cạnh ZIP.

Muốn kiểm thêm schema của repository sau khi cài dependencies:

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python.exe -m pip install -e '.[test]'
.venv\Scripts\python.exe -B verify_package.py --schemas
```

Không đặt file mới vào thư mục gói trước bước kiểm manifest toàn bộ. Nếu đã tạo `.venv` hoặc outputs mới, dùng bản giải nén sạch để xác minh inventory gốc; `.venv` không phải thành phần ZIP. Muốn cài riêng trước rồi kiểm schema, có thể tạo virtualenv ngoài thư mục giải nén. Backend còn các dependencies ghi trong [HANDOVER.md](HANDOVER.md); `pyproject.toml` hiện chưa là lock đầy đủ cho dashboard.

## Đường dẫn và provenance

- Inputs đã ở `data/raw/...` và `data/knowledge/...`; [packaging/inputs.json](packaging/inputs.json) liệt kê đủ đường tương đối và SHA-256. Không cần thư mục data ở máy cũ.
- Bản gốc các consumers/manifests/history giữ trong `outputs/`. Các absolute paths cũ là metadata lịch sử, không phải yêu cầu tạo ổ/thư mục giống máy cũ. Verifier ánh xạ chúng bằng [packaging/path_migration.json](packaging/path_migration.json), rồi kiểm file thật **bên trong bản giải nén**.
- Bản dùng đường tương đối mới ở [portable/runtime_artifacts.json](portable/runtime_artifacts.json) và `portable/consumers/<scenario_id>/`. Chỉ đổi input paths và các hash bindings cần thiết của GT→corpus/graph→index; không đổi labels, approval, evidence, chunk contents, vectors hoặc model revision. Không generation/re-embedding.
- Bản portable là migration cho bàn giao, **chưa phải benchmark hoặc generation pin mới**. Muốn dùng trong runtime, tạo config/preflight/pin mới theo HANDOVER. Không sửa pin/ledger lịch sử hoặc dùng portable hashes để giả tái lập một live run cũ.

## Trạng thái cần tiếp tục

Working source đã có bốn file đổi + một module mới so với pin v7 trước khi đóng gói. Gói giữ nguyên sự khác biệt đó; các lệnh dùng source hiện tại với pin cũ có thể bị chặn. Đây là việc cần xử lý tiếp theo, không phải lỗi thiếu inputs trong ZIP. Không tuyên bố dashboard/generation đã được nghiệm thu qua việc CRC thành công.

Bộ v7 còn 8 abstain, 1 provider_error và 15 not_run, chưa có model answer. Không trộn kết quả cũ để lấp. Đọc [HANDOVER.md](HANDOVER.md), [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md), tổng kết cuối [PROJECT_PROGRESS.md](PROJECT_PROGRESS.md). Giữ ba scenario, đề tài/mục lục và dashboard ba cột. Người nhận được chọn local/API LLM; trong mỗi bộ so sánh phải dùng cùng LLM/params cho RAG và GraphRAG.

## Nội dung đã lược hoặc làm sạch

[packaging/distribution_changes.json](packaging/distribution_changes.json) liệt kê exclusions và hashes của các bản đã che credential, không lưu giá trị secrets. README/HUONG_DAN_CHAY cũ được lưu dưới [docs/history](docs/history/) với credential đã che và cảnh báo nội dung lịch sử. Hai video demo tùy chọn không được đóng vì chưa kiểm từng frame; giữ 40 screenshots/QA reports và source quay demo. Không loại tests/fixtures, failed/rejected results hoặc toàn bộ outputs/review.

Thesis Word/đề cương PDF chính thức chưa có trong checkout và không nằm trong ZIP; có bản Markdown và lịch sử hiện có. Đây là bàn giao implementation/artifacts, chưa phải bộ hồ sơ nộp luận văn cuối. Các directories test scratch bị access denied đã được loại theo tên, không sửa quyền dự án gốc.

Không gọi LLM, benchmark, commit hoặc push để kiểm gói. API keys phải do người nhận tự cấu hình cục bộ; không đưa chúng vào artifacts/ZIP.
