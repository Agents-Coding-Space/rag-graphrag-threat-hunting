# Experimental pipeline trong dashboard chính

Dashboard giữ nguyên `App.tsx` với `EvidenceSidebar`, `CytoscapeGraph`, `ChatPanel` và bố cục ba cột. Chế độ mặc định là Experimental, nhánh RAG, không bật Live. `experimental.html` vẫn là trang QA riêng có fixtures; dashboard chính không có fixture controls.

## Mở bản build hiện tại

Service experimental phục vụ cả dashboard tại `/` và trang QA tại `/experimental.html`. Không cần backend legacy để dùng chế độ experimental.

CMD tại repository, khi cổng 8002 trống:

```bat
cd /d D:\rag-graphrag-friend
.venv\Scripts\python.exe scripts\serve_experimental_ui.py --port 8002
```

- Dashboard chính: `http://127.0.0.1:8002/`
- QA riêng: `http://127.0.0.1:8002/experimental.html`

Lệnh trên mặc định offline, cap 0. Trong lần tích hợp 30/10/2026, cổng 8002 đã có session live cũ; session đó được giữ nguyên, chỉ đọc config, không gửi hunt. Service QA offline riêng đã được mở tại `http://127.0.0.1:8003/`, cap 0. Có thể mở lại service riêng bằng:

```bat
cd /d D:\rag-graphrag-friend
.venv\Scripts\python.exe scripts\serve_experimental_ui.py --port 8003
```

Không mở thêm process vào cổng đã có service. Nếu dùng lại 8002 offline, dừng service cũ từ terminal đã khởi động nó trước.

## Chạy qua Vite

CMD 1: service offline cổng 8002 như trên. CMD 2:

```bat
cd /d D:\rag-graphrag-friend\frontend
npm run dev -- --host 127.0.0.1 --port 5173 --strictPort
```

Dashboard: `http://127.0.0.1:5173/`. QA: `http://127.0.0.1:5173/experimental.html`.

Vite giữ proxy `/experimental-api` → `http://127.0.0.1:8002`, `/api` → `http://127.0.0.1:8000`. Chỉ khi chọn Dashboard legacy mới cần thêm CMD:

```bat
cd /d D:\rag-graphrag-friend
.venv\Scripts\python.exe run_backend.py
```

## Sử dụng

1. Giữ chế độ Experimental; chọn RAG hoặc GraphRAG và kịch bản.
2. Nhập câu hỏi tự do rồi Gửi offline. Nút Hiện gợi ý chỉ điền preset, không tự chạy hoặc khóa câu hỏi.
3. Offline chạy retrieval/gate và hiển thị evidence/context; `dry_run_no_generation` chưa có câu trả lời LLM. RAG không hiển thị graph. GraphRAG chỉ vẽ các nodes/edges từ `response.context.traversal`.
4. Để xem draft đã lưu mà không gọi LLM, chọn gợi ý PS02 rồi bấm Xem bản lưu. Nhãn `saved_experimental_replay`, số request mới bằng 0 và human review được giữ rõ ràng.
5. Mỗi lần gửi, sửa câu hỏi hoặc đổi chế độ/nhánh/kịch bản, dashboard xóa response/evidence/graph/selected node cũ. Response không khớp request hiện tại bị từ chối. Query abstain luôn để graph trống.
6. `accepted_draft` chỉ hiện answer khi validation `passed`, có report và không fallback. `validation_failed` chỉ hiện diagnostic; abstain/provider error/rate limit/cap/stop/runtime error không được chuyển thành accepted answer. Config và diagnostic kỹ thuật mặc định thu gọn.

Live cần **cả hai**: service được chủ động khởi động với `--live --max-requests N` (N từ 1 đến 30), và checkbox Bật Live tại dashboard. Dashboard đọc lại config trước mỗi hunt, chặn gửi nếu service live mà checkbox chưa bật. Không gửi thêm flags để thay gate/prompt/model/policy. Backend hiện có tiếp tục giữ global cap, stop sau 401/403/429, không retry/fallback. Không có provider request thật trong nhiệm vụ tích hợp.

## Contract đã dùng

Đọc trực tiếp `src/threat_hunting/server/experimental.py`:

- `GET /experimental-api/config`
- `POST /experimental-api/hunt`: `{ "query": "...", "scenario_id": "...", "branch": "rag|graphrag" }`
- `GET /experimental-api/saved?case_id=PS02&branch=rag|graphrag`
- `/experimental-api/fixture` chỉ được dùng bởi trang QA/tests, không có control trong dashboard.

Service và harness cùng gọi `prepare_branch`/`generate_branch`; không tạo một pipeline frontend khác. Evidence dùng nguyên `response.evidence_contract.units`, raw references, JSON pointers và source provenance. Không tải toàn bộ graph/evidence của scenario legacy vào chế độ experimental.

## Verification

```bat
cd /d D:\rag-graphrag-friend
node frontend\dashboard-checks.mjs
node frontend\qa-checks.mjs
.venv\Scripts\python.exe -B -m pytest tests/test_experimental_ui.py tests/test_experimental_comparison.py tests/test_ui_replay.py tests/test_source_evidence_contract.py tests/test_runtime_query_scope.py -q -p no:cacheprovider --basetemp=outputs/demo/dashboard-integration-20261030/pytest-rerun
.venv\Scripts\python.exe -B scripts\verify_dashboard_offline.py --output outputs/demo/dashboard-integration-20261030/http-rerun
cd frontend
npm run build
```

Các output directory cho smoke/pytest cần dùng tên mới nếu chạy lại. HTTP smoke mặc định chỉ gọi localhost:8003 và từ chối hunt nếu config là live. Smoke không phải browser QA.

Kết quả lần này: 87 backend tests pass; 12 checks frontend mới pass; 22 assertions legacy/QA pass; build pass. HTTP smoke câu hỏi tự do ngoài preset cho RAG/GraphRAG trả `dry_run_no_generation`, lần lượt 5/24 evidence units, 0/9 traversal nodes; PS02 replay hai nhánh accepted draft, 0 provider request mới.

Browser QA và ảnh thật **chưa hoàn tất**: Computer Use đã dừng vì browser Windows hiện tại chưa hỗ trợ URL policy enforcement. Không tiếp tục điều khiển browser hoặc tạo ảnh giả. Cần hoàn tất browser QA trên dashboard chính trước khi coi bàn giao UI được nghiệm thu trực quan. Kết quả và hashes nằm riêng trong `outputs/demo/dashboard-integration-20261030/`.
