# Demo mốc thực nghiệm đã chốt — offline/replay

> **Bổ sung 29/10/2026 theo task tích hợp UI riêng:** demo xuyên suốt với common experimental evidence contract nằm tại [EXPERIMENTAL_UI.md](EXPERIMENTAL_UI.md), cổng 8002, mặc định offline. Hướng dẫn bên dưới giữ nguyên cho replay lịch sử; không dùng replay lịch sử như output của UI experimental mới. Benchmark 15×2 và số liệu đã chốt không thay đổi.

Mục đích: trình bày kết quả và cách truy vết bằng chứng, gồm cả abstain và validation_failed. Không gọi API LLM, không generation mới, không đổi runtime. Nguồn chính là [review tổng hợp](../outputs/review/rag_graphrag_combined_semantic_20261027/) và [screenshot_plan.md](../outputs/review/rag_graphrag_combined_semantic_20261027/screenshot_plan.md). Caption luôn ghi **REPLAY/OFFLINE — từ saved live runs, AI-assisted review, human review pending**.

**Đã đóng lượt đo.** Recheck chỉ xác minh tái lập; pilot/full live mới không phải bước chuẩn bị demo hoặc điều kiện nộp. Bộ ảnh đề nghị là **4 document replay + 2 historical UI replay** ở mục 2; nếu không dùng browser, chụp 4 document replay là đủ phạm vi minh họa này. Không cần lặp calibration, benchmark hoặc review/generation đã hoàn tất.

## 1. Khởi động đúng thành phần

### Demo kết quả hai lượt đã tổng hợp: mở tài liệu replay

Sáu cards có sẵn là Markdown replay, không cần backend, frontend dev server, database, embedding model hoặc provider router. Trong CMD:

```bat
cd /d D:\rag-graphrag-friend
code outputs\review\rag_graphrag_combined_semantic_20261027\report.md outputs\review\rag_graphrag_combined_semantic_20261027\replay
```

Lệnh `code` chỉ dùng nếu VS Code đã có trong PATH; nếu không, mở VS Code bằng Start Menu → File → Open Folder → chọn thư mục `replay` trên. Với mỗi `.md`, dùng `Ctrl+Shift+V` để mở Preview, hoặc `Ctrl+K V` để Preview cạnh source. Không cần cài plugin hoặc truy cập mạng.

### Demo đúng UI component: dịch vụ replay hiện có, minh họa bổ sung

Nếu cần trình bày giao diện thật với **fixtures lịch sử**, server có sẵn phục vụ cả frontend build và read-only replay transport trong một process. Từ CMD:

```bat
cd /d D:\rag-graphrag-friend
.venv\Scripts\python.exe scripts\serve_ui_replay.py --port 8001
```

Giữ cửa sổ này; mở browser bằng tay tới:

```text
http://127.0.0.1:8001/qa-api/health
http://127.0.0.1:8001/qa.html?case=MS04
http://127.0.0.1:8001/qa.html?case=MS01
http://127.0.0.1:8001/qa.html?case=RG05
```

Health phải ghi `mode=replay_only`, `llm_routes=false`; UI phải có replay provenance. MS04 minh họa draft có giới hạn, MS01 rejection lịch sử, RG05 abstain lịch sử. Có thêm `?case=provider_error`, `?case=rate_limited`, `?case=loading`: đây là **synthetic UI fixtures**, không phải lỗi đã xảy ra trong hai lượt đo. Không dùng chúng để tăng số provider errors trong kết quả.

**Nguồn UI này khác hai lượt đã tổng hợp.** `scripts/serve_ui_replay.py` đang allowlist responses từ `rg04_generation_fix`, `live_llm_fixes` và `three_case_corrective_regression`; nó không nạp pilot/remaining source-contract. Không được chụp UI đó rồi ghi là output của các cặp trong bảng kết quả mới. Muốn trình bày chính xác hai lượt mới mà không sửa runtime, dùng sáu Markdown cards phía trên. Task này không đổi adapter/allowlist để đưa dữ liệu mới vào UI.

Điều kiện cục bộ: `.venv` và `frontend/dist/qa.html` có sẵn ở mốc chốt. Nếu build thiếu trên máy khác, dùng terminal riêng:

```bat
cd /d D:\rag-graphrag-friend\frontend
npm run build
```

Chỉ dùng dependencies đã có; không tự `npm install`, không đổi package/config. Nếu thiếu dependencies/build không chạy, tiếp tục demo Markdown. Không cần chạy production backend cổng 8000, Vite cổng 5173 hoặc router LLM cổng 20128. Không gọi `/api/hunt`, SSE sample hoặc nút gửi production query. Kết thúc replay server bằng `Ctrl+C` ở terminal của chính process.

**Đã chuẩn bị dịch vụ trong lượt chốt demo:** replay server cổng 8001 đã khởi động; GET local xác minh health `replay_only/llm_routes=false`, trang QA HTTP200, MS04 `proceed` + validation `passed`, MS01 `validation_failed`, RG05 `abstained`. Không gọi provider. Bằng chứng tại [replay_service_check.json](../outputs/review/experimental_demo_ready_20261027/replay_service_check.json). Nếu server vẫn chạy thì mở URL ngay; chỉ chạy lệnh khởi động khi đã tắt. Chưa kiểm thử trực quan browser hoặc chụp ảnh, nên không dùng HTTP check làm chứng cứ layout/click/export đã QA.

## 2. Bộ 4–6 ảnh thật và thao tác cụ thể

Ảnh 1–4 lấy từ files dưới `outputs/review/rag_graphrag_combined_semantic_20261027/replay/`. Ảnh 5–6 là UI fixtures lịch sử, tách nguồn rõ ràng. Lưu ảnh thật vào thư mục đã tạo [screenshots](../outputs/review/experimental_demo_ready_20261027/screenshots/), không ghi vào artifacts gốc. Không có ảnh sẵn được giả lập trong thư mục này.

| Ảnh / tên lưu | Thao tác để chụp | Phần cần thấy và caption dùng trong đồ án |
|---|---|---|
| 1. `01_document_overview.png` | Mở `01_overview.md` → `Ctrl+Shift+V` → đưa bảng kết quả vào khung; nếu cần xem thêm `report.md` mục 2. Nhấn `Win+Shift+S`, chụp vùng Preview thật. | Banner document REPLAY/OFFLINE, 30 nhánh, 13 accepted/4 rejected/13 abstain, AI/pending. Caption: **Document replay — tổng hợp hai lượt saved live; status vận hành không phải accuracy.** |
| 2. `02_document_RG03_citation.png` | Mở `03_RG03_pair.md`, Preview phần `RG03_rag`; chụp câu hỏi/direct_answer và phần refs trong technical_analysis. Cuộn vừa đủ, giữ tên file/case; giữ qualifier nếu nằm trong khung. Không nhập lại query. | Endpoint10.10.10.5:8444, Sysmon Event3/ref1001, nguồn pilot-source-contract-02, draft cần review. Caption: **Document replay — RG03 RAG, câu trả lời và citation từ saved output; chưa chứng minh HTTP completion/content/C2 purpose.** |
| 3. `03_document_MS02_rejected.png` | Mở `04_MS02_graph_rejection.md`; mở [validation gốc](../outputs/experiments/rag-graphrag-remaining-source-contract-01/MS02_graphrag/validation.json) và [raw report](../outputs/experiments/rag-graphrag-remaining-source-contract-01/MS02_graphrag/raw_report_before_sanitize.json) cạnh Preview bằng split editor. `Ctrl+F` tìm `assessment_promotion` và `confidence`; dùng `Alt+Z` để wrap JSON nếu cần. | `validation_failed`, raw confidence=candidate, source support=supported_by_observed_behavior, reason. Caption: **Document replay — MS02 GraphRAG bị strict validator từ chối; confidence vocabulary mismatch không chứng minh model nâng confirmed.** |
| 4. `04_document_abstain.png` | Mở `06_abstain.md` → Preview; chọn vùng MS03_rag và reason `core_boundary_not_returned`. Nếu khung đủ chỗ, thêm phần RG02_rag; nếu không thì giữ MS03, không thu nhỏ đến mức khó đọc. | Nhãn abstain, query, benchmark FN/context boundary thiếu, không LLM answer. Caption: **Document replay — abstain được review theo context; không mặc định mọi rejection đúng hoặc mọi bằng chứng vắng mặt.** |
| 5. `05_historical_UI_MS04.png` | Mở `http://127.0.0.1:8001/qa.html?case=MS04`, đợi saved response tự hiện; chỉnh zoom/scroll panel để thấy answer và validation/human-review label. Không bấm Gửi. `Win+Shift+S` chụp cả header nguồn và panel. | REPLAY/MOCK, source file của three_case_corrective_regression, validation passed, câu trả lời giới hạn completion/output/service state. Caption: **Historical UI replay — MS04 corrective regression cũ, chỉ minh họa component ứng dụng; không phải output của hai lượt trong bảng thực nghiệm.** |
| 6. `06_historical_UI_MS01.png` | Mở `http://127.0.0.1:8001/qa.html?case=MS01`; chụp header nguồn và panel báo rejected/validation issues, kèm nút diagnostic nếu thấy. Không gửi lại câu hỏi hoặc tải như accepted report. | REPLAY/MOCK, source lịch sử, validation_failed, không trình rejected như accepted answer. Caption: **Historical UI replay — MS01 corrective regression cũ; minh họa cách giao diện xử lý rejection, không thay MS01 source-contract trong kết quả đo.** |

Ảnh 1–4 là bộ tối thiểu; ảnh 5–6 bổ sung giao diện. Không cần chụp tất cả cards hoặc toàn report trong một hình. Nếu muốn minh họa arguments thay endpoint, thay ảnh 2 bằng `02_PS02_pair.md`, giữ bốn `/t` IDs, host, refs16/19 và nhãn SUSPICIOUS chưa duyệt; đổi filename/caption tương ứng. `05_MS01_rag_rejection.md` là lựa chọn thay cho ảnh 3 nếu ưu tiên representation gap. Không thêm các lựa chọn này thành ảnh bắt buộc.

Nếu muốn UI abstain thay UI rejection, dùng `http://127.0.0.1:8001/qa.html?case=RG05` và caption **Historical UI replay — RG05 abstain từ live_llm_fixes, không phải RG05 của lượt tổng hợp**. Các synthetic provider_error/rate_limited/loading chỉ là minh họa bổ sung, không cần chụp cho bộ 4–6 này.

Giữ banner/source trong ảnh khi có thể. Nếu phải cuộn sâu để xem field, giữ tab/case và ghi source đầy đủ trong caption dưới hình; không sửa output hoặc ghép thêm banner giả. Câu hỏi lấy nguyên văn từ card/case_pairs.csv, không gọi lại để lấy câu trả lời mới.

Caption mẫu:

> REPLAY/OFFLINE — PS02 RAG/GraphRAG, nguồn `rag-graphrag-pilot-source-contract-02`; không request LLM mới. AI-assisted semantic review, human approval pending. Accepted draft không xác nhận mọi nhận định trong report.

Nếu minh họa UI fixtures bổ sung, caption phải đổi sang **Historical UI replay** hoặc **Synthetic UI fixture**, giữ source file thật mà màn hình hiển thị; không dùng caption pilot/remaining.

## 3. Chụp thủ công khi browser không khả dụng

Browser automation trước đây bị URL policy của Cốc Cốc chặn; lần soạn này không thử lại và không tạo ảnh. Nếu browser không mở được, vẫn hoàn tất phần minh họa saved results bằng VS Code Markdown Preview:

1. Mở card theo bảng, Preview cạnh source; điều chỉnh zoom để banner/source/status và claim/citation liên quan cùng xuất hiện.
2. Với rejection, mở JSON gốc cạnh card; giữ cả reason và raw value, không chỉ phần answer đã sanitize.
3. Nhấn `Win+Shift+S`, chụp vùng Preview/JSON đang thấy; lưu ảnh thật vào một thư mục minh họa mới, tách artifacts gốc.
4. Ghi caption nguồn/branch/replay và pending review. Nếu phải chia ảnh, giữ caption ở cả hai; không ghép thành màn hình UI giả.

Nếu cần ảnh production component mà browser vẫn không hoạt động, ghi “chưa chụp được UI” và dùng ảnh tài liệu có nhãn **document replay**. Không giả ảnh browser hoặc gắn nhãn live cho replay. Hướng dẫn này không yêu cầu sửa policy trình duyệt, bật generation hoặc đổi cấu hình để có ảnh đẹp.
