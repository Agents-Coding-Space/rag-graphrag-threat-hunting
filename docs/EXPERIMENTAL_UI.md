# Demo UI experimental dùng evidence contract đã đánh giá

Ngày bàn giao: **29/10/2026, Asia/Bangkok**. Task này cho phép tích hợp UI xuyên suốt theo yêu cầu mới, thay giới hạn chỉ replay của tài liệu demo cũ và trạng thái lịch sử 14/10 trong `PROJECT_CONTEXT.md`/`AGENTS.md`. Không có human approval mới hoặc thay đổi benchmark. **Không gọi API LLM thật trong task.**

Giao diện riêng: `experimental.html`. Backend riêng chỉ expose `/experimental-api/*`, không expose production `/api/hunt` hoặc SSE sample. RAG/GraphRAG gọi cùng `prepare_branch` và `generate_branch` mà harness sử dụng trong `src/threat_hunting/evaluation/experimental_comparison.py`. Scope vẫn corpus-only. RAG vẫn không có graph evidence; GraphRAG vẫn traversal both/depth=2/nodes=100/edges=200. Không đưa expected labels/reference answers vào runtime.

Startup đối chiếu experimental config, artifacts, runtime manifest, policy, prompt/schema/guardrail/client/config và evidence-contract source hashes với manifest pilot đã chốt. Model/provider vẫn `generic_openai` / `openrouter/gemma-4-31b-it`, temperature 0, max_tokens 2048, timeout 120s; một attempt, không retry/fallback. Context/messages budget giữ 262144/294912 canonical UTF-8 bytes. Production policy không bị sửa hoặc tự migrate.

## Khởi động từ CMD

Dependencies, local E5 cache và frontend build đã có trên máy này. Một process phục vụ cả backend experimental và frontend:

```bat
cd /d D:\rag-graphrag-friend
.venv\Scripts\python.exe scripts\serve_experimental_ui.py --port 8002
```

Mở **http://127.0.0.1:8002/experimental.html**. Kiểm tra cấu hình tại **http://127.0.0.1:8002/experimental-api/config**: `mode=experimental_offline_demo`, cap=0. Không cần production backend 8000, replay 8001, Vite 5173 hoặc LLM router cho offline. Cổng 8002 hiện đã được chạy ở chế độ offline trong lượt bàn giao; nếu còn chạy thì mở URL ngay, không khởi động process thứ hai. `Ctrl+C` tại terminal chạy server để dừng.

Nếu cần build lại bằng dependencies hiện có:

```bat
cd /d D:\rag-graphrag-friend\frontend
npm run build
```

Mỗi lần khởi động tự tạo thư mục `outputs/demo/experimental-ui-<UTC timestamp>/`, từ chối ghi đè. Có thể chỉ định `--output outputs\demo\<new-name>`. Mỗi POST lưu request, cấu hình/provenance, scope, context, messages, gate, eligibility, evidence projection, raw/validation khi có generation và response/result. Không ghi vào `outputs/experiments/` hoặc review benchmark.

## Ba ca đã khóa và thao tác demo

Preset được đọc trực tiếp từ `outputs/review/live_llm_functional_smoke/cases.json`, có kiểm tra SHA-256 đã pin. Chọn case sẽ nạp nguyên query và đúng scenario. Không cần gõ lại câu hỏi.

| Case | Query nguyên văn | Quyết định đã kiểm tra RAG / GraphRAG | Requests live dự kiến cho cả hai nhánh |
|---|---|---|---:|
| PS02 | Dòng lệnh khởi chạy PurpleSharp.exe chứa những tham số /t nào? Hãy trích dẫn command line từ bằng chứng. | proceed / proceed | 2 |
| RG04 | Chỉ từ kết nối regsvr32.exe tới 10.10.10.5:8444, có thể kết luận những dữ liệu nào đã bị đánh cắp và dung lượng exfiltration bao nhiêu không? | abstain / abstain | 0 |
| RG05 | Hãy viết thực đơn ăn chay cho ba ngày và tính lượng calo mỗi ngày. | scope abstain / scope abstain | 0 |

1. Chọn **PS02**, chọn **RAG**, bấm **Chạy offline · 0 request LLM**. Kết quả là `dry_run_no_generation`: eligibility proceed, chưa có LLM answer. Chọn **GraphRAG** và làm tương tự. Mở context/messages/gate để đối chiếu. Bấm **Saved experimental replay · 0 request** để xem draft thật đã lưu của chính nhánh trong `rag-graphrag-pilot-source-contract-02`; giữ nhãn `saved_experimental_replay`, nguồn và review caveat. Không coi là generation mới. Draft có `/t T1110.003,T1558.003,T1135,T1021.006`; arguments không chứng minh technique thành công. Verdict SUSPICIOUS vẫn chưa được human xác nhận.
2. Chọn **RG04**, chạy offline từng nhánh. Giữ nguyên abstain, stage `evidence_answerability`, reason `explicit_requested_limit_not_returned`. Mở gate để xem các facets thiếu witness. Có observed connection không đủ để gate hiện tại cho qua yêu cầu exfiltration/bytes. Không sửa câu hỏi hoặc ép limited answer để pass.
3. Chọn **RG05**, chạy từng nhánh. Scope abstain trước retrieval, reason `investigation_task_not_recognized`, không context/generation. Không trả thực đơn và không dựng security report.
4. Với PS02, mở **Evidence và citations**: source JSON pointer, `source_file`, `raw_record_ref`, status, `source_ground_truth.sha256` và properties. Toàn bộ draft/evidence_refs cùng supplied context/messages đều có thể mở và tải JSON. ID tồn tại chưa xác nhận semantic support; giữ pending/candidate của nguồn.
5. Dùng panel **Kiểm tra UI bằng fixtures** để xem accepted/rejected, provider error, rate limited, abstain, dry-run, runtime error, cap và stop. Chúng mang nhãn `synthetic_fixture`, 0 requests và không được tính vào benchmark. `validation_failed` chỉ có rejected diagnostic, không có accepted-answer panel. Export JSON cũng giữ outcome và provenance. Loading hiển thị khi thao tác đang chờ backend.

## Live sau này — chỉ khi người dùng chủ động quyết định chạy

**Dự kiến 2 HTTP attempts tổng cộng** nếu chạy mỗi PS02/RG04/RG05 đúng một lần ở mỗi nhánh: PS02 RAG 1, PS02 GraphRAG 1, còn lại 0. Đây là số dự kiến từ offline gate hiện tại, không đảm bảo validation sẽ accept hoặc provider sẽ thành công. Chỉ demo một nhánh thì dự kiến 1. Không chạy lại khi gặp rejection để tìm output tốt hơn.

Lệnh dưới đây **chưa được thực thi trong task**. Dừng server offline trước, bật router đã cấu hình sẵn tại `http://127.0.0.1:20128/v1` bằng cách hiện có của người dùng, không sửa `.env`:

```bat
cd /d D:\rag-graphrag-friend
.venv\Scripts\python.exe scripts\serve_experimental_ui.py --port 8002 --live --max-requests 2
```

UI phải ghi `experimental_live_demo`, đúng model/provider và cap=2. Dùng nút **Chạy live**, mỗi case/branch một lần; nút saved replay không gọi provider. Cap áp dụng toàn session, các POST chạy tuần tự. 401/403/429 khóa generation còn lại của session; vẫn được kiểm tra gate, không retry/fallback. Các transport/protocol/timeout errors là provider_error; 429 là rate_limited; schema/guardrail rejection là validation_failed. Không có answer cho các trạng thái đó. Request mới khi hết cap có `not_run_request_limit`; khi bị stop có `not_run_after_stop`. Không suy ra router/upstream cũng không retry.

## Bằng chứng kiểm tra và giới hạn

- [Parity offline](../outputs/demo/experimental-ui-20261029-verification/parity/parity.json): 6/6 nhánh giống harness trước refactor và harness dùng chung về scope/context/messages/gate/eligibility/evidence projection; 0 LLM requests.
- [Tests cuối](../outputs/demo/experimental-ui-20261029-verification/tests-final.txt): 190 tests liên quan pass; frontend `npm run build` pass. Đây không phải full suite.
- [Browser QA](../outputs/demo/experimental-ui-20261029-verification/browser-final/browser_check.json): Edge headless trên trang thật, clicks, sáu offline branches, saved PS02 hai nhánh, fixtures, loading, export accepted/rejected và viewport 1440×1080 / 390×844. Ảnh thật nằm cùng thư mục. Không gọi provider.
- Có một lỗi riêng ở SSE production cũ: `tests/test_server_sse.py::test_sse_stream_abstained` vẫn trả sample flow cho câu thời tiết. Lỗi tái hiện khi chạy test riêng; file production `server/app.py` giữ nguyên. Service experimental không mount route này. Không sửa hoặc dùng SSE sample để demo kết quả experimental.
- Live transport/generation chưa kiểm tra trực tiếp theo yêu cầu không gọi API; headful desktop browser chưa kiểm tra riêng. Không suy structured validation thành semantic accuracy, không thay AI review bằng human approval.

Lệnh tái kiểm tra parity trên thư mục mới, không gọi provider:

```bat
cd /d D:\rag-graphrag-friend
.venv\Scripts\python.exe scripts\verify_experimental_ui.py --output outputs\demo\experimental-ui-offline-check-02
```

Original raw inputs không có trong checkout theo checkpoint; task này dùng đúng pinned derived artifacts, không tuyên bố fresh raw audit. Bộ 15×2, các saved generations, số liệu chốt, `.env`, prompt, thresholds và guardrail được giữ nguyên; integrity được đối chiếu riêng trong thư mục verification. Không commit/push.
