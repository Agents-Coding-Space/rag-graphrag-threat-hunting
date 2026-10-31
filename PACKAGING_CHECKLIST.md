> Distribution note: this is the staged handover copy. Inputs are now included under data/. See START_HERE.md and packaging/path_migration.json for portable paths; dated instructions below describe earlier tasks.

# Checklist đóng gói bàn giao

Ngày đối chiếu: **31/10/2026, Asia/Bangkok**. Đây là hướng dẫn tự đóng ZIP; lượt này không tạo ZIP, không xóa/di chuyển/sao chép dữ liệu lớn. Đọc [HANDOVER.md](HANDOVER.md) trước khi chọn nội dung.

## 1. Thành phần bắt buộc

- [ ] Gửi [AGENTS.md](AGENTS.md), [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md), toàn bộ lịch sử [PROJECT_PROGRESS.md](PROJECT_PROGRESS.md), [HANDOVER.md](HANDOVER.md), checklist này và [.env.example](.env.example).
- [ ] Giữ [pyproject.toml](pyproject.toml), `.gitignore`, `.gitattributes`, [run_backend.py](run_backend.py), toàn bộ [src](src/), [scripts](scripts/), [configs](configs/), [benchmarks](benchmarks/).
- [ ] Giữ [frontend/src](frontend/src/), [package.json](frontend/package.json), [package-lock.json](frontend/package-lock.json), các HTML entry points và cấu hình Vite/TypeScript/Tailwind/PostCSS. Không chỉ gửi `dist` mà thiếu source.
- [ ] Giữ toàn bộ [tests](tests/) và [tests/fixtures](tests/fixtures/); fixtures nhỏ cần để kiểm parser, missing/nested fields, raw refs, correlation, source contracts, guardrails và ledger. Không loại tests vì dung lượng.
- [ ] Giữ [docs](docs/) và các tài liệu đề tài/mục lục/bản thảo đang dùng. Tài liệu luận văn gốc từng được nhắc trong context cũ chưa thấy ở root checkout này; chủ dự án bổ sung bản đề cương/luận văn chính thức nếu cần bàn giao phần viết. Không gọi bản Markdown hiện có là bản Word cuối đã nghiệm thu.

README và `HUONG_DAN_CHAY.md` hiện có **chuỗi có dạng credential** và chỉ dẫn/metrics cũ. Không gửi nguyên trạng hai file này: làm sạch bản phân phối, thay secret bằng placeholder, chỉ rõ hướng dẫn hiện hành là HANDOVER và loại claim không có nguồn hiện hành. Lượt tài liệu này giữ nguyên hai file gốc để không mở rộng phạm vi. Không chép giá trị credential vào checklist, ảnh hoặc log.

## 2. Artifacts và lịch sử cần giữ

Đơn giản nhất là giữ các outputs nghiên cứu có nguồn sau khi loại đúng cache/secret-bearing material bên dưới. Nếu đóng gói gọn, tối thiểu giữ **đầy đủ provenance closure**, không chỉ CSV cuối:

- [ ] [outputs/canonical/mordor-selected-v2](outputs/canonical/mordor-selected-v2/), [outputs/mordor_inspection](outputs/mordor_inspection/), [outputs/evidence](outputs/evidence/), [outputs/ground_truth](outputs/ground_truth/), [outputs/retrieval](outputs/retrieval/), [outputs/graph](outputs/graph/), [outputs/evaluation](outputs/evaluation/) và [outputs/v2](outputs/v2/) khi còn được các manifest/script/lịch sử tham chiếu.
- [ ] [outputs/review/mshta-ground-truth](outputs/review/mshta-ground-truth/) gồm GT/answers/manifest/report; [mshta-human-approval](outputs/review/mshta-human-approval/) và [docs/human_approval.md](docs/human_approval.md). Giữ các báo cáo calibration/fix1–fix3/semantic review và manifests kiểm chứng trong [outputs/review](outputs/review/). Không bỏ toàn bộ review.
- [ ] [outputs/offline/requirements_gap_20261030_v1](outputs/offline/requirements_gap_20261030_v1/) gồm raw input inventory, authentication survey/correlation, CTI corpus/extracted text/HTML snapshots. Giữ [harness_recovery_20261030_v1](outputs/offline/harness_recovery_20261030_v1/) và [http402_recovery_20261031_v1](outputs/offline/http402_recovery_20261031_v1/) để thấy trạng thái source delta chưa hoàn tất.
- [ ] [outputs/integrated](outputs/integrated/) v1–v6: đặc biệt `20261030_v1/cti_auth_sources/`, `20261030_v5/cti_auth/`, `20261030_v5/consumers/` cả ba scenario, surveys/build/coverage/source manifests; v6 audits/pins/report. V1–V4 phần lớn diagnostic nhưng có CTI snapshot v1 đang là dependency thật.
- [ ] [outputs/final/20261031_direct_v7](outputs/final/20261031_direct_v7/) gồm preflight cả 24 nhánh, pin/version/source/budget manifests, closeout states, saved-results index, results CSV/JSON, semantic review và thesis facts. Không reset hoặc bỏ `request_budget.json`.
- [ ] Các run trong [outputs/experiments](outputs/experiments/) được [HANDOVER.md](HANDOVER.md) liệt kê: giữ `manifest.json`, `configuration.json` nếu có, `results.json`, `progress.json`, từng branch context/messages/gate/eligibility/result, accepted/rejected/raw reports và hashes. Run v7 gốc chỉ một completed row; không thay bằng closeout 24 rows.
- [ ] [outputs/demo](outputs/demo/) giữ replay/session manifests, saved branch artifacts, exports và QA reports/ảnh thật liên quan, đặc biệt [v5 screenshot](outputs/integrated/20261030_v5/browser_qa_final/integrated-dashboard.png) và [v7 dashboard QA](outputs/final/20261031_direct_v7/dashboard_qa.json). Không dùng ảnh v5 như ảnh v7.

Giữ failed/rejected/not_run/error history để truy vết; chỉ lược log tạm khi thông tin cần thiết đã có trong report/manifests. `runtime_before`, `source_before`, `before_hashes.json`, JUnit/test logs có thể là bằng chứng của source delta: không mặc định chúng là cache. Quét secrets trước khi gửi vì có source snapshots chứa tài liệu cũ.

## 3. Mười inputs ngoài thư mục dự án

**Trong checkout `D:\rag-graphrag-friend` chưa có thư mục `data`.** Cả mười file hiện tồn tại tại thư mục anh em `D:\rag-graphrag-threat-hunting\data`. ZIP chỉ thư mục friend sẽ thiếu inputs gốc, dù có sẵn derived consumers. Không sao chép chúng trong lượt này.

Các đường bên dưới tính từ `D:\rag-graphrag-threat-hunting\data\` (giữ nguyên cách viết `burte_force` đang có):

| File bắt buộc | Đường tương đối trong data |
| --- | --- |
| `purplesharp_ad_playbook_I_2020-10-22042947.json` | `raw/mordor/burte_force/purplesharp_ad_playbook_II/purplesharp_ad_playbook_I_2020-10-22042947.json` |
| `cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json` | `raw/mordor/powershell/cmd_mshta_vbscript_execute_psh/cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json` |
| `empire_launcher_sct_regsvr32_2020-07-21232741.json` | `raw/mordor/c2_network/empire_launcher_sct_regsvr32/empire_launcher_sct_regsvr32_2020-07-21232741.json` |
| `enterprise-attack.json` | `knowledge/Mitre/enterprise-attack.json` |
| `win_security_susp_rc4_kerberos.yml` | `knowledge/sigma/selected/brute_force/win_security_susp_rc4_kerberos.yml` |
| `proc_creation_win_regsvr32_http_ip_pattern.yml` | `knowledge/sigma/selected/c2_regsvr32/proc_creation_win_regsvr32_http_ip_pattern.yml` |
| `proc_creation_win_regsvr32_susp_child_process.yml` | `knowledge/sigma/selected/c2_regsvr32/proc_creation_win_regsvr32_susp_child_process.yml` |
| `proc_creation_win_regsvr32_susp_parent.yml` | `knowledge/sigma/selected/c2_regsvr32/proc_creation_win_regsvr32_susp_parent.yml` |
| `proc_creation_win_mshta_susp_child_processes.yml` | `knowledge/sigma/selected/powershell/proc_creation_win_mshta_susp_child_processes.yml` |
| `proc_creation_win_mshta_susp_execution.yml` | `knowledge/sigma/selected/powershell/proc_creation_win_mshta_susp_execution.yml` |

- [ ] Người đóng gói bổ sung đúng mười file, giữ nguyên bytes và filename; gửi kèm manifest ánh xạ vị trí mới và SHA-256. Không lấy rule “gần giống” thay thế.
- [ ] Nếu không kèm data, ghi rõ nguồn tải lại: OTRF Security-Datasets/Mordor theo exact filename; SigmaHQ theo filename **và hash snapshot đã dùng**; MITRE theo commit URL trong [mitre manifest](configs/knowledge/mitre_enterprise_attack.json). Bản mới nhất trên mạng có thể khác hash; không gọi là tái lập nếu chưa khớp.
- [ ] Dùng [source_verification.json](outputs/final/20261031_direct_v7/source_verification.json), `verified_gt_input_provenance` và `raw_logs` để kiểm hashes, cùng [canonical manifest](outputs/canonical/mordor-selected-v2/manifest.json). Manifest provenance có một số key trùng input theo vai trò; 21 entries không phải 21 external files.
- [ ] Giữ cả ba CTI snapshots trong outputs đã nêu ở mục 2. Các đoạn trong `configs/knowledge/cti_*.json` là lựa chọn/bối cảnh, không thay thế HTML snapshot, extracted text và citation offsets.
- [ ] Derived password-spray correlation nằm trong [configs/knowledge/derived](configs/knowledge/derived/), không phải external input thứ 11. Các raw/reference bị loại khỏi active experiment giữ read-only nếu có gửi kèm và phải ghi nhãn reference.

## 4. Model cache và các đường dẫn không portable

- [ ] E5 snapshot đang ở ngoài repo: `C:\Users\phong\.cache\huggingface\hub\models--intfloat--multilingual-e5-small\snapshots\614241f622f53c4eeff9890bdc4f31cfecc418b3`. Người nhận cần chuẩn bị **đúng model/revision** ở Hugging Face cache của họ để query offline. Nếu chủ dự án kèm cache, giữ files/blobs/symlink targets cần thiết, không đóng nguyên user home. Chỉ gửi index JSON chưa đủ để embed câu hỏi mới.
- [ ] `configs/knowledge/mitre_enterprise_attack.json` trỏ `data/knowledge/Mitre/enterprise-attack.json`, nhưng vị trí thật hiện ở thư mục anh em. Discovery CLI cần data root thực; đừng mặc định checkout chứa raw.
- [ ] GT `input_provenance`, canonical/source manifests, run `configuration.json`, ledger `attempts[].batch`, final live manifest `preflight` còn absolute paths tới hai project roots cũ. Một số GT provenance còn ghi absolute path bên trong `D:\rag-graphrag-friend`. Phải kiểm cả đường ngoài **và trong** thư mục cũ khi chuyển máy.
- [ ] Không tìm-thay thế trực tiếp trong historical manifests/GT/ledger/pins: sẽ đổi hashes hoặc phá replay/recovery bindings. Giữ bản gốc; tạo migration manifest/version/config/pin mới cho working copy, ghi old→new paths và hashes; kiểm lại provenance closure. Nếu phục hồi layout cũ, xác minh thật các file, không chỉ tạo thư mục rỗng.
- [ ] Working source hiện có bốn tệp đổi + một module mới chưa pin. Đóng gói cả source hiện tại lẫn pin/history, kèm cảnh báo trong HANDOVER; không sửa source/pin lịch sử chỉ để startup qua kiểm tra. Chưa có execution delta pin hoàn tất để gửi như bản “đã chạy được”.

## 5. Có thể loại khỏi bản phân phối

- [ ] `.venv/`, `frontend/node_modules/`, `__pycache__/`, `*.pyc`, `.pytest_cache/`, `pytest-cache-files-*`, các thư mục pytest temp đã xác định chỉ là scratch.
- [ ] `frontend/dist/`, build/cache tái tạo được nếu đã kèm source/lockfile và hướng dẫn build. Nếu muốn replay ngay có thể giữ dist, nhưng phải ghi rõ build nào; không dùng dist cũ như bằng chứng code mới đã build.
- [ ] ZIP trùng trong outputs/review/experiments nếu đã kèm thư mục nội dung đầy đủ và hashes; không xóa bản gốc ở máy hiện tại.
- [ ] Browser profiles, cookie/cache/session storage, `outputs/demo/integrated-v5-browser-profile/` và các `browser-profile/` lồng trong demo. Giữ QA JSON/screenshot bên ngoài profile; profile trình duyệt không cần cho tái lập và có dữ liệu tài khoản.
- [ ] Logs tạm/rác sau khi xác định không là nguồn duy nhất của test command, exception, operator stop hoặc metric. Giữ logs/JUnit quan trọng dù run không đạt.

Một số test-temp directories đang access denied; lượt này không đổi quyền để đọc. Không đưa chúng vào ZIP theo kiểu sao chép mù, cũng không tuyên bố đã rà nội dung của chúng.

## 6. Secrets tuyệt đối không đưa vào ZIP

- [ ] `.env`, các `.env.*` thật; chỉ giữ `.env.example` key rỗng, không dùng `Compress-Archive *` mà quên file ẩn và exclusions.
- [ ] API keys, bearer tokens, passwords, private keys, credential store/SQLite DB, provider/account settings, exported shell environment, request/response headers, cookies và browser profiles.
- [ ] Chuỗi credential trong README, HUONG_DAN_CHAY, source snapshots, logs, ảnh/video hoặc file ZIP cũ. Không assume key mẫu/hết hạn là an toàn để gửi; làm sạch bản phân phối và kiểm lại. Không đưa file backup `.env` vào outputs.
- [ ] Machine/user paths không liên quan. Các đường dữ liệu thực nghiệm cần cho provenance giữ trong history có mục đích rõ ràng; migration manifest dùng đường mới cần thiết, không dump home/config databases.

## 7. Kiểm trước khi nén và sau giải nén

- [ ] Có inventory file→size→SHA-256 của bản phân phối; các tài liệu vừa làm sạch là bản phân phối có ghi nhận khác bản lịch sử.
- [ ] Kiểm lại đủ inputs/extracted text/model cache và các liên kết tài liệu; đọc JSON back, đối chiếu registry/pin/provenance. Pin runtime hiện lệch phải được ghi rõ cho người nhận.
- [ ] Máy nhận có Python/frontend dependencies đầy đủ; không hiểu `pyproject.toml` hiện tại là đã pin đủ backend dependencies.
- [ ] Không đưa log/metric của các phiên bản khác vào final result để lấp not_run; giữ riêng live checkpoint và derived closeout.
- [ ] Sau giải nén, thực hiện kiểm offline theo HANDOVER với output mới, không tự phát sinh generation. Việc kiểm trên máy nhận là bước nghiệm thu sau này, không phải yêu cầu chạy lại thực nghiệm ở lượt soạn hồ sơ này.
