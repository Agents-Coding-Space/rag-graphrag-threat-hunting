# Bộ câu hỏi mới được đề xuất, chưa đánh giá

`proposed_test_set.json` chứa **11 cases do AI đề xuất**: 5 `in_scope_sufficient_evidence`, 3 `in_scope_insufficient_evidence`, 3 `unrelated`, được giữ trong 9 semantic groups. Tất cả có `pending_human_review`, `reviewer=null`, `reviewed_at=null`. Approval của Ground Truth và 32 reference answers hiện có không áp dụng cho các nhãn mới.

Chưa query retrieval, chưa tính embedding, chưa gọi gate, chưa có kết quả và không dùng bất kỳ case mới nào để chọn threshold. Đây là tài liệu cho review nhãn và phạm vi, **không phải kết quả held-out độc lập**.

## Phạm vi của nhãn

Nhãn của 8 câu cùng kịch bản dựa trên **toàn file raw MSHTA**, rộng hơn hai nhóm process creation trong Ground Truth Core. Các trường/nhóm mới không được thêm vào Ground Truth, corpus, graph hoặc index. `expected_decision` của đề xuất nói về khả năng đáp ứng từ miền dữ liệu được ghi trong `label_domain`; không nói rằng context do frozen retrieval trả về đã đủ bằng chứng.

**Cả 5 positive cases cần chi tiết raw không có trong 19 chunks và frozen graph hiện tại.** Không được coi gate abstain trên những câu này là false abstain với context frozen, hoặc dùng chúng để tuyên bố policy hiện tại đã được kiểm chứng. Mỗi case giữ `sufficient_context_label=not_established_no_retrieval_run` và `included_in_held_out_metrics=false`. Approval nhãn sau này cũng không tự làm xuất hiện evidence trong corpus; cần quyết định rõ tính phù hợp của từng case với scope/context trước khi đánh giá.

Đề xuất này không tạo scenario thứ tư, không gán technique hoặc nâng nhãn an ninh. Những câu về hoạt động nền chỉ hỏi trường forensic trong cùng raw file. Nhãn `unrelated` của ba câu còn lại dựa trên phạm vi dataset và yêu cầu của câu hỏi; không giả tạo raw evidence cho chủ đề ngoài phạm vi.

## Các trường hợp cần review

| Case | Nhóm / nhãn | Căn cứ raw và yêu cầu mới |
| --- | --- | --- |
| `nt-raw-conhost-launch-detail` | conhost / đủ | Lines 36, 422 ghi command line `conhost.exe 0xffffffff -ForceV1`, PID cha/con; line 398 chỉ để đối chiếu parent GUID. Không đếm thành một MSHTA hoặc PowerShell mới. |
| `nt-raw-mshta-termination-status` | MSHTA lifecycle / đủ | Security 4689 line 42 có `Status=0x0`; Sysmon 5 line 452 có GUID/PID tương ứng creation line 275. Không coi exit status MSHTA là kết quả PowerShell/cmdlet. |
| `nt-raw-powershell-delete-records` | temporary-file lifecycle / đủ | Lines 612, 655, 782 có ba `TargetFilename`, `Archived="true"`, `IsExecutable="false"`. Chỉ liệt kê telemetry, không suy ý đồ phá hoại. |
| `nt-raw-network-owner` | background network / đủ | Security 5156 line 3 thuộc WindowsAzureGuestAgent, PID 3428, `192.168.2.5:52507 → 168.63.129.16:80`. Không gán connection này cho chuỗi MSHTA/PowerShell hoặc C2. |
| `nt-raw-log-clear-chronology` | eventlog clearing / đủ | Lines 1, 1126, 1127 ghi clear Security/System/Application. Hai record 104 nằm trong channel System; Message mới phân biệt System/Application được clear. Không dùng thứ tự dòng làm timestamp order toàn file. |
| `nt-missing-powershell-exit` | PowerShell lifecycle / thiếu | Lines 30/398 chỉ ghi launch; toàn file không có PowerShell termination Event 5/4689. Records exit 42/452 thuộc MSHTA. Không biết exit code/lifetime của PowerShell trong collection này. |
| `nt-missing-deleted-script-content` | temporary-file lifecycle / thiếu | Lines 648/649 và 655/782 có create/delete metadata và hashes; không có bytes của hai tệp `__PSScriptPolicyTest`. Archive flag không thay thế artifact archive. |
| `nt-missing-log-clear-caller` | eventlog clearing / thiếu | Lines 1, 1126, 1127 không cung cấp initiating process/command line. Account text hoặc timestamp proximity không tạo causal edge. |
| `nt-unrelated-printer-policy` | printer configuration / ngoài | Yêu cầu hướng dẫn Group Policy cho máy in, không phải câu hỏi về evidence MSHTA. |
| `nt-unrelated-tls-rotation` | TLS maintenance / ngoài | Yêu cầu vận hành certificate cho Nginx, không phải telemetry Windows/MSHTA. |
| `nt-unrelated-python-sequences` | Python semantics / ngoài | Yêu cầu giải thích list/tuple, không thuộc phạm vi dataset. |

Mỗi câu trong JSON có `reference_answer`, `label_rationale`, `missing_evidence`, raw refs và bản sao chính xác các original fields cần thiết. Không lấy quyết định của evaluator làm nhãn. Bản sao trường được kiểm tra bằng phép so sánh với record raw tương ứng sau streaming read.

## Lịch sử sử dụng và giới hạn độc lập

Đã đọc cả 32 câu và reference answers hiện có, các cấu hình calibration, summary/provenance của hai legacy calibration reports và corpus hiện tại. Hai legacy runs đều dùng đủ 32 cases, mỗi run 672 candidate policies; embedding comparison dùng 32 cases cho hai models và 64 rankings. 32 cases còn trải qua phân tích lỗi/review, gồm hai chỉnh query wording. Toàn bộ tiếp tục thuộc development/calibration, không chia lại để gọi một phần là held-out.

`split_manifest` nằm ngay trong JSON: 32 case IDs ở calibration; 11 IDs mới ở proposed-test quarantine; approved held-out rỗng. Cases cùng một semantic/evidence task group, ví dụ inventory và missing-content của cùng tệp hoặc inventory và causal attribution của cùng log-clearing records, phải đi cùng nhau nếu sau này có chia tập. Không chuyển một case cùng group sang calibration để chỉnh threshold rồi gọi case còn lại là held-out.

Các câu mới không trùng nguyên văn với 32 query cũ và hỏi các thuộc tính hoặc evidence requirements khác. Điều đó **không chứng minh độc lập về nghĩa, evidence hay dữ liệu**: cùng một file MSHTA; creation anchors 275/398 được dùng lại để liên kết identity; scope answer cũ đã nói có conhost, temporary deletion và log clearing; review trước đã thấy background connection. Mỗi case ghi `closest_previous_cases`, khác biệt intent và overlap này. Đây là new-task probes trong cùng dataset đã được xem, không phải dữ liệu chưa từng thấy hoặc test generalization sang scenario mới.

Trong corpus/graph frozen chỉ có hai nhóm core, phần lớn intents trả lời được đã có trong 32 cases. Vì vậy không tạo thêm positive core bằng đổi ID/cách diễn đạt để làm giả held-out. Bộ đề xuất đủ ba loại câu theo yêu cầu nhưng **chưa cung cấp positive-context held-out hợp lệ cho frozen experiment**. Review cần giữ rõ giới hạn này.

## Kiểm tra đã thực hiện

- Đọc streaming đủ 1.127 JSONL records; dropped `0`; min/max `TimeCreated` được giữ trong JSON. Không đổi hoặc sửa timezone-naive `UtcTime`.
- Event distribution có Sysmon 1: 3; 5: 1; 23: 3; Security 4688: 3; 4689: 1; 5156: 1; Eventlog 1102: 1; 104: 2. Full distribution được lưu trong JSON.
- Không thấy PowerShell Event 5/4689, Event 4103/4104 hoặc fields `ScriptBlockText`/`ScriptBlockId` trong collection. Đây là kiểm tra bounded theo file, không phải kết luận hành vi toàn hệ thống không xảy ra.
- SHA-256 raw trước/sau streaming và tạo proposal: `25aa24b5f631f19ac23f64db116c23e632295fb5f59040e966fa47e7758b2a32`.
- JSON readback khớp object đã ghi; 11 IDs duy nhất, không giao 32 IDs cũ; 9 proposed groups không giao nhau theo case assignment; tất cả metadata review vẫn null/pending; original fields khớp raw.
- Không chạy pytest, retrieval, embedding, gate hoặc threshold search trong phần chuẩn bị proposal này. Không tạo held-out results.

Các source SHA-256 cụ thể, case lists, nhãn/vocabulary và usage history nằm trong `proposed_test_set.json` để package review đối chiếu. JSON này là evaluation artifact; không đưa reference answers, expected decisions hoặc labels của nó vào corpus/graph/query embedding/gate input.
