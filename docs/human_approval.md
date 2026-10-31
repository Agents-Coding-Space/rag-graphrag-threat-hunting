# Human approval metadata for the MSHTA review bundle

Prerequisite này chỉ ghi nhận việc người dùng duyệt Ground Truth MSHTA và 32 đáp án tham chiếu. `confirmed` tại `Ground Truth.review.review_status` xác nhận sự kiện phê duyệt tài liệu. Các nhãn evidence, Sigma và MITRE không đổi; approval không phải kết luận an ninh hoặc tín hiệu để gate quyết định `proceed`.

| Artifact | Version cũ | Version mới | Trạng thái chờ / đã duyệt | Human identity và thời điểm |
| --- | --- | --- | --- | --- |
| Ground Truth | `scenario-ground-truth/v1` | `scenario-ground-truth/v2` | `pending_human_review` / `confirmed` | `review.reviewer`, `review.reviewed_at` |
| Reference answers | `mshta-reference-answers/v1` | `mshta-reference-answers/v2` | `ai_review_completed_pending_human_approval` / `human_approved` | `review.human_reviewer`, `review.human_approved_at` |
| Review manifest | `mshta-technical-review/v1` | `mshta-technical-review/v2` | `pending_human_review` / `confirmed` tại `human_review_status` | `human_reviewer`, `human_approved_at` |

Schema v1 giữ nguyên trạng thái pending và bắt buộc human identity/time là `null` (manifest v1 chưa có hai fields này). Ground Truth builder vẫn mặc định phát sinh v1. V2 hỗ trợ cả pending và approved: pending bắt buộc hai fields `null`; approved bắt buộc reviewer string không trắng và ISO 8601 datetime hợp lệ có giây, timezone `Z` hoặc offset `±HH:MM`. Validator không tự suy ra thời gian hoặc danh tính. Không hỗ trợ trạng thái rejected/revoked hoặc ghi đè approval đã có.

Nâng version từ v1 pending sang v2 pending giữ nguyên ý nghĩa. Hàm thuần `approve_review_bundle` thực hiện chuyển pending → approved bằng metadata được cung cấp rõ ràng, kiểm tra bundle trước/sau và không thay đổi input. Ba artifact phải cùng pending hoặc cùng approved, cùng scenario, cùng reviewer và cùng chuỗi thời điểm. Hash Ground Truth trong answers và hash GT/answers trong manifest phải khớp bytes hiện tại. Manifest v2 có `approval_provenance` với `previous_artifacts` (hash cả ba artifact trước chuyển trạng thái), `basis` và `timestamp_basis` để giữ lịch sử.

`validate_reference_answers_document` và `validate_review_manifest_document` kiểm tra cấu trúc, vocabulary, kiểu dữ liệu và counts. `validate_review_bundle` kiểm tra liên kết trạng thái, identity/time, hashes, source provenance và evidence pointers. Cần kiểm tra hash thực tế của các file nguồn riêng; validator nhận document không tự đọc raw files. Khi dùng `approve_review_bundle`, input hashes dựa trên `serialize_review_document` (UTF-8, indent 2, newline cuối file); caller phải xác minh bytes ban đầu khớp serialization này trước khi dùng hashes để ghi nhận provenance vật lý.

Reviewer và ngày technical review `Codex`/`2026-10-14` trong answers/manifest giữ nguyên. Notes, answer constraints và một đáp án nhắc “pending” là nội dung lịch sử của technical review, được giữ nguyên theo yêu cầu bảo toàn đáp án. Metadata v2 là trạng thái human approval hiện tại. `analysis_status` vẫn `draft_reviewable`; đây không phải một schema kết luận attack đã được xác nhận.

Trong lượt ghi nhận này, người dùng xác nhận approval và chỉ định `Nguyen Hong Phong`. Thời điểm ghi nhận xác nhận là `2026-10-15T23:36:13+07:00`, lấy từ clock `2026-10-15 16:36:13 UTC` ở preflight đầu lượt. Đây là thời điểm ghi nhận xác nhận hiện tại; không suy đoán thời điểm một lần duyệt trước đó chưa có timestamp trong ngữ cảnh. Nguồn này được lưu trong `approval_provenance.timestamp_basis`.

Các corpus/graph/indexes/evaluation baseline giữ nguyên. Consumer contracts hiện vẫn dành cho provenance v1; một số builder sao chép `source_review_status` và sẽ từ chối `confirmed`. Cần review contract và rebuild có kiểm soát trong milestone tiếp theo. Không đưa human approval vào gate signals/decision output và không đưa reference answers vào retrieval/runtime input. Prerequisite này chưa chạy calibration, chưa mở held-out, chưa triển khai GRAPHRAG-2D3 hoặc sửa CLI.

Không chạy lại `outputs/review/mshta-ground-truth/assemble_review.py` lên bộ đã duyệt: script lịch sử tái tạo artifact pending và có thể ghi đè metadata approval. Bốn Markdown đã có thay đổi và các báo cáo technical review cũ được giữ nguyên; audit trước/sau của lượt này nằm riêng tại `outputs/review/mshta-human-approval/`.
