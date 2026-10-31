# Việc còn lại trước khi nộp đồ án

**Mốc 27/10/2026:** chốt kết quả đã lưu và bản nháp [chương thực nghiệm](EXPERIMENTAL_RESULTS.md), chưa tự xác nhận toàn đồ án hoàn thành hoặc human approval. Danh sách dựa trên mục tiêu/đề cương ba chương và tiêu chí đánh giá ở [PROJECT_CONTEXT.md, mục 3–4 và 13](../PROJECT_CONTEXT.md). Không tự thêm yêu cầu production, số request mới, database service, holdout hoặc full test suite như điều kiện cản trở nộp bài.

**Đã đóng thực nghiệm:** recheck chỉ là kiểm tra tái lập. Không chạy lại pilot/full live, calibration, generation, aggregate hoặc chấm lại bộ regression đã hoàn tất để đáp ứng checklist này. Hai lượt live đã tổng hợp và ba tài liệu RESULTS/DEMO/SUBMISSION_CHECKLIST là mốc hiện hành; các kế hoạch live cũ chỉ còn giá trị lịch sử.

## 1. Bắt buộc đối với nội dung đồ án và tính trung thực của bàn giao

| Việc cần hoàn tất | Trạng thái hiện tại / cách hoàn thành có giới hạn |
|---|---|
| Hoàn thiện ba chương theo đề cương: nền tảng, thiết kế, xây dựng và đánh giá | Bản nháp chương thực nghiệm đã có; người dùng cần tích hợp vào bản đồ án chính, thống nhất thuật ngữ, hình/bảng và trích dẫn. Task này không sửa Word/PDF chính. |
| Mô tả đúng hệ thống đã xây, mục tiêu RAG–GraphRAG–LLM và contribution | Nêu hybrid baseline, graph expansion, local JSON artifacts, source evidence/provenance, gate/guardrail; phân biệt kiến trúc dự kiến với implementation. Không tuyên bố CTI ingestion/DB service/user study đã có nếu chưa có artifact. |
| Báo cáo kết quả có mẫu số và nguồn truy vết | Dùng CSV/JSON đã chốt; giữ accepted coverage khác accuracy, pure provider timer là chưa có, bytes khác tokens. Trình bày các trường hợp rejected/abstain và lỗi contract, không chỉ chọn output đẹp. |
| Bao quát tiêu chí đề cương: retrieval, mapping, đầy đủ, giải thích, hữu ích, so sánh, hạn chế | Có context review, mapping caveats, source traces và paired analysis. Độ hữu ích với chuyên viên và accuracy toàn report chưa đo bằng human study; phải ghi “chưa đo”, không điền điểm tự động hoặc bịa kết quả. |
| Chốt phạm vi ba scenario với người hướng dẫn/người dùng | MSHTA core và Regsvr32 selected slice có kết quả; PurpleSharp hiện chỉ launch. Mục tiêu phát hiện spraying/correlation và Kerberoasting đầy đủ chưa được lượt này chứng minh. Phải công khai khoảng trống và xác nhận phạm vi trình bày được chấp nhận; không tự bỏ mục tiêu gốc hoặc nhận launch slice là hoàn thành toàn kịch bản. |
| Phân biệt nhãn nguồn, AI review và human approval | Giữ candidate/not_assessed/pending theo artifacts. Người dùng đọc các kết luận cần duyệt bên dưới; nếu chưa duyệt thì bản nộp ghi rõ giới hạn, không tự ghi tên reviewer người dùng hoặc tỷ lệ human-verified. |
| Hoàn tất minh họa và mô tả tái lập | Chụp ảnh thật theo [demo](EXPERIMENTAL_DEMO.md), có caption replay/source. Nếu UI browser chưa chụp được, ghi giới hạn và dùng document replay có nhãn. Dẫn manifest/hash và phiên bản cấu hình, không kèm secrets. |
| Soát bản nộp cuối | Kiểm tra đánh số bảng/hình, trích dẫn nguồn dữ liệu/tri thức/phương pháp, consistency giữa abstract–kết luận–kết quả, định dạng theo mẫu nhà trường đang áp dụng. Danh sách này không tự đặt deadline, số trang hoặc biểu mẫu chưa được cung cấp. |

“Bắt buộc” ở đây là mô tả trung thực và hoàn thiện nội dung theo yêu cầu đã có. Nếu người hướng dẫn yêu cầu chứng minh toàn bộ password spraying/Kerberoasting, đó là khoảng trống chức năng cần quyết định phạm vi riêng; tài liệu này không tự cho phép chạy API hoặc mở thêm vòng triển khai để lấp khoảng trống. Không coi một tỷ lệ accepted cao hơn là bằng chứng đạt tất cả mục tiêu đề cương.

## 2. Cải thiện có thể đưa vào hướng phát triển

Những mục sau không phải điều kiện production mới áp lên mốc thực nghiệm này. Chỉ thực hiện khi có quyết định công việc riêng; không tune runtime theo pilot để tăng điểm.

- Independent/held-out questions, nhiều lần sinh mỗi nhánh, thêm scenario coverage và chấm bởi người đánh giá độc lập để đo độ ổn định/khả năng tổng quát.
- Chuẩn hóa adapter/validator representation và confidence vocabulary dựa trên contract đã công bố; giữ checkpoint gốc, kiểm tra tác động và đánh giá lại như cấu hình mới nếu triển khai.
- Đo retrieval relevance/completeness, claim-level citation precision/recall, mapping correctness và mức hữu ích bằng rubric/human study riêng; bổ sung pure provider timer/token usage khi có nguồn đo thật.
- Hoàn thiện PurpleSharp authentication correlation, tránh double-count endpoint/DC, và đánh giá ticket/RC4 evidence. Không dùng launch arguments để thay bằng chứng kết quả kỹ thuật.
- Mở rộng CTI ingestion, graph/index storage hoặc cơ sở dữ liệu khi có nhu cầu thực nghiệm cụ thể. Không coi việc chưa có Neo4j/vector DB là lý do tự động chặn nộp prototype hiện tại.
- Đưa saved outputs của hai lượt source-contract vào đúng UI replay adapter, kiểm tra browser/loading/export và cải thiện bố cục khi có task riêng. Hiện six cards là document replay, còn UI transport dùng fixtures cũ.

## 3. Các kết luận và cách diễn giải cần người dùng duyệt

Đây là danh sách quyết định **chưa có human approval**; không phải biểu mẫu đã ký. Không cần gọi thêm LLM để người dùng xem các artifacts hiện có.

| Nội dung cần duyệt | Căn cứ / lựa chọn diễn giải cần xác nhận |
|---|---|
| Phạm vi chốt chương thực nghiệm | Dùng regression 15×2 và các slices thực tế, đặc biệt PurpleSharp launch; công khai phần mục tiêu chưa được kiểm chứng. Nếu phạm vi chính thức rộng hơn, trao đổi với người hướng dẫn thay vì tự nâng mức hoàn thành. |
| Kết luận so sánh | Có thể nói GraphRAG có nhiều accepted drafts hơn trong tập này, kèm representation/validator confound; chưa kết luận chất lượng sinh tổng quát tốt hơn. |
| Ba raw verdicts MALICIOUS | PS01 GraphRAG, RG01 cả hai chưa được bằng chứng parent/launch đang hỏi hỗ trợ. Quyết định phần nhận định trong văn bản chính; không sửa outputs gốc. |
| Mười một verdicts SUSPICIOUS và nhãn pending | Chưa có căn cứ riêng đủ để ghi human-confirmed verdict. Có thể giữ nguyên trong replay như output cần review, không biến pending thành tỷ lệ sai. |
| Wording/scope PS03 GraphRAG và MS02 GraphRAG | Phạm vi INSUFFICIENT của PS03 chưa rõ; “thực hiện lệnh” của MS02 có qualifier nhưng dễ vượt launch. Đọc prose và qualifiers cùng nhau, không tự gán false refusal/completion claim. |
| Bốn structured rejections | Chấp nhận phân tích source-field/assessment-shape/confidence mismatch từ pre-sanitize như lỗi contract; không gọi cả bốn là hallucination hoặc successful answers. |
| False abstain theo dataset và context | MS03 cả hai thiếu boundary/completeness; RG02 RAG có URL summary nhưng thiếu field witness. Duyệt cách phân biệt benchmark FN với khả năng trả limited answer từ summary. |
| Review status của nguồn/technique | Các pending/candidate mappings vẫn giữ nguyên. Việc duyệt nội dung chương không tự promote GT/technique hoặc nâng approval của runtime artifacts. |

Nguồn xem nhanh: [semantic review](../outputs/review/rag_graphrag_combined_semantic_20261027/semantic_review.md), [annotations](../outputs/review/rag_graphrag_combined_semantic_20261027/semantic_annotations.json), [rejections](../outputs/review/rag_graphrag_combined_semantic_20261027/validation_failures.json), [bảng cặp](../outputs/review/rag_graphrag_combined_semantic_20261027/case_pairs.csv). Không có thao tác approve tự động trong các tài liệu này.

## 4. Trạng thái đóng mốc

Đã hoàn tất tổng hợp offline và bản nháp tài liệu có thể dùng cho chương thực nghiệm. Artifacts gốc và review tổng hợp được giữ nguyên. Không còn yêu cầu tự động chạy lại generation, đổi model/prompt/gate hoặc gọi API trong mốc này. Việc tích hợp bản nộp, ảnh chụp thật và các quyết định human review/phạm vi vẫn thuộc người dùng; các điểm chưa đo được được ghi thành giới hạn thay vì tạo thêm vòng tinh chỉnh.

## 5. Công việc tích hợp vào bản đồ án chính

Đây là việc biên tập và bàn giao, không phải một vòng thực nghiệm mới. Task hiện tại không tự sửa bản Word/PDF chính.

| Vị trí theo đề cương | Thao tác còn thiếu | Nguồn đã có để đưa vào |
|---|---|---|
| Chương 2, thiết kế mô hình | Đối chiếu mô tả/diagram với implementation; ghi hybrid RAG và graph expansion, source contract, gate và validator khác vai trò. Đồng bộ thuật ngữ giữa chương 2 và 3. | `EXPERIMENTAL_RESULTS.md` mục 2, code/config links; không cần triển khai thêm kiến trúc. |
| Chương 3.1–3.2 | Đưa cấu hình model/E5, nguồn và giới hạn slice, phần mềm/JSON artifacts vào bản chính; phân biệt dữ liệu nguồn với số samples đánh giá. | `EXPERIMENTAL_RESULTS.md` mục 1–3 và manifests đã lưu. |
| Chương 3.3 | Viết ba scenario đúng mức evidence; giải thích PurpleSharp launch slice thay vì nhận đủ spraying/Kerberoasting. Lấy case analysis và 4–6 ảnh thật có caption. | Mục 6 của RESULTS, `EXPERIMENTAL_DEMO.md`; xác nhận phạm vi trình bày với người hướng dẫn nếu cần, không tự hứa thêm implementation. |
| Chương 3.4 | Chèn bảng outcomes/semantic/citations/timing và phân tích cặp; ghi rõ mẫu số, AI review, 15/17 pending khác tỷ lệ sai, bytes khác tokens. | RESULTS mục 4–7, CSV/JSON gốc; chỉ định dạng lại bảng, không chạy lại đánh giá. |
| Kết luận/hạn chế/hướng phát triển | Đồng bộ với kết quả: không gọi accepted coverage là accuracy, không tuyên bố GraphRAG sinh tốt hơn từ validation pass, không gọi regression là independent. Giữ các hạn chế chưa đo được. | RESULTS mục 8; các quyết định cần người dùng duyệt ở mục 3 checklist này. |
| Hình/bảng/phụ lục/tài liệu tham khảo | Chụp và chèn ảnh thật, đánh số/cross-reference, dẫn dataset/Sigma/MITRE/phương pháp; thêm bảng truy vết artifacts/hashes và mô tả chạy replay. Soát format theo mẫu nhà trường đang dùng. | DEMO mục 2, RESULTS mục 9, manifests và review files. Không ZIP mới hoặc kèm secrets. |

Chưa có human approval cho semantic review mới; người dùng chỉ cần quyết định cách diễn giải/phạm vi và hoàn thiện bản nộp. Không coi pending review hoặc phần chưa đo được là lý do tự động lặp calibration, tune runtime hay gọi thêm LLM.
