# Đáp án tham chiếu MSHTA–PowerShell

Review kỹ thuật: Codex, 14/10/2026. Phê duyệt của con người còn pending.

32 câu: 16 proceed, 8 thiếu bằng chứng, 8 ngoài phạm vi. Hai câu được làm rõ cách diễn đạt; không đổi nhãn.

Đáp án chỉ dùng cho đánh giá, không đưa vào retrieval corpus hoặc runtime gate input. Đây là calibration set, chưa phải benchmark độc lập.

## 1. rd-en-process-chain

**Câu hỏi:** Which process chain led to powershell.exe in the reviewed evidence?

**Nhãn:** `relevant_direct` / `proceed`; context target `answer_support`.

**Đáp án:** Chuỗi được quan sát trên WORKSTATION5 là cmd.exe → mshta.exe → powershell.exe. fact-cmd-spawns-mshta và fact-mshta-spawns-powershell ghi hai quan hệ có hướng; Sysmon 1 ở lines 275/398 và Security 4688 ở lines 4/30 là các góc telemetry hỗ trợ cùng hai lần tạo tiến trình, không phải bốn lần tạo riêng.

**Ground truth pointers:** `/evidence/0`, `/evidence/1`, `/facts/0`, `/facts/1`, `/relationships/0`, `/relationships/1`, `/scenario`

**Log gốc:** `jsonl:line:275`, `jsonl:line:30`, `jsonl:line:398`, `jsonl:line:4`

## 2. rd-en-shell-parent

**Câu hỏi:** Which process is the observed parent of powershell.exe?

**Nhãn:** `relevant_direct` / `proceed`; context target `answer_support`.

**Đáp án:** Tiến trình cha của powershell.exe là mshta.exe. fact-mshta-spawns-powershell liên kết process-9c691740bde5d3dbdc4e với process-9f7ceeecb4cd61358ab7; evidence-b31714b888d1489a380c giữ refs jsonl:line:30 và jsonl:line:398.

**Ground truth pointers:** `/evidence/1`, `/facts/1`, `/relationships/0`, `/scenario`

**Log gốc:** `jsonl:line:30`, `jsonl:line:398`

## 3. rd-en-initial-spawn-evidence

**Câu hỏi:** What evidence supports the cmd.exe to mshta.exe process creation relationship?

**Nhãn:** `relevant_direct` / `proceed`; context target `answer_support`.

**Đáp án:** evidence-b07a5ff4763e629715e6 giữ Sysmon Event ID 1 ở jsonl:line:275 và Security Event ID 4688 ở jsonl:line:4. ParentImage/ParentProcessName là cmd.exe, Image/NewProcessName là mshta.exe; PID cha 5888 tương ứng 0x1700, PID con 10980 tương ứng 0x2ae4. Hai records hỗ trợ một quan hệ cmd.exe → mshta.exe.

**Ground truth pointers:** `/evidence/0`, `/facts/0`, `/relationships/1`

**Log gốc:** `jsonl:line:275`, `jsonl:line:4`

## 4. rd-en-final-spawn-evidence

**Câu hỏi:** What evidence supports the mshta.exe to powershell.exe process creation relationship?

**Nhãn:** `relevant_direct` / `proceed`; context target `answer_support`.

**Đáp án:** evidence-b31714b888d1489a380c giữ Security Event ID 4688 ở jsonl:line:30 và Sysmon Event ID 1 ở jsonl:line:398. ParentImage/ParentProcessName là mshta.exe, Image/NewProcessName là powershell.exe; PID cha 10980 tương ứng 0x2ae4, PID con 9572 tương ứng 0x2564. Sysmon ParentProcessGuid khớp ProcessGuid của mshta.exe trong nhóm đầu.

**Ground truth pointers:** `/evidence/1`, `/facts/1`, `/relationships/0`

**Log gốc:** `jsonl:line:30`, `jsonl:line:398`

## 5. rd-vi-proxy-technique-assessment

**Câu hỏi:** Đánh giá hiện tại đối với ATT&CK T1218.005 có mức hỗ trợ bằng chứng và trạng thái review nào?

**Nhãn:** `relevant_direct` / `proceed`; context target `answer_support`.

**Đáp án:** T1218.005 (Mshta) có evidence_support=supported_by_observed_behavior, status=candidate và review_status=needs_review tại /mitre_assessments/2. Hai evidence groups hỗ trợ mshta.exe với vbscript:Execute và việc sinh PowerShell; mapping này chưa được con người duyệt hay đánh dấu confirmed.

**Ground truth pointers:** `/mitre_assessments/2`

**Log gốc:** `jsonl:line:275`, `jsonl:line:30`, `jsonl:line:398`, `jsonl:line:4`

## 6. rd-vi-scripting-technique-status

**Câu hỏi:** T1059.007 có được hỗ trợ bởi command line đã quan sát không, và trạng thái đánh giá là gì?

**Nhãn:** `relevant_direct` / `proceed`; context target `answer_support`.

**Đáp án:** T1059.007 là JavaScript, nhưng command line quan sát được dùng vbscript:Execute. /mitre_assessments/0 ghi not_supported_by_observed_command, status=candidate và review_status=needs_review; nhãn được giữ từ Sigma tag để truy vết nguồn, không chứng minh JavaScript đã chạy.

**Ground truth pointers:** `/mitre_assessments/0`

**Log gốc:** `jsonl:line:275`, `jsonl:line:4`

## 7. rd-vi-reviewed-scope-limitations

**Câu hỏi:** Ground Truth ghi nhận những giới hạn nào đối với phạm vi bằng chứng đã review?

**Nhãn:** `relevant_direct` / `proceed`; context target `answer_support`.

**Đáp án:** Ground truth chỉ chứa hai behavior/evidence groups, không phải toàn bộ process inventory. Sysmon có timestamp_conflict: canonical dùng TimeCreated, còn UtcTime lệch khoảng bốn giờ và timezone chưa được xác nhận. Process creation không chứng minh cmdlet hoàn tất hay trạng thái dịch vụ. Log gốc có conhost creation, log clearing và temporary-file deletion ngoài core, nên không được kết luận các hành vi đó vắng mặt trên toàn dataset hoặc tự coi là destructive payload. Chưa có negative detector toàn diện; MITRE assessments còn candidate và human approval còn pending.

**Ground truth pointers:** `/scenario`, `/summary/limitations/0`, `/summary/limitations/1`, `/summary/limitations/2`, `/summary/limitations/3`, `/summary/limitations/4`, `/summary/limitations/5`, `/summary/limitations/6`

## 8. rd-vi-initial-relation-provenance

**Câu hỏi:** Nguồn log và raw record references nào hỗ trợ quan hệ cmd.exe tạo mshta.exe?

**Nhãn:** `relevant_direct` / `proceed`; context target `answer_support`.

**Đáp án:** Quan hệ cmd.exe tạo mshta.exe được truy về file cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json, tại jsonl:line:275 (Sysmon 1) và jsonl:line:4 (Security 4688). fact-cmd-spawns-mshta, relationship-9e41d0cc407e7878b2d8 và evidence-b07a5ff4763e629715e6 cùng giữ các refs này.

**Ground truth pointers:** `/evidence/0`, `/facts/0`, `/relationships/1`

**Log gốc:** `jsonl:line:275`, `jsonl:line:4`

## 9. rp-en-intermediate-utility

**Câu hỏi:** Which Windows utility sits between the initial command interpreter and the final shell?

**Nhãn:** `relevant_paraphrase` / `proceed`; context target `answer_support`.

**Đáp án:** Tiện ích nằm giữa cmd.exe và powershell.exe là mshta.exe: cmd.exe → mshta.exe → powershell.exe. Hai process_spawn relationships và evidence tương ứng ghi rõ hướng của từng liên kết.

**Ground truth pointers:** `/evidence/0`, `/evidence/1`, `/facts/0`, `/facts/1`, `/relationships/0`, `/relationships/1`, `/scenario`

**Log gốc:** `jsonl:line:275`, `jsonl:line:30`, `jsonl:line:398`, `jsonl:line:4`

## 10. rp-en-shell-creator

**Câu hỏi:** How can I trace the launch of the final shell back to its creator?

**Nhãn:** `relevant_paraphrase` / `proceed`; context target `answer_support`.

**Đáp án:** Truy từ process-9f7ceeecb4cd61358ab7 (powershell.exe) về relationship-1641029b76ea1ac3df6e và fact-mshta-spawns-powershell; source là process-9c691740bde5d3dbdc4e (mshta.exe). evidence-b31714b888d1489a380c đưa về Security 4688 line 30 và Sysmon 1 line 398 để kiểm tra cha-con.

**Ground truth pointers:** `/evidence/1`, `/facts/1`, `/relationships/0`

**Log gốc:** `jsonl:line:30`, `jsonl:line:398`

## 11. rp-en-technique-review

**Câu hỏi:** Why is the proxy execution technique still awaiting analyst approval even though its behavior has supporting records?

**Nhãn:** `relevant_paraphrase` / `proceed`; context target `answer_support`.

**Đáp án:** T1218.005 được hỗ trợ ở mức hành vi quan sát, nhưng status vẫn candidate và review_status=needs_review. Khớp Sigma hoặc quan sát mshta.exe sinh PowerShell không tự thay thế phê duyệt của người phân tích; artifact còn giới hạn phạm vi và timestamp_conflict, chưa có kết luận tấn công cuối cùng.

**Ground truth pointers:** `/mitre_assessments/2`, `/scenario`, `/summary/limitations/3`

**Log gốc:** `jsonl:line:275`, `jsonl:line:30`, `jsonl:line:398`, `jsonl:line:4`

## 12. rp-en-retained-scripting-label

**Câu hỏi:** Why does a scripting technique label remain in the record when the reviewed inline command uses a different scripting language?

**Nhãn:** `relevant_paraphrase` / `proceed`; context target `answer_support`.

**Đáp án:** T1059.007 được giữ vì xuất phát từ tag của Sigma rule, để bảo toàn provenance. Command line dùng VBScript, không phải JavaScript; assessment vì vậy ghi not_supported_by_observed_command và không coi nhãn JavaScript là hành vi đã được chứng minh.

**Ground truth pointers:** `/mitre_assessments/0`, `/scenario`

**Log gốc:** `jsonl:line:275`, `jsonl:line:4`

## 13. rp-vi-launch-order

**Câu hỏi:** Nhìn các quan hệ cha-con đã lưu, làm thế nào dựng lại thứ tự khởi chạy ba tiến trình?

**Nhãn:** `relevant_paraphrase` / `proceed`; context target `answer_support`.

**Đáp án:** Dựng thứ tự bằng hướng của facts và relationships: fact-cmd-spawns-mshta trước, rồi fact-mshta-spawns-powershell, tạo chuỗi cmd.exe → mshta.exe → powershell.exe. Không suy ra thứ tự bằng vị trí phần tử trong mảng relationships; mảng lưu quan hệ cuối ở /relationships/0 và quan hệ đầu ở /relationships/1. Mỗi bước có một cặp Security/Sysmon telemetry, không đếm đôi.

**Ground truth pointers:** `/evidence/0`, `/evidence/1`, `/facts/0`, `/facts/1`, `/relationships/0`, `/relationships/1`, `/scenario`

**Log gốc:** `jsonl:line:275`, `jsonl:line:30`, `jsonl:line:398`, `jsonl:line:4`

## 14. rp-vi-observation-provenance

**Câu hỏi:** Những bản ghi telemetry nào cùng làm căn cứ cho mỗi lần tạo tiến trình trong hai nhóm bằng chứng?

**Nhãn:** `relevant_paraphrase` / `proceed`; context target `answer_support`.

**Đáp án:** Nhóm evidence-b07a5ff4763e629715e6 gồm Security 4688 line 4 và Sysmon 1 line 275 cho cmd.exe → mshta.exe. Nhóm evidence-b31714b888d1489a380c gồm Security 4688 line 30 và Sysmon 1 line 398 cho mshta.exe → powershell.exe. Tất cả thuộc cùng source file; chúng được tương quan thành hai behavior groups để tránh đếm telemetry thành nhiều tiến trình.

**Ground truth pointers:** `/evidence/0`, `/evidence/1`

**Log gốc:** `jsonl:line:275`, `jsonl:line:30`, `jsonl:line:398`, `jsonl:line:4`

## 15. rp-vi-final-review-limits

**Câu hỏi:** Người phân tích còn phải xem lại điều gì trước khi đưa ra nhận định cuối cùng?

**Nhãn:** `relevant_paraphrase` / `proceed`; context target `answer_support`.

**Đáp án:** Người phân tích cần kiểm tra lại correlation và refs của hai behavior groups, xử lý timestamp_conflict của Sysmon, xem mức hỗ trợ của từng MITRE assessment và giữ giới hạn negative scan. Cần duyệt ground truth và phân biệt lệnh xuất hiện trên command line với kết quả thực thi; các candidate hiện có chưa phải kết luận tấn công cuối cùng.

**Ground truth pointers:** `/scenario`, `/summary/limitations/0`, `/summary/limitations/1`, `/summary/limitations/2`, `/summary/limitations/3`

## 16. rp-vi-service-action

**Câu hỏi:** Lệnh liên quan đến dịch vụ được ghi nhận trên command line khi PowerShell được khởi chạy là gì?

**Nhãn:** `relevant_paraphrase` / `proceed`; context target `answer_support`.

**Đáp án:** Command line của PowerShell ở jsonl:line:30 và jsonl:line:398 chứa -noexit -command Get-Service sysmon. Điều được quan sát trực tiếp là PowerShell được khởi chạy với lệnh này; căn cứ hiện có chưa cung cấp đầu ra cmdlet hoặc chứng minh trạng thái dịch vụ Sysmon. Không suy ra payload tải xuống, C2 hay thao tác phá hoại.

**Ground truth pointers:** `/scenario`

**Log gốc:** `jsonl:line:30`, `jsonl:line:398`

**Câu gốc được sửa:** Tác vụ về dịch vụ mà shell cuối cùng đã thực hiện được ghi nhận như thế nào?

## 17. ie-en-payload-download-url

**Câu hỏi:** Which URL did PowerShell use to download the payload in this MSHTA chain?

**Nhãn:** `insufficient_evidence` / `abstain`; context target `abstention_support`.

**Đáp án:** Không đủ bằng chứng để nêu URL tải payload. Hai evidence groups đã lưu chủ yếu là process creation; command line ghi Get-Service sysmon, không cung cấp download URL. Không được bịa URL hoặc kết luận mọi download đều vắng mặt trên toàn dataset từ ground truth giới hạn này.

**Ground truth pointers:** `/evidence/1`, `/scenario`, `/summary/limitations/0`, `/summary/limitations/2`

## 18. ie-en-c2-address

**Câu hỏi:** What IP address acted as the C2 server for the PowerShell process?

**Nhãn:** `insufficient_evidence` / `abstain`; context target `abstention_support`.

**Đáp án:** Không đủ bằng chứng để xác định IP C2 cho PowerShell trong chuỗi MSHTA. Hai nhóm evidence này không cung cấp quan hệ C2 hay endpoint tương ứng; không được gán IP từ kịch bản khác hoặc coi giới hạn hiện có là kết luận vắng mặt trên toàn dataset.

**Ground truth pointers:** `/evidence/1`, `/scenario`, `/summary/limitations/0`, `/summary/limitations/2`

## 19. ie-en-attacker-identity

**Câu hỏi:** Who was the attacker responsible for the reviewed MSHTA execution?

**Nhãn:** `insufficient_evidence` / `abstain`; context target `abstention_support`.

**Đáp án:** Không đủ bằng chứng để quy kết danh tính kẻ tấn công. Process và tài khoản chạy tiến trình trong telemetry chỉ là thực thể quan sát, không chứng minh người hoặc nhóm chịu trách nhiệm; ground truth chưa có attribution được duyệt.

**Ground truth pointers:** `/evidence/0`, `/evidence/1`, `/scenario`, `/summary/limitations/0`, `/summary/limitations/2`

## 20. ie-en-stolen-credentials

**Câu hỏi:** Which credentials did PowerShell steal during this activity?

**Nhãn:** `insufficient_evidence` / `abstain`; context target `abstention_support`.

**Đáp án:** Không đủ bằng chứng để nêu thông tin xác thực bị đánh cắp. Evidence và summary hiện có không chứng minh credential theft hay cung cấp stolen values; command line Get-Service sysmon không tự chứng minh hành vi này. Không suy rộng thành kết luận toàn dataset không có đánh cắp thông tin xác thực.

**Ground truth pointers:** `/evidence/1`, `/scenario`, `/summary/limitations/0`, `/summary/limitations/2`

## 21. ie-vi-destructive-files

**Câu hỏi:** Trong hai nhóm process-creation evidence của ground truth, có bằng chứng nào cho thấy payload PowerShell cố ý phá hoại tệp không?

**Nhãn:** `insufficient_evidence` / `abstain`; context target `abstention_support`.

**Đáp án:** Hai nhóm process-creation evidence không chứng minh payload PowerShell cố ý phá hoại tệp. Log gốc có record xóa tệp tạm, nhưng việc xóa tệp tạm không tự chứng minh ý định phá hoại và nằm ngoài hai nhóm evidence của core này. Không suy ra toàn dataset không có thao tác xóa tệp; câu hỏi liệt kê tệp đã xóa trong raw cần một phạm vi evidence khác.

**Ground truth pointers:** `/evidence/1`, `/scenario`, `/summary/limitations/0`, `/summary/limitations/2`, `/summary/limitations/6`

**Câu gốc được sửa:** PowerShell trong chuỗi MSHTA này đã xóa hoặc phá hoại những tệp nào?

## 22. ie-vi-decoded-content

**Câu hỏi:** Nội dung payload đã được MSHTA hoặc PowerShell giải mã là gì?

**Nhãn:** `insufficient_evidence` / `abstain`; context target `abstention_support`.

**Đáp án:** Không đủ bằng chứng để đưa ra nội dung payload đã giải mã. Artifact có command line VBScript và Get-Service sysmon, nhưng không có căn cứ về thao tác giải mã hoặc kết quả giải mã; T1140 còn not_assessed. Không coi lệnh quan sát được là decoded payload.

**Ground truth pointers:** `/evidence/0`, `/evidence/1`, `/mitre_assessments/1`, `/summary/limitations/0`, `/summary/limitations/2`

## 23. ie-vi-decoding-proof

**Câu hỏi:** Bằng chứng nào chứng minh T1140 đã xảy ra trong chuỗi MSHTA?

**Nhãn:** `insufficient_evidence` / `abstain`; context target `abstention_support`.

**Đáp án:** Ground truth hiện không có bằng chứng chứng minh T1140 đã xảy ra. /mitre_assessments/1 ghi status=candidate, evidence_support=not_assessed và supporting_evidence_ids rỗng; nhãn được giải quyết từ Sigma tag, không phải bằng chứng hành vi giải mã.

**Ground truth pointers:** `/mitre_assessments/1`

## 24. ie-vi-certain-attack-determination

**Câu hỏi:** Có thể khẳng định chắc chắn toàn bộ chuỗi cmd.exe, mshta.exe và powershell.exe là một cuộc tấn công không?

**Nhãn:** `insufficient_evidence` / `abstain`; context target `abstention_support`.

**Đáp án:** Chưa thể khẳng định chắc chắn toàn bộ chuỗi là cuộc tấn công từ ground truth hiện có. Quan hệ cha-con và command line đáng chú ý được quan sát, nhưng scenario còn draft_reviewable, MITRE assessments còn candidate và human review chưa hoàn tất. Có thể mô tả các hành vi được hỗ trợ, không nâng chúng thành nhận định chắc chắn được yêu cầu.

**Ground truth pointers:** `/mitre_assessments/2`, `/scenario`, `/summary/limitations/0`, `/summary/limitations/2`, `/summary/limitations/3`

## 25. ur-en-weather

**Câu hỏi:** What will the weather be in Hanoi tomorrow?

**Nhãn:** `unrelated` / `abstain`; context target `no_relevant_chunk`.

**Đáp án:** Câu hỏi dự báo thời tiết nằm ngoài phạm vi ground truth MSHTA–PowerShell; corpus này không cung cấp căn cứ trả lời.

**Ground truth pointers:** Không có chunk liên quan trong phạm vi này.

## 26. ur-en-product-price

**Câu hỏi:** What is the current price of a gaming laptop?

**Nhãn:** `unrelated` / `abstain`; context target `no_relevant_chunk`.

**Đáp án:** Câu hỏi giá laptop nằm ngoài phạm vi ground truth MSHTA–PowerShell; corpus này không cung cấp căn cứ về giá sản phẩm.

**Ground truth pointers:** Không có chunk liên quan trong phạm vi này.

## 27. ur-en-linux-cron

**Câu hỏi:** How do I schedule a Linux cron job to run every ten minutes?

**Nhãn:** `unrelated` / `abstain`; context target `no_relevant_chunk`.

**Đáp án:** Hướng dẫn Linux cron nằm ngoài phạm vi bằng chứng thực thi tiến trình Windows của ground truth MSHTA–PowerShell.

**Ground truth pointers:** Không có chunk liên quan trong phạm vi này.

## 28. ur-en-sql-injection

**Câu hỏi:** How can I prevent SQL injection in a web application's database queries?

**Nhãn:** `unrelated` / `abstain`; context target `no_relevant_chunk`.

**Đáp án:** Hướng dẫn phòng SQL injection nằm ngoài phạm vi ground truth MSHTA–PowerShell; corpus này không phải nguồn trả lời câu hỏi cấu hình bảo mật cơ sở dữ liệu web.

**Ground truth pointers:** Không có chunk liên quan trong phạm vi này.

## 29. ur-vi-ransomware-encryption

**Câu hỏi:** Mã hóa ransomware xử lý các khóa mật mã như thế nào?

**Nhãn:** `unrelated` / `abstain`; context target `no_relevant_chunk`.

**Đáp án:** Cơ chế quản lý khóa của ransomware nằm ngoài phạm vi MSHTA–PowerShell đang được đánh giá; corpus này không có tri thức để giải thích yêu cầu đó.

**Ground truth pointers:** Không có chunk liên quan trong phạm vi này.

## 30. ur-vi-kubernetes-configuration

**Câu hỏi:** Cần cấu hình Kubernetes thế nào để tự động mở rộng một Deployment?

**Nhãn:** `unrelated` / `abstain`; context target `no_relevant_chunk`.

**Đáp án:** Cấu hình tự động mở rộng Kubernetes Deployment nằm ngoài phạm vi ground truth MSHTA–PowerShell; corpus không cung cấp căn cứ hướng dẫn.

**Ground truth pointers:** Không có chunk liên quan trong phạm vi này.

## 31. ur-vi-literature-learning

**Câu hỏi:** Làm thế nào phân biệt hình ảnh ẩn dụ và hoán dụ trong một bài thơ?

**Nhãn:** `unrelated` / `abstain`; context target `no_relevant_chunk`.

**Đáp án:** Phân biệt ẩn dụ và hoán dụ trong thơ nằm ngoài phạm vi ground truth MSHTA–PowerShell; không có chunk liên quan để trả lời.

**Ground truth pointers:** Không có chunk liên quan trong phạm vi này.

## 32. ur-vi-opaque-token

**Câu hỏi:** Chuỗi velora_quartz_token_483920761 có ý nghĩa gì?

**Nhãn:** `unrelated` / `abstain`; context target `no_relevant_chunk`.

**Đáp án:** Chuỗi velora_quartz_token_483920761 không có ngữ cảnh trong corpus MSHTA–PowerShell; không đủ cơ sở gán ý nghĩa cho chuỗi ngoài phạm vi này.

**Ground truth pointers:** Không có chunk liên quan trong phạm vi này.
