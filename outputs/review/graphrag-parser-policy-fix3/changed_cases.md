# FIX3 — Phân tích các case thay đổi quyết định

Đối chiếu E1–E4 với E0 trên cùng 32 development queries đã exposed. Phân tích này chạy sau frozen experiment, giữ approved labels và AI rubric ngoài runtime. Không gọi đây là held-out hoặc independent validation.

Mọi quotation dưới đây được kiểm tra đúng field/item ID/source pointer trong final context thực tế. Support và guard là chẩn đoán runtime, không được dùng làm ground truth tự chấm chính nó. Các trace v1 không có parser spans được ghi rõ; không tạo source span giả.

Changed counts: `{"E1":{"baseline_true_positive_lost":0,"false_proceed":0,"newly_permitted":3,"rescued_dataset_positive":3,"rescued_dataset_positive_vi":0},"E2":{"baseline_true_positive_lost":0,"false_proceed":0,"newly_permitted":4,"rescued_dataset_positive":4,"rescued_dataset_positive_vi":4},"E3":{"baseline_true_positive_lost":0,"false_proceed":0,"newly_permitted":6,"rescued_dataset_positive":6,"rescued_dataset_positive_vi":3},"E4":{"baseline_true_positive_lost":0,"false_proceed":0,"newly_permitted":7,"rescued_dataset_positive":7,"rescued_dataset_positive_vi":4}}`.

## `rd-en-process-chain` (en)

Which process chain led to powershell.exe in the reviewed evidence?

Approved label: **proceed**; category `relevant_direct`. Đây là đối chiếu ngoài runtime; không thay đổi nhãn.

| Arm | Decision | Parser | Support | Rubric context sufficient | Reasons |
| --- | --- | --- | --- | --- | --- |
| E0 | abstain | ambiguous | unknown | True | query_requirements_ambiguous, required_evidence_unknown |
| E1 | proceed | supported | supported | True | — |
| E2 | abstain | ambiguous | unknown | True | query_requirements_ambiguous, required_evidence_unknown, independent_evidence_guard_unknown, mandatory_support_trace_empty, required_evidence_identity_or_source_anchor_missing |
| E3 | proceed | supported | supported | True | — |
| E4 | proceed | supported | supported | True | — |

Nhóm thay đổi: abstain_to_proceed.

### E1: abstain->proceed

Legacy decision: `proceed`; scope `unspecified`. Final context: 38 items, 0 supplementary. Approved-label outcome: **TP**.

Rubric AI ngoài runtime: {"context_sufficiency_basis":"all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation","context_sufficient":true,"expected_evidence_ids":["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"],"missing_answer_units":[],"missing_evidence_diagnostics":[],"returned_evidence_ids":["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"],"satisfied_answer_units":["initial_spawn","final_spawn"]}. Rubric này còn giới hạn exact text/semantic unknown và không phải independent validation.

Requirement `r1` — `process_relationship`: `{"chain":true,"child":"powershell.exe","parent":null}`; support `supported`.

Parser source spans (exact original query offsets/text):

- {"clause_id":"c1","end":66,"role":"request","start":0,"text":"Which process chain led to powershell.exe in the reviewed evidence"}
- {"clause_id":"c1","end":41,"role":"target","start":27,"text":"powershell.exe"}
- {"clause_id":"c1","end":41,"role":"object","start":27,"text":"powershell.exe"}
- {"clause_id":"c1","end":19,"role":"action","start":14,"text":"chain"}

Các quan hệ process creation có hướng được nối bằng process instance identity thực tế. Guard kiểm tra boundary, depth/cycle và mâu thuẫn identity. Query chỉ nêu target; truy ngược tới source boundary, không đoán tên ancestor trong parser.

Completeness/contradiction guards: {"completeness":{"reason_codes":["authenticated_source_boundary_reached"],"status":"complete"},"contradiction":{"reason_codes":[],"status":"none_detected"},"status":"supported"}.

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/1/original_fields/ParentImage`, context `/final_items/10/payload/attributes/attributes/source_observations/1/original_fields/ParentImage`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"powershell.exe","object_identity":"{39e4a257-2d78-5f91-6c13-000000000700}","subject":"mshta.exe","subject_identity":"{39e4a257-2d77-5f91-6b13-000000000700}"}.

> C:\Windows\System32\mshta.exe

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/1/original_fields/Image`, context `/final_items/10/payload/attributes/attributes/source_observations/1/original_fields/Image`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"powershell.exe","object_identity":"{39e4a257-2d78-5f91-6c13-000000000700}","subject":"mshta.exe","subject_identity":"{39e4a257-2d77-5f91-6b13-000000000700}"}.

> C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/1/original_fields/ParentProcessGuid`, context `/final_items/10/payload/attributes/attributes/source_observations/1/original_fields/ParentProcessGuid`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"powershell.exe","object_identity":"{39e4a257-2d78-5f91-6c13-000000000700}","subject":"mshta.exe","subject_identity":"{39e4a257-2d77-5f91-6b13-000000000700}"}.

> {39e4a257-2d77-5f91-6b13-000000000700}

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/1/original_fields/ProcessGuid`, context `/final_items/10/payload/attributes/attributes/source_observations/1/original_fields/ProcessGuid`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"powershell.exe","object_identity":"{39e4a257-2d78-5f91-6c13-000000000700}","subject":"mshta.exe","subject_identity":"{39e4a257-2d77-5f91-6b13-000000000700}"}.

> {39e4a257-2d78-5f91-6c13-000000000700}

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/1/source_file`, context `/final_items/10/payload/attributes/attributes/source_observations/1/source_file`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/1/raw_record_ref`, context `/final_items/10/payload/attributes/attributes/source_observations/1/raw_record_ref`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> jsonl:line:398

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/ParentImage`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/ParentImage`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"mshta.exe","object_identity":"{39e4a257-2d77-5f91-6b13-000000000700}","subject":"cmd.exe","subject_identity":"{39e4a257-2d59-5f91-6813-000000000700}"}.

> C:\Windows\System32\cmd.exe

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/Image`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/Image`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"mshta.exe","object_identity":"{39e4a257-2d77-5f91-6b13-000000000700}","subject":"cmd.exe","subject_identity":"{39e4a257-2d59-5f91-6813-000000000700}"}.

> C:\Windows\System32\mshta.exe

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/ParentProcessGuid`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/ParentProcessGuid`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"mshta.exe","object_identity":"{39e4a257-2d77-5f91-6b13-000000000700}","subject":"cmd.exe","subject_identity":"{39e4a257-2d59-5f91-6813-000000000700}"}.

> {39e4a257-2d59-5f91-6813-000000000700}

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/ProcessGuid`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/ProcessGuid`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"mshta.exe","object_identity":"{39e4a257-2d77-5f91-6b13-000000000700}","subject":"cmd.exe","subject_identity":"{39e4a257-2d59-5f91-6813-000000000700}"}.

> {39e4a257-2d77-5f91-6b13-000000000700}

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/source_file`, context `/final_items/6/payload/attributes/attributes/source_observations/0/source_file`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/raw_record_ref`, context `/final_items/6/payload/attributes/attributes/source_observations/0/raw_record_ref`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> jsonl:line:275

Giới hạn:

- Trace được đối chiếu với final_items thực tế; runtime support không thay thế approved label hoặc rubric ngoài.
- Thiếu evidence chỉ mô tả context đã kiểm tra; không chứng minh hành vi vắng mặt trên toàn hệ thống.
- Parent-child creation không chứng minh completion, payload intent hoặc hành vi network.

Requirement `r2` — `evidence_provenance`: `{"process":"powershell.exe"}`; support `supported`.

Parser source spans (exact original query offsets/text):

- {"clause_id":"c1","end":66,"role":"request","start":0,"text":"Which process chain led to powershell.exe in the reviewed evidence"}
- {"clause_id":"c1","end":41,"role":"subject","start":27,"text":"powershell.exe"}
- {"clause_id":"c1","end":66,"role":"action","start":58,"text":"evidence"}

Các trường/source observation thực sự được trả về gắn event/provider/timestamp với source file và raw record reference.

Completeness/contradiction guards: {"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"status":"supported"}.

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/NewProcessName`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/NewProcessName`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/SourceName`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/SourceName`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> Microsoft-Windows-Security-Auditing

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/Channel`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/Channel`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> Security

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/EventID`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/EventID`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> 4688

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/TimeCreated`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/TimeCreated`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> 2020-10-22T02:58:00.462Z

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/source_file`, context `/final_items/10/payload/attributes/attributes/source_observations/0/source_file`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/raw_record_ref`, context `/final_items/10/payload/attributes/attributes/source_observations/0/raw_record_ref`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> jsonl:line:30

Giới hạn:

- Trace được đối chiếu với final_items thực tế; runtime support không thay thế approved label hoặc rubric ngoài.
- Thiếu evidence chỉ mô tả context đã kiểm tra; không chứng minh hành vi vắng mặt trên toàn hệ thống.
- Không tự sửa xung đột TimeCreated/UtcTime hoặc suy timezone chưa được nguồn xác minh.

### E3: abstain->proceed

Legacy decision: `proceed`; scope `unspecified`. Final context: 38 items, 0 supplementary. Approved-label outcome: **TP**.

Rubric AI ngoài runtime: {"context_sufficiency_basis":"all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation","context_sufficient":true,"expected_evidence_ids":["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"],"missing_answer_units":[],"missing_evidence_diagnostics":[],"returned_evidence_ids":["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"],"satisfied_answer_units":["initial_spawn","final_spawn"]}. Rubric này còn giới hạn exact text/semantic unknown và không phải independent validation.

Requirement `r1` — `process_relationship`: `{"chain":true,"child":"powershell.exe","parent":null}`; support `supported`.

Parser source spans (exact original query offsets/text):

- {"clause_id":"c1","end":66,"role":"request","start":0,"text":"Which process chain led to powershell.exe in the reviewed evidence"}
- {"clause_id":"c1","end":41,"role":"target","start":27,"text":"powershell.exe"}
- {"clause_id":"c1","end":41,"role":"object","start":27,"text":"powershell.exe"}
- {"clause_id":"c1","end":19,"role":"action","start":14,"text":"chain"}

Các quan hệ process creation có hướng được nối bằng process instance identity thực tế. Guard kiểm tra boundary, depth/cycle và mâu thuẫn identity. Query chỉ nêu target; truy ngược tới source boundary, không đoán tên ancestor trong parser.

Completeness/contradiction guards: {"completeness":{"reason_codes":["authenticated_source_boundary_reached"],"status":"complete"},"contradiction":{"reason_codes":[],"status":"none_detected"},"status":"supported"}.

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/1/original_fields/ParentImage`, context `/final_items/10/payload/attributes/attributes/source_observations/1/original_fields/ParentImage`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"powershell.exe","object_identity":"{39e4a257-2d78-5f91-6c13-000000000700}","subject":"mshta.exe","subject_identity":"{39e4a257-2d77-5f91-6b13-000000000700}"}.

> C:\Windows\System32\mshta.exe

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/1/original_fields/Image`, context `/final_items/10/payload/attributes/attributes/source_observations/1/original_fields/Image`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"powershell.exe","object_identity":"{39e4a257-2d78-5f91-6c13-000000000700}","subject":"mshta.exe","subject_identity":"{39e4a257-2d77-5f91-6b13-000000000700}"}.

> C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/1/original_fields/ParentProcessGuid`, context `/final_items/10/payload/attributes/attributes/source_observations/1/original_fields/ParentProcessGuid`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"powershell.exe","object_identity":"{39e4a257-2d78-5f91-6c13-000000000700}","subject":"mshta.exe","subject_identity":"{39e4a257-2d77-5f91-6b13-000000000700}"}.

> {39e4a257-2d77-5f91-6b13-000000000700}

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/1/original_fields/ProcessGuid`, context `/final_items/10/payload/attributes/attributes/source_observations/1/original_fields/ProcessGuid`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"powershell.exe","object_identity":"{39e4a257-2d78-5f91-6c13-000000000700}","subject":"mshta.exe","subject_identity":"{39e4a257-2d77-5f91-6b13-000000000700}"}.

> {39e4a257-2d78-5f91-6c13-000000000700}

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/1/source_file`, context `/final_items/10/payload/attributes/attributes/source_observations/1/source_file`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/1/raw_record_ref`, context `/final_items/10/payload/attributes/attributes/source_observations/1/raw_record_ref`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> jsonl:line:398

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/ParentImage`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/ParentImage`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"mshta.exe","object_identity":"{39e4a257-2d77-5f91-6b13-000000000700}","subject":"cmd.exe","subject_identity":"{39e4a257-2d59-5f91-6813-000000000700}"}.

> C:\Windows\System32\cmd.exe

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/Image`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/Image`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"mshta.exe","object_identity":"{39e4a257-2d77-5f91-6b13-000000000700}","subject":"cmd.exe","subject_identity":"{39e4a257-2d59-5f91-6813-000000000700}"}.

> C:\Windows\System32\mshta.exe

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/ParentProcessGuid`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/ParentProcessGuid`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"mshta.exe","object_identity":"{39e4a257-2d77-5f91-6b13-000000000700}","subject":"cmd.exe","subject_identity":"{39e4a257-2d59-5f91-6813-000000000700}"}.

> {39e4a257-2d59-5f91-6813-000000000700}

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/ProcessGuid`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/ProcessGuid`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"mshta.exe","object_identity":"{39e4a257-2d77-5f91-6b13-000000000700}","subject":"cmd.exe","subject_identity":"{39e4a257-2d59-5f91-6813-000000000700}"}.

> {39e4a257-2d77-5f91-6b13-000000000700}

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/source_file`, context `/final_items/6/payload/attributes/attributes/source_observations/0/source_file`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/raw_record_ref`, context `/final_items/6/payload/attributes/attributes/source_observations/0/raw_record_ref`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> jsonl:line:275

Giới hạn:

- Trace được đối chiếu với final_items thực tế; runtime support không thay thế approved label hoặc rubric ngoài.
- Thiếu evidence chỉ mô tả context đã kiểm tra; không chứng minh hành vi vắng mặt trên toàn hệ thống.
- Parent-child creation không chứng minh completion, payload intent hoặc hành vi network.

Requirement `r2` — `evidence_provenance`: `{"process":"powershell.exe"}`; support `supported`.

Parser source spans (exact original query offsets/text):

- {"clause_id":"c1","end":66,"role":"request","start":0,"text":"Which process chain led to powershell.exe in the reviewed evidence"}
- {"clause_id":"c1","end":41,"role":"subject","start":27,"text":"powershell.exe"}
- {"clause_id":"c1","end":66,"role":"action","start":58,"text":"evidence"}

Các trường/source observation thực sự được trả về gắn event/provider/timestamp với source file và raw record reference.

Completeness/contradiction guards: {"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"status":"supported"}.

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/NewProcessName`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/NewProcessName`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/SourceName`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/SourceName`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> Microsoft-Windows-Security-Auditing

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/Channel`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/Channel`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> Security

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/EventID`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/EventID`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> 4688

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/TimeCreated`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/TimeCreated`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> 2020-10-22T02:58:00.462Z

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/source_file`, context `/final_items/10/payload/attributes/attributes/source_observations/0/source_file`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/raw_record_ref`, context `/final_items/10/payload/attributes/attributes/source_observations/0/raw_record_ref`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> jsonl:line:30

Giới hạn:

- Trace được đối chiếu với final_items thực tế; runtime support không thay thế approved label hoặc rubric ngoài.
- Thiếu evidence chỉ mô tả context đã kiểm tra; không chứng minh hành vi vắng mặt trên toàn hệ thống.
- Không tự sửa xung đột TimeCreated/UtcTime hoặc suy timezone chưa được nguồn xác minh.

### E4: abstain->proceed

Legacy decision: `proceed`; scope `unspecified`. Final context: 40 items, 2 supplementary. Approved-label outcome: **TP**.

Rubric AI ngoài runtime: {"context_sufficiency_basis":"all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation","context_sufficient":true,"expected_evidence_ids":["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"],"missing_answer_units":[],"missing_evidence_diagnostics":[],"returned_evidence_ids":["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"],"satisfied_answer_units":["initial_spawn","final_spawn"]}. Rubric này còn giới hạn exact text/semantic unknown và không phải independent validation.

Requirement `r1` — `process_relationship`: `{"chain":true,"child":"powershell.exe","parent":null}`; support `supported`.

Parser source spans (exact original query offsets/text):

- {"clause_id":"c1","end":66,"role":"request","start":0,"text":"Which process chain led to powershell.exe in the reviewed evidence"}
- {"clause_id":"c1","end":41,"role":"target","start":27,"text":"powershell.exe"}
- {"clause_id":"c1","end":41,"role":"object","start":27,"text":"powershell.exe"}
- {"clause_id":"c1","end":19,"role":"action","start":14,"text":"chain"}

Các quan hệ process creation có hướng được nối bằng process instance identity thực tế. Guard kiểm tra boundary, depth/cycle và mâu thuẫn identity. Query chỉ nêu target; truy ngược tới source boundary, không đoán tên ancestor trong parser.

Completeness/contradiction guards: {"completeness":{"reason_codes":["authenticated_source_boundary_reached"],"status":"complete"},"contradiction":{"reason_codes":[],"status":"none_detected"},"status":"supported"}.

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/1/original_fields/ParentImage`, context `/final_items/10/payload/attributes/attributes/source_observations/1/original_fields/ParentImage`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"powershell.exe","object_identity":"{39e4a257-2d78-5f91-6c13-000000000700}","subject":"mshta.exe","subject_identity":"{39e4a257-2d77-5f91-6b13-000000000700}"}.

> C:\Windows\System32\mshta.exe

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/1/original_fields/Image`, context `/final_items/10/payload/attributes/attributes/source_observations/1/original_fields/Image`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"powershell.exe","object_identity":"{39e4a257-2d78-5f91-6c13-000000000700}","subject":"mshta.exe","subject_identity":"{39e4a257-2d77-5f91-6b13-000000000700}"}.

> C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/1/original_fields/ParentProcessGuid`, context `/final_items/10/payload/attributes/attributes/source_observations/1/original_fields/ParentProcessGuid`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"powershell.exe","object_identity":"{39e4a257-2d78-5f91-6c13-000000000700}","subject":"mshta.exe","subject_identity":"{39e4a257-2d77-5f91-6b13-000000000700}"}.

> {39e4a257-2d77-5f91-6b13-000000000700}

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/1/original_fields/ProcessGuid`, context `/final_items/10/payload/attributes/attributes/source_observations/1/original_fields/ProcessGuid`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"powershell.exe","object_identity":"{39e4a257-2d78-5f91-6c13-000000000700}","subject":"mshta.exe","subject_identity":"{39e4a257-2d77-5f91-6b13-000000000700}"}.

> {39e4a257-2d78-5f91-6c13-000000000700}

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/1/source_file`, context `/final_items/10/payload/attributes/attributes/source_observations/1/source_file`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/1/raw_record_ref`, context `/final_items/10/payload/attributes/attributes/source_observations/1/raw_record_ref`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> jsonl:line:398

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/ParentImage`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/ParentImage`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"mshta.exe","object_identity":"{39e4a257-2d77-5f91-6b13-000000000700}","subject":"cmd.exe","subject_identity":"{39e4a257-2d59-5f91-6813-000000000700}"}.

> C:\Windows\System32\cmd.exe

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/Image`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/Image`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"mshta.exe","object_identity":"{39e4a257-2d77-5f91-6b13-000000000700}","subject":"cmd.exe","subject_identity":"{39e4a257-2d59-5f91-6813-000000000700}"}.

> C:\Windows\System32\mshta.exe

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/ParentProcessGuid`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/ParentProcessGuid`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"mshta.exe","object_identity":"{39e4a257-2d77-5f91-6b13-000000000700}","subject":"cmd.exe","subject_identity":"{39e4a257-2d59-5f91-6813-000000000700}"}.

> {39e4a257-2d59-5f91-6813-000000000700}

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/ProcessGuid`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/ProcessGuid`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"mshta.exe","object_identity":"{39e4a257-2d77-5f91-6b13-000000000700}","subject":"cmd.exe","subject_identity":"{39e4a257-2d59-5f91-6813-000000000700}"}.

> {39e4a257-2d77-5f91-6b13-000000000700}

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/source_file`, context `/final_items/6/payload/attributes/attributes/source_observations/0/source_file`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/raw_record_ref`, context `/final_items/6/payload/attributes/attributes/source_observations/0/raw_record_ref`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> jsonl:line:275

Giới hạn:

- Trace được đối chiếu với final_items thực tế; runtime support không thay thế approved label hoặc rubric ngoài.
- Thiếu evidence chỉ mô tả context đã kiểm tra; không chứng minh hành vi vắng mặt trên toàn hệ thống.
- Parent-child creation không chứng minh completion, payload intent hoặc hành vi network.

Requirement `r2` — `evidence_provenance`: `{"process":"powershell.exe"}`; support `supported`.

Parser source spans (exact original query offsets/text):

- {"clause_id":"c1","end":66,"role":"request","start":0,"text":"Which process chain led to powershell.exe in the reviewed evidence"}
- {"clause_id":"c1","end":41,"role":"subject","start":27,"text":"powershell.exe"}
- {"clause_id":"c1","end":66,"role":"action","start":58,"text":"evidence"}

Các trường/source observation thực sự được trả về gắn event/provider/timestamp với source file và raw record reference.

Completeness/contradiction guards: {"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"status":"supported"}.

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/NewProcessName`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/NewProcessName`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/SourceName`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/SourceName`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> Microsoft-Windows-Security-Auditing

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/Channel`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/Channel`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> Security

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/EventID`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/EventID`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> 4688

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/TimeCreated`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/TimeCreated`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> 2020-10-22T02:58:00.462Z

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/source_file`, context `/final_items/10/payload/attributes/attributes/source_observations/0/source_file`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/raw_record_ref`, context `/final_items/10/payload/attributes/attributes/source_observations/0/raw_record_ref`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> jsonl:line:30

Giới hạn:

- Trace được đối chiếu với final_items thực tế; runtime support không thay thế approved label hoặc rubric ngoài.
- Thiếu evidence chỉ mô tả context đã kiểm tra; không chứng minh hành vi vắng mặt trên toàn hệ thống.
- Không tự sửa xung đột TimeCreated/UtcTime hoặc suy timezone chưa được nguồn xác minh.


## `rd-en-initial-spawn-evidence` (en)

What evidence supports the cmd.exe to mshta.exe process creation relationship?

Approved label: **proceed**; category `relevant_direct`. Đây là đối chiếu ngoài runtime; không thay đổi nhãn.

| Arm | Decision | Parser | Support | Rubric context sufficient | Reasons |
| --- | --- | --- | --- | --- | --- |
| E0 | abstain | ambiguous | unknown | True | query_requirements_ambiguous, required_evidence_unknown |
| E1 | proceed | supported | supported | True | — |
| E2 | abstain | ambiguous | unknown | True | query_requirements_ambiguous, required_evidence_unknown, independent_evidence_guard_unknown, mandatory_support_trace_empty, required_evidence_identity_or_source_anchor_missing |
| E3 | proceed | supported | supported | True | — |
| E4 | proceed | supported | supported | True | — |

Nhóm thay đổi: abstain_to_proceed.

### E1: abstain->proceed

Legacy decision: `proceed`; scope `unspecified`. Final context: 39 items, 0 supplementary. Approved-label outcome: **TP**.

Rubric AI ngoài runtime: {"context_sufficiency_basis":"all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation","context_sufficient":true,"expected_evidence_ids":["evidence-b07a5ff4763e629715e6"],"missing_answer_units":[],"missing_evidence_diagnostics":[],"returned_evidence_ids":["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"],"satisfied_answer_units":["initial_spawn","initial_observations"]}. Rubric này còn giới hạn exact text/semantic unknown và không phải independent validation.

Requirement `r1` — `process_relationship`: `{"chain":false,"child":"mshta.exe","parent":"cmd.exe"}`; support `supported`.

Parser source spans (exact original query offsets/text):

- {"clause_id":"c1","end":77,"role":"request","start":0,"text":"What evidence supports the cmd.exe to mshta.exe process creation relationship"}
- {"clause_id":"c1","end":34,"role":"parent","start":27,"text":"cmd.exe"}
- {"clause_id":"c1","end":47,"role":"child","start":38,"text":"mshta.exe"}

Trace ràng buộc parent và child đúng chiều, có instance identities và source references của process creation.

Completeness/contradiction guards: {"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"status":"supported"}.

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/ParentImage`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/ParentImage`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"mshta.exe","object_identity":"{39e4a257-2d77-5f91-6b13-000000000700}","subject":"cmd.exe","subject_identity":"{39e4a257-2d59-5f91-6813-000000000700}"}.

> C:\Windows\System32\cmd.exe

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/Image`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/Image`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"mshta.exe","object_identity":"{39e4a257-2d77-5f91-6b13-000000000700}","subject":"cmd.exe","subject_identity":"{39e4a257-2d59-5f91-6813-000000000700}"}.

> C:\Windows\System32\mshta.exe

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/ParentProcessGuid`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/ParentProcessGuid`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"mshta.exe","object_identity":"{39e4a257-2d77-5f91-6b13-000000000700}","subject":"cmd.exe","subject_identity":"{39e4a257-2d59-5f91-6813-000000000700}"}.

> {39e4a257-2d59-5f91-6813-000000000700}

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/ProcessGuid`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/ProcessGuid`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"mshta.exe","object_identity":"{39e4a257-2d77-5f91-6b13-000000000700}","subject":"cmd.exe","subject_identity":"{39e4a257-2d59-5f91-6813-000000000700}"}.

> {39e4a257-2d77-5f91-6b13-000000000700}

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/source_file`, context `/final_items/6/payload/attributes/attributes/source_observations/0/source_file`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/raw_record_ref`, context `/final_items/6/payload/attributes/attributes/source_observations/0/raw_record_ref`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> jsonl:line:275

Giới hạn:

- Trace được đối chiếu với final_items thực tế; runtime support không thay thế approved label hoặc rubric ngoài.
- Thiếu evidence chỉ mô tả context đã kiểm tra; không chứng minh hành vi vắng mặt trên toàn hệ thống.
- Parent-child creation không chứng minh completion, payload intent hoặc hành vi network.

Requirement `r2` — `evidence_provenance`: `{"process":"mshta.exe"}`; support `supported`.

Parser source spans (exact original query offsets/text):

- {"clause_id":"c1","end":77,"role":"request","start":0,"text":"What evidence supports the cmd.exe to mshta.exe process creation relationship"}
- {"clause_id":"c1","end":47,"role":"subject","start":38,"text":"mshta.exe"}
- {"clause_id":"c1","end":13,"role":"action","start":5,"text":"evidence"}

Các trường/source observation thực sự được trả về gắn event/provider/timestamp với source file và raw record reference.

Completeness/contradiction guards: {"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"status":"supported"}.

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/Image`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/Image`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> C:\Windows\System32\mshta.exe

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/SourceName`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/SourceName`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> Microsoft-Windows-Sysmon

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/Channel`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/Channel`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> Microsoft-Windows-Sysmon/Operational

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/EventID`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/EventID`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> 1

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/TimeCreated`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/TimeCreated`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> 2020-10-22T02:57:59.857Z

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/source_file`, context `/final_items/6/payload/attributes/attributes/source_observations/0/source_file`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/raw_record_ref`, context `/final_items/6/payload/attributes/attributes/source_observations/0/raw_record_ref`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> jsonl:line:275

Giới hạn:

- Trace được đối chiếu với final_items thực tế; runtime support không thay thế approved label hoặc rubric ngoài.
- Thiếu evidence chỉ mô tả context đã kiểm tra; không chứng minh hành vi vắng mặt trên toàn hệ thống.
- Không tự sửa xung đột TimeCreated/UtcTime hoặc suy timezone chưa được nguồn xác minh.

### E3: abstain->proceed

Legacy decision: `proceed`; scope `unspecified`. Final context: 39 items, 0 supplementary. Approved-label outcome: **TP**.

Rubric AI ngoài runtime: {"context_sufficiency_basis":"all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation","context_sufficient":true,"expected_evidence_ids":["evidence-b07a5ff4763e629715e6"],"missing_answer_units":[],"missing_evidence_diagnostics":[],"returned_evidence_ids":["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"],"satisfied_answer_units":["initial_spawn","initial_observations"]}. Rubric này còn giới hạn exact text/semantic unknown và không phải independent validation.

Requirement `r1` — `process_relationship`: `{"chain":false,"child":"mshta.exe","parent":"cmd.exe"}`; support `supported`.

Parser source spans (exact original query offsets/text):

- {"clause_id":"c1","end":77,"role":"request","start":0,"text":"What evidence supports the cmd.exe to mshta.exe process creation relationship"}
- {"clause_id":"c1","end":34,"role":"parent","start":27,"text":"cmd.exe"}
- {"clause_id":"c1","end":47,"role":"child","start":38,"text":"mshta.exe"}

Trace ràng buộc parent và child đúng chiều, có instance identities và source references của process creation.

Completeness/contradiction guards: {"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"status":"supported"}.

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/ParentImage`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/ParentImage`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"mshta.exe","object_identity":"{39e4a257-2d77-5f91-6b13-000000000700}","subject":"cmd.exe","subject_identity":"{39e4a257-2d59-5f91-6813-000000000700}"}.

> C:\Windows\System32\cmd.exe

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/Image`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/Image`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"mshta.exe","object_identity":"{39e4a257-2d77-5f91-6b13-000000000700}","subject":"cmd.exe","subject_identity":"{39e4a257-2d59-5f91-6813-000000000700}"}.

> C:\Windows\System32\mshta.exe

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/ParentProcessGuid`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/ParentProcessGuid`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"mshta.exe","object_identity":"{39e4a257-2d77-5f91-6b13-000000000700}","subject":"cmd.exe","subject_identity":"{39e4a257-2d59-5f91-6813-000000000700}"}.

> {39e4a257-2d59-5f91-6813-000000000700}

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/ProcessGuid`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/ProcessGuid`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"mshta.exe","object_identity":"{39e4a257-2d77-5f91-6b13-000000000700}","subject":"cmd.exe","subject_identity":"{39e4a257-2d59-5f91-6813-000000000700}"}.

> {39e4a257-2d77-5f91-6b13-000000000700}

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/source_file`, context `/final_items/6/payload/attributes/attributes/source_observations/0/source_file`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/raw_record_ref`, context `/final_items/6/payload/attributes/attributes/source_observations/0/raw_record_ref`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> jsonl:line:275

Giới hạn:

- Trace được đối chiếu với final_items thực tế; runtime support không thay thế approved label hoặc rubric ngoài.
- Thiếu evidence chỉ mô tả context đã kiểm tra; không chứng minh hành vi vắng mặt trên toàn hệ thống.
- Parent-child creation không chứng minh completion, payload intent hoặc hành vi network.

Requirement `r2` — `evidence_provenance`: `{"process":"mshta.exe"}`; support `supported`.

Parser source spans (exact original query offsets/text):

- {"clause_id":"c1","end":77,"role":"request","start":0,"text":"What evidence supports the cmd.exe to mshta.exe process creation relationship"}
- {"clause_id":"c1","end":47,"role":"subject","start":38,"text":"mshta.exe"}
- {"clause_id":"c1","end":13,"role":"action","start":5,"text":"evidence"}

Các trường/source observation thực sự được trả về gắn event/provider/timestamp với source file và raw record reference.

Completeness/contradiction guards: {"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"status":"supported"}.

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/Image`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/Image`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> C:\Windows\System32\mshta.exe

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/SourceName`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/SourceName`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> Microsoft-Windows-Sysmon

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/Channel`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/Channel`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> Microsoft-Windows-Sysmon/Operational

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/EventID`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/EventID`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> 1

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/TimeCreated`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/TimeCreated`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> 2020-10-22T02:57:59.857Z

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/source_file`, context `/final_items/6/payload/attributes/attributes/source_observations/0/source_file`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/raw_record_ref`, context `/final_items/6/payload/attributes/attributes/source_observations/0/raw_record_ref`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> jsonl:line:275

Giới hạn:

- Trace được đối chiếu với final_items thực tế; runtime support không thay thế approved label hoặc rubric ngoài.
- Thiếu evidence chỉ mô tả context đã kiểm tra; không chứng minh hành vi vắng mặt trên toàn hệ thống.
- Không tự sửa xung đột TimeCreated/UtcTime hoặc suy timezone chưa được nguồn xác minh.

### E4: abstain->proceed

Legacy decision: `proceed`; scope `unspecified`. Final context: 39 items, 0 supplementary. Approved-label outcome: **TP**.

Rubric AI ngoài runtime: {"context_sufficiency_basis":"all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation","context_sufficient":true,"expected_evidence_ids":["evidence-b07a5ff4763e629715e6"],"missing_answer_units":[],"missing_evidence_diagnostics":[],"returned_evidence_ids":["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"],"satisfied_answer_units":["initial_spawn","initial_observations"]}. Rubric này còn giới hạn exact text/semantic unknown và không phải independent validation.

Requirement `r1` — `process_relationship`: `{"chain":false,"child":"mshta.exe","parent":"cmd.exe"}`; support `supported`.

Parser source spans (exact original query offsets/text):

- {"clause_id":"c1","end":77,"role":"request","start":0,"text":"What evidence supports the cmd.exe to mshta.exe process creation relationship"}
- {"clause_id":"c1","end":34,"role":"parent","start":27,"text":"cmd.exe"}
- {"clause_id":"c1","end":47,"role":"child","start":38,"text":"mshta.exe"}

Trace ràng buộc parent và child đúng chiều, có instance identities và source references của process creation.

Completeness/contradiction guards: {"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"status":"supported"}.

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/ParentImage`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/ParentImage`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"mshta.exe","object_identity":"{39e4a257-2d77-5f91-6b13-000000000700}","subject":"cmd.exe","subject_identity":"{39e4a257-2d59-5f91-6813-000000000700}"}.

> C:\Windows\System32\cmd.exe

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/Image`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/Image`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"mshta.exe","object_identity":"{39e4a257-2d77-5f91-6b13-000000000700}","subject":"cmd.exe","subject_identity":"{39e4a257-2d59-5f91-6813-000000000700}"}.

> C:\Windows\System32\mshta.exe

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/ParentProcessGuid`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/ParentProcessGuid`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"mshta.exe","object_identity":"{39e4a257-2d77-5f91-6b13-000000000700}","subject":"cmd.exe","subject_identity":"{39e4a257-2d59-5f91-6813-000000000700}"}.

> {39e4a257-2d59-5f91-6813-000000000700}

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/ProcessGuid`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/ProcessGuid`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"mshta.exe","object_identity":"{39e4a257-2d77-5f91-6b13-000000000700}","subject":"cmd.exe","subject_identity":"{39e4a257-2d59-5f91-6813-000000000700}"}.

> {39e4a257-2d77-5f91-6b13-000000000700}

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/source_file`, context `/final_items/6/payload/attributes/attributes/source_observations/0/source_file`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/raw_record_ref`, context `/final_items/6/payload/attributes/attributes/source_observations/0/raw_record_ref`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> jsonl:line:275

Giới hạn:

- Trace được đối chiếu với final_items thực tế; runtime support không thay thế approved label hoặc rubric ngoài.
- Thiếu evidence chỉ mô tả context đã kiểm tra; không chứng minh hành vi vắng mặt trên toàn hệ thống.
- Parent-child creation không chứng minh completion, payload intent hoặc hành vi network.

Requirement `r2` — `evidence_provenance`: `{"process":"mshta.exe"}`; support `supported`.

Parser source spans (exact original query offsets/text):

- {"clause_id":"c1","end":77,"role":"request","start":0,"text":"What evidence supports the cmd.exe to mshta.exe process creation relationship"}
- {"clause_id":"c1","end":47,"role":"subject","start":38,"text":"mshta.exe"}
- {"clause_id":"c1","end":13,"role":"action","start":5,"text":"evidence"}

Các trường/source observation thực sự được trả về gắn event/provider/timestamp với source file và raw record reference.

Completeness/contradiction guards: {"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"status":"supported"}.

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/Image`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/Image`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> C:\Windows\System32\mshta.exe

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/SourceName`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/SourceName`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> Microsoft-Windows-Sysmon

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/Channel`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/Channel`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> Microsoft-Windows-Sysmon/Operational

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/EventID`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/EventID`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> 1

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/TimeCreated`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/TimeCreated`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> 2020-10-22T02:57:59.857Z

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/source_file`, context `/final_items/6/payload/attributes/attributes/source_observations/0/source_file`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/raw_record_ref`, context `/final_items/6/payload/attributes/attributes/source_observations/0/raw_record_ref`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> jsonl:line:275

Giới hạn:

- Trace được đối chiếu với final_items thực tế; runtime support không thay thế approved label hoặc rubric ngoài.
- Thiếu evidence chỉ mô tả context đã kiểm tra; không chứng minh hành vi vắng mặt trên toàn hệ thống.
- Không tự sửa xung đột TimeCreated/UtcTime hoặc suy timezone chưa được nguồn xác minh.


## `rd-en-final-spawn-evidence` (en)

What evidence supports the mshta.exe to powershell.exe process creation relationship?

Approved label: **proceed**; category `relevant_direct`. Đây là đối chiếu ngoài runtime; không thay đổi nhãn.

| Arm | Decision | Parser | Support | Rubric context sufficient | Reasons |
| --- | --- | --- | --- | --- | --- |
| E0 | abstain | ambiguous | unknown | True | query_requirements_ambiguous, required_evidence_unknown |
| E1 | proceed | supported | supported | True | — |
| E2 | abstain | ambiguous | unknown | True | query_requirements_ambiguous, required_evidence_unknown, independent_evidence_guard_unknown, mandatory_support_trace_empty, required_evidence_identity_or_source_anchor_missing |
| E3 | proceed | supported | supported | True | — |
| E4 | proceed | supported | supported | True | — |

Nhóm thay đổi: abstain_to_proceed.

### E1: abstain->proceed

Legacy decision: `proceed`; scope `unspecified`. Final context: 39 items, 0 supplementary. Approved-label outcome: **TP**.

Rubric AI ngoài runtime: {"context_sufficiency_basis":"all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation","context_sufficient":true,"expected_evidence_ids":["evidence-b31714b888d1489a380c"],"missing_answer_units":[],"missing_evidence_diagnostics":[],"returned_evidence_ids":["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"],"satisfied_answer_units":["final_spawn","final_observations"]}. Rubric này còn giới hạn exact text/semantic unknown và không phải independent validation.

Requirement `r1` — `process_relationship`: `{"chain":false,"child":"powershell.exe","parent":"mshta.exe"}`; support `supported`.

Parser source spans (exact original query offsets/text):

- {"clause_id":"c1","end":84,"role":"request","start":0,"text":"What evidence supports the mshta.exe to powershell.exe process creation relationship"}
- {"clause_id":"c1","end":36,"role":"parent","start":27,"text":"mshta.exe"}
- {"clause_id":"c1","end":54,"role":"child","start":40,"text":"powershell.exe"}

Trace ràng buộc parent và child đúng chiều, có instance identities và source references của process creation.

Completeness/contradiction guards: {"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"status":"supported"}.

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/ParentProcessName`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/ParentProcessName`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"powershell.exe","object_identity":"0x2564","subject":"mshta.exe","subject_identity":"0x2ae4"}.

> C:\Windows\System32\mshta.exe

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/NewProcessName`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/NewProcessName`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"powershell.exe","object_identity":"0x2564","subject":"mshta.exe","subject_identity":"0x2ae4"}.

> C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/ProcessId`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/ProcessId`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"powershell.exe","object_identity":"0x2564","subject":"mshta.exe","subject_identity":"0x2ae4"}.

> 0x2ae4

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/NewProcessId`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/NewProcessId`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"powershell.exe","object_identity":"0x2564","subject":"mshta.exe","subject_identity":"0x2ae4"}.

> 0x2564

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/source_file`, context `/final_items/10/payload/attributes/attributes/source_observations/0/source_file`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/raw_record_ref`, context `/final_items/10/payload/attributes/attributes/source_observations/0/raw_record_ref`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> jsonl:line:30

Giới hạn:

- Trace được đối chiếu với final_items thực tế; runtime support không thay thế approved label hoặc rubric ngoài.
- Thiếu evidence chỉ mô tả context đã kiểm tra; không chứng minh hành vi vắng mặt trên toàn hệ thống.
- Parent-child creation không chứng minh completion, payload intent hoặc hành vi network.

Requirement `r2` — `evidence_provenance`: `{"process":"powershell.exe"}`; support `supported`.

Parser source spans (exact original query offsets/text):

- {"clause_id":"c1","end":84,"role":"request","start":0,"text":"What evidence supports the mshta.exe to powershell.exe process creation relationship"}
- {"clause_id":"c1","end":54,"role":"subject","start":40,"text":"powershell.exe"}
- {"clause_id":"c1","end":13,"role":"action","start":5,"text":"evidence"}

Các trường/source observation thực sự được trả về gắn event/provider/timestamp với source file và raw record reference.

Completeness/contradiction guards: {"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"status":"supported"}.

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/NewProcessName`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/NewProcessName`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/SourceName`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/SourceName`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> Microsoft-Windows-Security-Auditing

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/Channel`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/Channel`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> Security

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/EventID`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/EventID`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> 4688

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/TimeCreated`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/TimeCreated`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> 2020-10-22T02:58:00.462Z

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/source_file`, context `/final_items/10/payload/attributes/attributes/source_observations/0/source_file`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/raw_record_ref`, context `/final_items/10/payload/attributes/attributes/source_observations/0/raw_record_ref`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> jsonl:line:30

Giới hạn:

- Trace được đối chiếu với final_items thực tế; runtime support không thay thế approved label hoặc rubric ngoài.
- Thiếu evidence chỉ mô tả context đã kiểm tra; không chứng minh hành vi vắng mặt trên toàn hệ thống.
- Không tự sửa xung đột TimeCreated/UtcTime hoặc suy timezone chưa được nguồn xác minh.

### E3: abstain->proceed

Legacy decision: `proceed`; scope `unspecified`. Final context: 39 items, 0 supplementary. Approved-label outcome: **TP**.

Rubric AI ngoài runtime: {"context_sufficiency_basis":"all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation","context_sufficient":true,"expected_evidence_ids":["evidence-b31714b888d1489a380c"],"missing_answer_units":[],"missing_evidence_diagnostics":[],"returned_evidence_ids":["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"],"satisfied_answer_units":["final_spawn","final_observations"]}. Rubric này còn giới hạn exact text/semantic unknown và không phải independent validation.

Requirement `r1` — `process_relationship`: `{"chain":false,"child":"powershell.exe","parent":"mshta.exe"}`; support `supported`.

Parser source spans (exact original query offsets/text):

- {"clause_id":"c1","end":84,"role":"request","start":0,"text":"What evidence supports the mshta.exe to powershell.exe process creation relationship"}
- {"clause_id":"c1","end":36,"role":"parent","start":27,"text":"mshta.exe"}
- {"clause_id":"c1","end":54,"role":"child","start":40,"text":"powershell.exe"}

Trace ràng buộc parent và child đúng chiều, có instance identities và source references của process creation.

Completeness/contradiction guards: {"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"status":"supported"}.

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/ParentProcessName`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/ParentProcessName`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"powershell.exe","object_identity":"0x2564","subject":"mshta.exe","subject_identity":"0x2ae4"}.

> C:\Windows\System32\mshta.exe

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/NewProcessName`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/NewProcessName`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"powershell.exe","object_identity":"0x2564","subject":"mshta.exe","subject_identity":"0x2ae4"}.

> C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/ProcessId`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/ProcessId`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"powershell.exe","object_identity":"0x2564","subject":"mshta.exe","subject_identity":"0x2ae4"}.

> 0x2ae4

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/NewProcessId`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/NewProcessId`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"powershell.exe","object_identity":"0x2564","subject":"mshta.exe","subject_identity":"0x2ae4"}.

> 0x2564

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/source_file`, context `/final_items/10/payload/attributes/attributes/source_observations/0/source_file`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/raw_record_ref`, context `/final_items/10/payload/attributes/attributes/source_observations/0/raw_record_ref`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> jsonl:line:30

Giới hạn:

- Trace được đối chiếu với final_items thực tế; runtime support không thay thế approved label hoặc rubric ngoài.
- Thiếu evidence chỉ mô tả context đã kiểm tra; không chứng minh hành vi vắng mặt trên toàn hệ thống.
- Parent-child creation không chứng minh completion, payload intent hoặc hành vi network.

Requirement `r2` — `evidence_provenance`: `{"process":"powershell.exe"}`; support `supported`.

Parser source spans (exact original query offsets/text):

- {"clause_id":"c1","end":84,"role":"request","start":0,"text":"What evidence supports the mshta.exe to powershell.exe process creation relationship"}
- {"clause_id":"c1","end":54,"role":"subject","start":40,"text":"powershell.exe"}
- {"clause_id":"c1","end":13,"role":"action","start":5,"text":"evidence"}

Các trường/source observation thực sự được trả về gắn event/provider/timestamp với source file và raw record reference.

Completeness/contradiction guards: {"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"status":"supported"}.

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/NewProcessName`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/NewProcessName`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/SourceName`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/SourceName`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> Microsoft-Windows-Security-Auditing

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/Channel`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/Channel`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> Security

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/EventID`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/EventID`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> 4688

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/TimeCreated`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/TimeCreated`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> 2020-10-22T02:58:00.462Z

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/source_file`, context `/final_items/10/payload/attributes/attributes/source_observations/0/source_file`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/raw_record_ref`, context `/final_items/10/payload/attributes/attributes/source_observations/0/raw_record_ref`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> jsonl:line:30

Giới hạn:

- Trace được đối chiếu với final_items thực tế; runtime support không thay thế approved label hoặc rubric ngoài.
- Thiếu evidence chỉ mô tả context đã kiểm tra; không chứng minh hành vi vắng mặt trên toàn hệ thống.
- Không tự sửa xung đột TimeCreated/UtcTime hoặc suy timezone chưa được nguồn xác minh.

### E4: abstain->proceed

Legacy decision: `proceed`; scope `unspecified`. Final context: 39 items, 0 supplementary. Approved-label outcome: **TP**.

Rubric AI ngoài runtime: {"context_sufficiency_basis":"all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation","context_sufficient":true,"expected_evidence_ids":["evidence-b31714b888d1489a380c"],"missing_answer_units":[],"missing_evidence_diagnostics":[],"returned_evidence_ids":["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"],"satisfied_answer_units":["final_spawn","final_observations"]}. Rubric này còn giới hạn exact text/semantic unknown và không phải independent validation.

Requirement `r1` — `process_relationship`: `{"chain":false,"child":"powershell.exe","parent":"mshta.exe"}`; support `supported`.

Parser source spans (exact original query offsets/text):

- {"clause_id":"c1","end":84,"role":"request","start":0,"text":"What evidence supports the mshta.exe to powershell.exe process creation relationship"}
- {"clause_id":"c1","end":36,"role":"parent","start":27,"text":"mshta.exe"}
- {"clause_id":"c1","end":54,"role":"child","start":40,"text":"powershell.exe"}

Trace ràng buộc parent và child đúng chiều, có instance identities và source references của process creation.

Completeness/contradiction guards: {"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"status":"supported"}.

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/ParentProcessName`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/ParentProcessName`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"powershell.exe","object_identity":"0x2564","subject":"mshta.exe","subject_identity":"0x2ae4"}.

> C:\Windows\System32\mshta.exe

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/NewProcessName`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/NewProcessName`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"powershell.exe","object_identity":"0x2564","subject":"mshta.exe","subject_identity":"0x2ae4"}.

> C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/ProcessId`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/ProcessId`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"powershell.exe","object_identity":"0x2564","subject":"mshta.exe","subject_identity":"0x2ae4"}.

> 0x2ae4

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/NewProcessId`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/NewProcessId`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"powershell.exe","object_identity":"0x2564","subject":"mshta.exe","subject_identity":"0x2ae4"}.

> 0x2564

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/source_file`, context `/final_items/10/payload/attributes/attributes/source_observations/0/source_file`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/raw_record_ref`, context `/final_items/10/payload/attributes/attributes/source_observations/0/raw_record_ref`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> jsonl:line:30

Giới hạn:

- Trace được đối chiếu với final_items thực tế; runtime support không thay thế approved label hoặc rubric ngoài.
- Thiếu evidence chỉ mô tả context đã kiểm tra; không chứng minh hành vi vắng mặt trên toàn hệ thống.
- Parent-child creation không chứng minh completion, payload intent hoặc hành vi network.

Requirement `r2` — `evidence_provenance`: `{"process":"powershell.exe"}`; support `supported`.

Parser source spans (exact original query offsets/text):

- {"clause_id":"c1","end":84,"role":"request","start":0,"text":"What evidence supports the mshta.exe to powershell.exe process creation relationship"}
- {"clause_id":"c1","end":54,"role":"subject","start":40,"text":"powershell.exe"}
- {"clause_id":"c1","end":13,"role":"action","start":5,"text":"evidence"}

Các trường/source observation thực sự được trả về gắn event/provider/timestamp với source file và raw record reference.

Completeness/contradiction guards: {"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"status":"supported"}.

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/NewProcessName`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/NewProcessName`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/SourceName`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/SourceName`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> Microsoft-Windows-Security-Auditing

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/Channel`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/Channel`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> Security

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/EventID`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/EventID`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> 4688

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/original_fields/TimeCreated`, context `/final_items/10/payload/attributes/attributes/source_observations/0/original_fields/TimeCreated`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> 2020-10-22T02:58:00.462Z

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/source_file`, context `/final_items/10/payload/attributes/attributes/source_observations/0/source_file`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json

- `node:graph-node--5de7c6b37416d9b4a9e1d38dbca3b6e637c610654f3aeeb7bf9cd7a2edeaa121` (traversal), field `/attributes/attributes/source_observations/0/raw_record_ref`, context `/final_items/10/payload/attributes/attributes/source_observations/0/raw_record_ref`, source `/facts/1`.
  Source binding: {"json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> jsonl:line:30

Giới hạn:

- Trace được đối chiếu với final_items thực tế; runtime support không thay thế approved label hoặc rubric ngoài.
- Thiếu evidence chỉ mô tả context đã kiểm tra; không chứng minh hành vi vắng mặt trên toàn hệ thống.
- Không tự sửa xung đột TimeCreated/UtcTime hoặc suy timezone chưa được nguồn xác minh.


## `rd-vi-proxy-technique-assessment` (vi)

Đánh giá hiện tại đối với ATT&CK T1218.005 có mức hỗ trợ bằng chứng và trạng thái review nào?

Approved label: **proceed**; category `relevant_direct`. Đây là đối chiếu ngoài runtime; không thay đổi nhãn.

| Arm | Decision | Parser | Support | Rubric context sufficient | Reasons |
| --- | --- | --- | --- | --- | --- |
| E0 | abstain | supported | supported | True | legacy_quality_gate_abstained |
| E1 | abstain | supported | missing | True | required_evidence_missing, legacy_quality_gate_abstained |
| E2 | proceed | supported | supported | True | — |
| E3 | abstain | supported | missing | True | required_evidence_missing, independent_evidence_guard_missing, mandatory_support_trace_empty, required_evidence_identity_or_source_anchor_missing, required_completeness_incomplete |
| E4 | proceed | supported | supported | True | — |

Nhóm thay đổi: abstain_to_proceed.

### E2: abstain->proceed

Legacy decision: `abstain`; scope `unspecified`. Final context: 34 items, 0 supplementary. Approved-label outcome: **TP**.

Rubric AI ngoài runtime: {"context_sufficiency_basis":"all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation","context_sufficient":true,"expected_evidence_ids":["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"],"missing_answer_units":[],"missing_evidence_diagnostics":[],"returned_evidence_ids":["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"],"satisfied_answer_units":["proxy_assessment"]}. Rubric này còn giới hạn exact text/semantic unknown và không phải independent validation.

Requirement `r1` — `evidence_provenance`: `{"process":null}`; support `supported`.

Requirements v1 không có source spans; không tạo trace ngôn ngữ giả cho E0/E2.

Các trường/source observation thực sự được trả về gắn event/provider/timestamp với source file và raw record reference.

Completeness/contradiction guards: {"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"status":"supported"}.

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/Image`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/Image`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> C:\Windows\System32\mshta.exe

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/SourceName`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/SourceName`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> Microsoft-Windows-Sysmon

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/Channel`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/Channel`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> Microsoft-Windows-Sysmon/Operational

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/EventID`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/EventID`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> 1

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/TimeCreated`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/TimeCreated`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> 2020-10-22T02:57:59.857Z

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/source_file`, context `/final_items/6/payload/attributes/attributes/source_observations/0/source_file`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/raw_record_ref`, context `/final_items/6/payload/attributes/attributes/source_observations/0/raw_record_ref`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> jsonl:line:275

Giới hạn:

- Trace được đối chiếu với final_items thực tế; runtime support không thay thế approved label hoặc rubric ngoài.
- Thiếu evidence chỉ mô tả context đã kiểm tra; không chứng minh hành vi vắng mặt trên toàn hệ thống.
- Không tự sửa xung đột TimeCreated/UtcTime hoặc suy timezone chưa được nguồn xác minh.

Requirement `r2` — `technique_assessment`: `{"certainty":"assessment","technique_id":"T1218.005"}`; support `supported`.

Requirements v1 không có source spans; không tạo trace ngôn ngữ giả cho E0/E2.

Trace giữ external technique ID, evidence_support, review_status và rationale của source-associated assessment.

Completeness/contradiction guards: {"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"status":"supported"}.

- `chunk:retrieval-chunk--8a73d544afa5a8a974c12b905a13224e95e58a8dc73c3a6141ca02c3e2b731e8` (ranked), field `/mitre_external_ids`, context `/final_items/0/payload/mitre_external_ids`, source `/mitre_assessments/2`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/mitre_assessments/2","object_id":"mitre-assessment--09f12e591ccdc088e57b01d09c528efead966e0f723ae9a0be6596b78a9c78f1","object_type":"mitre_assessment"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> ["T1218.005"]

- `chunk:retrieval-chunk--8a73d544afa5a8a974c12b905a13224e95e58a8dc73c3a6141ca02c3e2b731e8` (ranked), field `/status`, context `/final_items/0/payload/status`, source `/mitre_assessments/2`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/mitre_assessments/2","object_id":"mitre-assessment--09f12e591ccdc088e57b01d09c528efead966e0f723ae9a0be6596b78a9c78f1","object_type":"mitre_assessment"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> candidate

- `chunk:retrieval-chunk--8a73d544afa5a8a974c12b905a13224e95e58a8dc73c3a6141ca02c3e2b731e8` (ranked), field `/metadata/evidence_support`, context `/final_items/0/payload/metadata/evidence_support`, source `/mitre_assessments/2`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/mitre_assessments/2","object_id":"mitre-assessment--09f12e591ccdc088e57b01d09c528efead966e0f723ae9a0be6596b78a9c78f1","object_type":"mitre_assessment"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> supported_by_observed_behavior

- `chunk:retrieval-chunk--8a73d544afa5a8a974c12b905a13224e95e58a8dc73c3a6141ca02c3e2b731e8` (ranked), field `/metadata/review_status`, context `/final_items/0/payload/metadata/review_status`, source `/mitre_assessments/2`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/mitre_assessments/2","object_id":"mitre-assessment--09f12e591ccdc088e57b01d09c528efead966e0f723ae9a0be6596b78a9c78f1","object_type":"mitre_assessment"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> needs_review

- `chunk:retrieval-chunk--8a73d544afa5a8a974c12b905a13224e95e58a8dc73c3a6141ca02c3e2b731e8` (ranked), field `/content`, context `/final_items/0/payload/content`, source `/mitre_assessments/2`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/mitre_assessments/2","object_id":"mitre-assessment--09f12e591ccdc088e57b01d09c528efead966e0f723ae9a0be6596b78a9c78f1","object_type":"mitre_assessment"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> MITRE assessment T1218.005: Mshta. Status: candidate. Evidence support: supported_by_observed_behavior. Rationale: mshta.exe is directly observed in the first evidence group, and its launch of PowerShell is directly observed in the second. This supports the candidate technique at the evidence level only and does not finalize the assessment. Review status: needs_review.

Giới hạn:

- Trace được đối chiếu với final_items thực tế; runtime support không thay thế approved label hoặc rubric ngoài.
- Thiếu evidence chỉ mô tả context đã kiểm tra; không chứng minh hành vi vắng mặt trên toàn hệ thống.
- Candidate/needs_review không được nâng thành confirmed; Sigma tags không tự chứng minh behavior.

### E4: abstain->proceed

Legacy decision: `abstain`; scope `unspecified`. Final context: 40 items, 6 supplementary. Approved-label outcome: **TP**.

Rubric AI ngoài runtime: {"context_sufficiency_basis":"all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation","context_sufficient":true,"expected_evidence_ids":["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"],"missing_answer_units":[],"missing_evidence_diagnostics":[],"returned_evidence_ids":["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"],"satisfied_answer_units":["proxy_assessment"]}. Rubric này còn giới hạn exact text/semantic unknown và không phải independent validation.

Requirement `r1` — `evidence_provenance`: `{"process":null}`; support `supported`.

Parser source spans (exact original query offsets/text):

- {"clause_id":"c1","end":67,"role":"request","start":0,"text":"Đánh giá hiện tại đối với ATT&CK T1218.005 có mức hỗ trợ bằng chứng"}
- {"clause_id":"c1","end":67,"role":"action","start":57,"text":"bằng chứng"}

Các trường/source observation thực sự được trả về gắn event/provider/timestamp với source file và raw record reference.

Completeness/contradiction guards: {"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"status":"supported"}.

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/Image`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/Image`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> C:\Windows\System32\mshta.exe

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/SourceName`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/SourceName`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> Microsoft-Windows-Sysmon

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/Channel`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/Channel`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> Microsoft-Windows-Sysmon/Operational

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/EventID`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/EventID`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> 1

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/TimeCreated`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/TimeCreated`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> 2020-10-22T02:57:59.857Z

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/source_file`, context `/final_items/6/payload/attributes/attributes/source_observations/0/source_file`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/raw_record_ref`, context `/final_items/6/payload/attributes/attributes/source_observations/0/raw_record_ref`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> jsonl:line:275

Giới hạn:

- Trace được đối chiếu với final_items thực tế; runtime support không thay thế approved label hoặc rubric ngoài.
- Thiếu evidence chỉ mô tả context đã kiểm tra; không chứng minh hành vi vắng mặt trên toàn hệ thống.
- Không tự sửa xung đột TimeCreated/UtcTime hoặc suy timezone chưa được nguồn xác minh.

Requirement `r2` — `technique_assessment`: `{"certainty":"assessment","technique_id":"T1218.005"}`; support `supported`.

Parser source spans (exact original query offsets/text):

- {"clause_id":"c1","end":67,"role":"request","start":0,"text":"Đánh giá hiện tại đối với ATT&CK T1218.005 có mức hỗ trợ bằng chứng"}
- {"clause_id":"c1","end":32,"role":"action","start":26,"text":"ATT&CK"}

Trace giữ external technique ID, evidence_support, review_status và rationale của source-associated assessment.

Completeness/contradiction guards: {"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"status":"supported"}.

- `chunk:retrieval-chunk--8a73d544afa5a8a974c12b905a13224e95e58a8dc73c3a6141ca02c3e2b731e8` (ranked), field `/mitre_external_ids`, context `/final_items/0/payload/mitre_external_ids`, source `/mitre_assessments/2`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/mitre_assessments/2","object_id":"mitre-assessment--09f12e591ccdc088e57b01d09c528efead966e0f723ae9a0be6596b78a9c78f1","object_type":"mitre_assessment"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> ["T1218.005"]

- `chunk:retrieval-chunk--8a73d544afa5a8a974c12b905a13224e95e58a8dc73c3a6141ca02c3e2b731e8` (ranked), field `/status`, context `/final_items/0/payload/status`, source `/mitre_assessments/2`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/mitre_assessments/2","object_id":"mitre-assessment--09f12e591ccdc088e57b01d09c528efead966e0f723ae9a0be6596b78a9c78f1","object_type":"mitre_assessment"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> candidate

- `chunk:retrieval-chunk--8a73d544afa5a8a974c12b905a13224e95e58a8dc73c3a6141ca02c3e2b731e8` (ranked), field `/metadata/evidence_support`, context `/final_items/0/payload/metadata/evidence_support`, source `/mitre_assessments/2`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/mitre_assessments/2","object_id":"mitre-assessment--09f12e591ccdc088e57b01d09c528efead966e0f723ae9a0be6596b78a9c78f1","object_type":"mitre_assessment"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> supported_by_observed_behavior

- `chunk:retrieval-chunk--8a73d544afa5a8a974c12b905a13224e95e58a8dc73c3a6141ca02c3e2b731e8` (ranked), field `/metadata/review_status`, context `/final_items/0/payload/metadata/review_status`, source `/mitre_assessments/2`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/mitre_assessments/2","object_id":"mitre-assessment--09f12e591ccdc088e57b01d09c528efead966e0f723ae9a0be6596b78a9c78f1","object_type":"mitre_assessment"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> needs_review

- `chunk:retrieval-chunk--8a73d544afa5a8a974c12b905a13224e95e58a8dc73c3a6141ca02c3e2b731e8` (ranked), field `/content`, context `/final_items/0/payload/content`, source `/mitre_assessments/2`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/mitre_assessments/2","object_id":"mitre-assessment--09f12e591ccdc088e57b01d09c528efead966e0f723ae9a0be6596b78a9c78f1","object_type":"mitre_assessment"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> MITRE assessment T1218.005: Mshta. Status: candidate. Evidence support: supported_by_observed_behavior. Rationale: mshta.exe is directly observed in the first evidence group, and its launch of PowerShell is directly observed in the second. This supports the candidate technique at the evidence level only and does not finalize the assessment. Review status: needs_review.

Giới hạn:

- Trace được đối chiếu với final_items thực tế; runtime support không thay thế approved label hoặc rubric ngoài.
- Thiếu evidence chỉ mô tả context đã kiểm tra; không chứng minh hành vi vắng mặt trên toàn hệ thống.
- Candidate/needs_review không được nâng thành confirmed; Sigma tags không tự chứng minh behavior.

Requirement `r3` — `review_limitations`: `{"facets":["review_status"]}`; support `supported`.

Parser source spans (exact original query offsets/text):

- {"clause_id":"c2","end":92,"role":"request","start":71,"text":"trạng thái review nào"}
- {"clause_id":"c2","end":88,"role":"requested_field","start":71,"text":"trạng thái review"}

Các limitation/review-scope fields được trích đúng source identities cần cho facets; completeness guard đối chiếu tập identities, không chỉ đếm items.

Completeness/contradiction guards: {"completeness":{"reason_codes":["requested_source_identity_set_present"],"status":"complete"},"contradiction":{"reason_codes":[],"status":"none_detected"},"status":"supported"}.

- `chunk:retrieval-chunk--86dd89fe0cfd03c1505a8534ce63dfb9f72221fe32c23d7a0341a66fa98d48ad` (supplementary), field `/metadata/analysis_status`, context `/final_items/34/payload/metadata/analysis_status`, source `/scenario`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/scenario","object_id":null,"object_type":"scenario"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> draft_reviewable

Giới hạn:

- Trace được đối chiếu với final_items thực tế; runtime support không thay thế approved label hoặc rubric ngoài.
- Thiếu evidence chỉ mô tả context đã kiểm tra; không chứng minh hành vi vắng mặt trên toàn hệ thống.
- analysis_status mô tả tình trạng phân tích của artifact; human approval không xác nhận kết luận an ninh.
- Limitation prose hỗ trợ câu hỏi về giới hạn, không chứng minh một positive behavior khác.


## `rd-vi-reviewed-scope-limitations` (vi)

Ground Truth ghi nhận những giới hạn nào đối với phạm vi bằng chứng đã review?

Approved label: **proceed**; category `relevant_direct`. Đây là đối chiếu ngoài runtime; không thay đổi nhãn.

| Arm | Decision | Parser | Support | Rubric context sufficient | Reasons |
| --- | --- | --- | --- | --- | --- |
| E0 | abstain | supported | supported | True | legacy_quality_gate_abstained |
| E1 | abstain | supported | supported | True | legacy_quality_gate_abstained |
| E2 | proceed | supported | supported | True | — |
| E3 | proceed | supported | supported | True | — |
| E4 | proceed | supported | supported | True | — |

Nhóm thay đổi: abstain_to_proceed.

### E2: abstain->proceed

Legacy decision: `abstain`; scope `unspecified`. Final context: 40 items, 6 supplementary. Approved-label outcome: **TP**.

Rubric AI ngoài runtime: {"context_sufficiency_basis":"all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation","context_sufficient":true,"expected_evidence_ids":[],"missing_answer_units":[],"missing_evidence_diagnostics":[],"returned_evidence_ids":["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"],"satisfied_answer_units":["limitation_0","limitation_1","limitation_2","limitation_3","limitation_4","limitation_5","limitation_6"]}. Rubric này còn giới hạn exact text/semantic unknown và không phải independent validation.

Requirement `r1` — `evidence_provenance`: `{"process":null}`; support `supported`.

Requirements v1 không có source spans; không tạo trace ngôn ngữ giả cho E0/E2.

Các trường/source observation thực sự được trả về gắn event/provider/timestamp với source file và raw record reference.

Completeness/contradiction guards: {"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"status":"supported"}.

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/Image`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/Image`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> C:\Windows\System32\mshta.exe

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/SourceName`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/SourceName`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> Microsoft-Windows-Sysmon

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/Channel`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/Channel`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> Microsoft-Windows-Sysmon/Operational

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/EventID`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/EventID`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> 1

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/TimeCreated`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/TimeCreated`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> 2020-10-22T02:57:59.857Z

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/source_file`, context `/final_items/6/payload/attributes/attributes/source_observations/0/source_file`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/raw_record_ref`, context `/final_items/6/payload/attributes/attributes/source_observations/0/raw_record_ref`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> jsonl:line:275

Giới hạn:

- Trace được đối chiếu với final_items thực tế; runtime support không thay thế approved label hoặc rubric ngoài.
- Thiếu evidence chỉ mô tả context đã kiểm tra; không chứng minh hành vi vắng mặt trên toàn hệ thống.
- Không tự sửa xung đột TimeCreated/UtcTime hoặc suy timezone chưa được nguồn xác minh.

Requirement `r2` — `review_limitations`: `{"facets":["scope"]}`; support `supported`.

Requirements v1 không có source spans; không tạo trace ngôn ngữ giả cho E0/E2.

Các limitation/review-scope fields được trích đúng source identities cần cho facets; completeness guard đối chiếu tập identities, không chỉ đếm items.

Completeness/contradiction guards: {"completeness":{"reason_codes":["requested_source_identity_set_present"],"status":"complete"},"contradiction":{"reason_codes":[],"status":"none_detected"},"status":"supported"}.

- `chunk:retrieval-chunk--21d69e9c7ff2d03d44ac6d53e1fa234e961f1c743e59c6ffa11289ddcd5e715c` (ranked), field `/content`, context `/final_items/0/payload/content`, source `/summary/limitations/0`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/summary/limitations/0","object_id":null,"object_type":"limitation"}; raw references [].
  Role binding: null.

> This ground truth scope covers only the two reviewed behavior and evidence groups.

- `node:graph-node--35b8bcd535dd4ccf222294889c5fa36ef7e5e2969809b6991e27d501bab1269b` (traversal), field `/label`, context `/final_items/8/payload/label`, source `/summary/limitations/0`.
  Source binding: {"json_pointer":"/summary/limitations/0","object_id":null,"object_type":"limitation"}; raw references [].
  Role binding: null.

> This ground truth scope covers only the two reviewed behavior and evidence groups.

- `chunk:retrieval-chunk--82de3946302e7f785eef02295ff593ae743fe8820b352255edd7688fde42479c` (supplementary), field `/content`, context `/final_items/35/payload/content`, source `/summary/limitations/1`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/summary/limitations/1","object_id":null,"object_type":"limitation"}; raw references [].
  Role binding: null.

> The two Sysmon observations carry upstream timestamp_conflict review issues.

- `chunk:retrieval-chunk--7c8854204807c39fe6d6da4ea799f643abe73976e973f1b6677fd130020af72a` (supplementary), field `/content`, context `/final_items/36/payload/content`, source `/summary/limitations/2`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/summary/limitations/2","object_id":null,"object_type":"limitation"}; raw references [].
  Role binding: null.

> A full-dataset negative scan has not been performed, so absence claims cannot be made across the full scope.

- `node:graph-node--cfe937b1c0ad152c49a19f0edaeb42cbca9c8da42682d806a63e31c8a4ed5f36` (traversal), field `/label`, context `/final_items/17/payload/label`, source `/summary/limitations/3`.
  Source binding: {"json_pointer":"/summary/limitations/3","object_id":null,"object_type":"limitation"}; raw references [].
  Role binding: null.

> MITRE assessments remain candidates and require human review.

- `chunk:retrieval-chunk--df3b8e31f96555994c35b133bba1cc21a226769503fd0a214bef7d3c16d7a1f3` (supplementary), field `/content`, context `/final_items/37/payload/content`, source `/summary/limitations/4`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/summary/limitations/4","object_id":null,"object_type":"limitation"}; raw references [].
  Role binding: null.

> Process-creation telemetry does not establish successful cmdlet completion, output, or the Sysmon service state.

- `chunk:retrieval-chunk--81558baf58ca7b808ffd023be3ed3f7bc806f9c12b608733a849786d0a09e571` (supplementary), field `/content`, context `/final_items/38/payload/content`, source `/summary/limitations/5`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/summary/limitations/5","object_id":null,"object_type":"limitation"}; raw references [].
  Role binding: null.

> Canonical timestamps follow TimeCreated; Sysmon UtcTime differs by about four hours and its timezone is unresolved.

- `chunk:retrieval-chunk--7c3e4f2632332dda121602b7919f6c7f5c6310e4347a0d24a0a9e1c823c4f030` (supplementary), field `/content`, context `/final_items/39/payload/content`, source `/summary/limitations/6`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/summary/limitations/6","object_id":null,"object_type":"limitation"}; raw references [].
  Role binding: null.

> The file also contains conhost creation, event-log clearing and temporary-file deletion telemetry outside this two-group core. These must not be described as globally absent or automatically classified as a destructive payload.

Giới hạn:

- Trace được đối chiếu với final_items thực tế; runtime support không thay thế approved label hoặc rubric ngoài.
- Thiếu evidence chỉ mô tả context đã kiểm tra; không chứng minh hành vi vắng mặt trên toàn hệ thống.
- analysis_status mô tả tình trạng phân tích của artifact; human approval không xác nhận kết luận an ninh.
- Limitation prose hỗ trợ câu hỏi về giới hạn, không chứng minh một positive behavior khác.

### E3: abstain->proceed

Legacy decision: `abstain`; scope `unspecified`. Final context: 40 items, 6 supplementary. Approved-label outcome: **TP**.

Rubric AI ngoài runtime: {"context_sufficiency_basis":"all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation","context_sufficient":true,"expected_evidence_ids":[],"missing_answer_units":[],"missing_evidence_diagnostics":[],"returned_evidence_ids":["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"],"satisfied_answer_units":["limitation_0","limitation_1","limitation_2","limitation_3","limitation_4","limitation_5","limitation_6"]}. Rubric này còn giới hạn exact text/semantic unknown và không phải independent validation.

Requirement `r1` — `review_limitations`: `{"facets":["all"]}`; support `supported`.

Parser source spans (exact original query offsets/text):

- {"clause_id":"c1","end":77,"role":"request","start":0,"text":"Ground Truth ghi nhận những giới hạn nào đối với phạm vi bằng chứng đã review"}
- {"clause_id":"c1","end":36,"role":"action","start":28,"text":"giới hạn"}

Các limitation/review-scope fields được trích đúng source identities cần cho facets; completeness guard đối chiếu tập identities, không chỉ đếm items.

Completeness/contradiction guards: {"completeness":{"reason_codes":["requested_source_identity_set_present"],"status":"complete"},"contradiction":{"reason_codes":[],"status":"none_detected"},"status":"supported"}.

- `node:graph-node--35b8bcd535dd4ccf222294889c5fa36ef7e5e2969809b6991e27d501bab1269b` (traversal), field `/label`, context `/final_items/8/payload/label`, source `/summary/limitations/0`.
  Source binding: {"json_pointer":"/summary/limitations/0","object_id":null,"object_type":"limitation"}; raw references [].
  Role binding: null.

> This ground truth scope covers only the two reviewed behavior and evidence groups.

- `chunk:retrieval-chunk--82de3946302e7f785eef02295ff593ae743fe8820b352255edd7688fde42479c` (supplementary), field `/content`, context `/final_items/35/payload/content`, source `/summary/limitations/1`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/summary/limitations/1","object_id":null,"object_type":"limitation"}; raw references [].
  Role binding: null.

> The two Sysmon observations carry upstream timestamp_conflict review issues.

- `chunk:retrieval-chunk--7c8854204807c39fe6d6da4ea799f643abe73976e973f1b6677fd130020af72a` (supplementary), field `/content`, context `/final_items/36/payload/content`, source `/summary/limitations/2`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/summary/limitations/2","object_id":null,"object_type":"limitation"}; raw references [].
  Role binding: null.

> A full-dataset negative scan has not been performed, so absence claims cannot be made across the full scope.

- `node:graph-node--cfe937b1c0ad152c49a19f0edaeb42cbca9c8da42682d806a63e31c8a4ed5f36` (traversal), field `/label`, context `/final_items/17/payload/label`, source `/summary/limitations/3`.
  Source binding: {"json_pointer":"/summary/limitations/3","object_id":null,"object_type":"limitation"}; raw references [].
  Role binding: null.

> MITRE assessments remain candidates and require human review.

- `chunk:retrieval-chunk--df3b8e31f96555994c35b133bba1cc21a226769503fd0a214bef7d3c16d7a1f3` (supplementary), field `/content`, context `/final_items/37/payload/content`, source `/summary/limitations/4`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/summary/limitations/4","object_id":null,"object_type":"limitation"}; raw references [].
  Role binding: null.

> Process-creation telemetry does not establish successful cmdlet completion, output, or the Sysmon service state.

- `chunk:retrieval-chunk--81558baf58ca7b808ffd023be3ed3f7bc806f9c12b608733a849786d0a09e571` (supplementary), field `/content`, context `/final_items/38/payload/content`, source `/summary/limitations/5`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/summary/limitations/5","object_id":null,"object_type":"limitation"}; raw references [].
  Role binding: null.

> Canonical timestamps follow TimeCreated; Sysmon UtcTime differs by about four hours and its timezone is unresolved.

- `chunk:retrieval-chunk--7c3e4f2632332dda121602b7919f6c7f5c6310e4347a0d24a0a9e1c823c4f030` (supplementary), field `/content`, context `/final_items/39/payload/content`, source `/summary/limitations/6`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/summary/limitations/6","object_id":null,"object_type":"limitation"}; raw references [].
  Role binding: null.

> The file also contains conhost creation, event-log clearing and temporary-file deletion telemetry outside this two-group core. These must not be described as globally absent or automatically classified as a destructive payload.

Giới hạn:

- Trace được đối chiếu với final_items thực tế; runtime support không thay thế approved label hoặc rubric ngoài.
- Thiếu evidence chỉ mô tả context đã kiểm tra; không chứng minh hành vi vắng mặt trên toàn hệ thống.
- analysis_status mô tả tình trạng phân tích của artifact; human approval không xác nhận kết luận an ninh.
- Limitation prose hỗ trợ câu hỏi về giới hạn, không chứng minh một positive behavior khác.

### E4: abstain->proceed

Legacy decision: `abstain`; scope `unspecified`. Final context: 40 items, 6 supplementary. Approved-label outcome: **TP**.

Rubric AI ngoài runtime: {"context_sufficiency_basis":"all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation","context_sufficient":true,"expected_evidence_ids":[],"missing_answer_units":[],"missing_evidence_diagnostics":[],"returned_evidence_ids":["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"],"satisfied_answer_units":["limitation_0","limitation_1","limitation_2","limitation_3","limitation_4","limitation_5","limitation_6"]}. Rubric này còn giới hạn exact text/semantic unknown và không phải independent validation.

Requirement `r1` — `review_limitations`: `{"facets":["all"]}`; support `supported`.

Parser source spans (exact original query offsets/text):

- {"clause_id":"c1","end":77,"role":"request","start":0,"text":"Ground Truth ghi nhận những giới hạn nào đối với phạm vi bằng chứng đã review"}
- {"clause_id":"c1","end":36,"role":"action","start":28,"text":"giới hạn"}

Các limitation/review-scope fields được trích đúng source identities cần cho facets; completeness guard đối chiếu tập identities, không chỉ đếm items.

Completeness/contradiction guards: {"completeness":{"reason_codes":["requested_source_identity_set_present"],"status":"complete"},"contradiction":{"reason_codes":[],"status":"none_detected"},"status":"supported"}.

- `node:graph-node--35b8bcd535dd4ccf222294889c5fa36ef7e5e2969809b6991e27d501bab1269b` (traversal), field `/label`, context `/final_items/8/payload/label`, source `/summary/limitations/0`.
  Source binding: {"json_pointer":"/summary/limitations/0","object_id":null,"object_type":"limitation"}; raw references [].
  Role binding: null.

> This ground truth scope covers only the two reviewed behavior and evidence groups.

- `chunk:retrieval-chunk--82de3946302e7f785eef02295ff593ae743fe8820b352255edd7688fde42479c` (supplementary), field `/content`, context `/final_items/35/payload/content`, source `/summary/limitations/1`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/summary/limitations/1","object_id":null,"object_type":"limitation"}; raw references [].
  Role binding: null.

> The two Sysmon observations carry upstream timestamp_conflict review issues.

- `chunk:retrieval-chunk--7c8854204807c39fe6d6da4ea799f643abe73976e973f1b6677fd130020af72a` (supplementary), field `/content`, context `/final_items/36/payload/content`, source `/summary/limitations/2`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/summary/limitations/2","object_id":null,"object_type":"limitation"}; raw references [].
  Role binding: null.

> A full-dataset negative scan has not been performed, so absence claims cannot be made across the full scope.

- `node:graph-node--cfe937b1c0ad152c49a19f0edaeb42cbca9c8da42682d806a63e31c8a4ed5f36` (traversal), field `/label`, context `/final_items/17/payload/label`, source `/summary/limitations/3`.
  Source binding: {"json_pointer":"/summary/limitations/3","object_id":null,"object_type":"limitation"}; raw references [].
  Role binding: null.

> MITRE assessments remain candidates and require human review.

- `chunk:retrieval-chunk--df3b8e31f96555994c35b133bba1cc21a226769503fd0a214bef7d3c16d7a1f3` (supplementary), field `/content`, context `/final_items/37/payload/content`, source `/summary/limitations/4`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/summary/limitations/4","object_id":null,"object_type":"limitation"}; raw references [].
  Role binding: null.

> Process-creation telemetry does not establish successful cmdlet completion, output, or the Sysmon service state.

- `chunk:retrieval-chunk--81558baf58ca7b808ffd023be3ed3f7bc806f9c12b608733a849786d0a09e571` (supplementary), field `/content`, context `/final_items/38/payload/content`, source `/summary/limitations/5`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/summary/limitations/5","object_id":null,"object_type":"limitation"}; raw references [].
  Role binding: null.

> Canonical timestamps follow TimeCreated; Sysmon UtcTime differs by about four hours and its timezone is unresolved.

- `chunk:retrieval-chunk--7c3e4f2632332dda121602b7919f6c7f5c6310e4347a0d24a0a9e1c823c4f030` (supplementary), field `/content`, context `/final_items/39/payload/content`, source `/summary/limitations/6`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/summary/limitations/6","object_id":null,"object_type":"limitation"}; raw references [].
  Role binding: null.

> The file also contains conhost creation, event-log clearing and temporary-file deletion telemetry outside this two-group core. These must not be described as globally absent or automatically classified as a destructive payload.

Giới hạn:

- Trace được đối chiếu với final_items thực tế; runtime support không thay thế approved label hoặc rubric ngoài.
- Thiếu evidence chỉ mô tả context đã kiểm tra; không chứng minh hành vi vắng mặt trên toàn hệ thống.
- analysis_status mô tả tình trạng phân tích của artifact; human approval không xác nhận kết luận an ninh.
- Limitation prose hỗ trợ câu hỏi về giới hạn, không chứng minh một positive behavior khác.


## `rd-vi-initial-relation-provenance` (vi)

Nguồn log và raw record references nào hỗ trợ quan hệ cmd.exe tạo mshta.exe?

Approved label: **proceed**; category `relevant_direct`. Đây là đối chiếu ngoài runtime; không thay đổi nhãn.

| Arm | Decision | Parser | Support | Rubric context sufficient | Reasons |
| --- | --- | --- | --- | --- | --- |
| E0 | abstain | supported | supported | True | legacy_quality_gate_abstained |
| E1 | abstain | supported | supported | True | legacy_quality_gate_abstained |
| E2 | proceed | supported | supported | True | — |
| E3 | proceed | supported | supported | True | — |
| E4 | proceed | supported | supported | True | — |

Nhóm thay đổi: abstain_to_proceed.

### E2: abstain->proceed

Legacy decision: `abstain`; scope `unspecified`. Final context: 39 items, 0 supplementary. Approved-label outcome: **TP**.

Rubric AI ngoài runtime: {"context_sufficiency_basis":"all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation","context_sufficient":true,"expected_evidence_ids":["evidence-b07a5ff4763e629715e6"],"missing_answer_units":[],"missing_evidence_diagnostics":[],"returned_evidence_ids":["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"],"satisfied_answer_units":["initial_observations"]}. Rubric này còn giới hạn exact text/semantic unknown và không phải independent validation.

Requirement `r1` — `process_relationship`: `{"chain":false,"child":"mshta.exe","parent":"cmd.exe"}`; support `supported`.

Requirements v1 không có source spans; không tạo trace ngôn ngữ giả cho E0/E2.

Trace ràng buộc parent và child đúng chiều, có instance identities và source references của process creation.

Completeness/contradiction guards: {"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"status":"supported"}.

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/ParentImage`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/ParentImage`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"mshta.exe","object_identity":"{39e4a257-2d77-5f91-6b13-000000000700}","subject":"cmd.exe","subject_identity":"{39e4a257-2d59-5f91-6813-000000000700}"}.

> C:\Windows\System32\cmd.exe

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/Image`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/Image`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"mshta.exe","object_identity":"{39e4a257-2d77-5f91-6b13-000000000700}","subject":"cmd.exe","subject_identity":"{39e4a257-2d59-5f91-6813-000000000700}"}.

> C:\Windows\System32\mshta.exe

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/ParentProcessGuid`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/ParentProcessGuid`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"mshta.exe","object_identity":"{39e4a257-2d77-5f91-6b13-000000000700}","subject":"cmd.exe","subject_identity":"{39e4a257-2d59-5f91-6813-000000000700}"}.

> {39e4a257-2d59-5f91-6813-000000000700}

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/ProcessGuid`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/ProcessGuid`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"mshta.exe","object_identity":"{39e4a257-2d77-5f91-6b13-000000000700}","subject":"cmd.exe","subject_identity":"{39e4a257-2d59-5f91-6813-000000000700}"}.

> {39e4a257-2d77-5f91-6b13-000000000700}

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/source_file`, context `/final_items/6/payload/attributes/attributes/source_observations/0/source_file`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/raw_record_ref`, context `/final_items/6/payload/attributes/attributes/source_observations/0/raw_record_ref`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> jsonl:line:275

Giới hạn:

- Trace được đối chiếu với final_items thực tế; runtime support không thay thế approved label hoặc rubric ngoài.
- Thiếu evidence chỉ mô tả context đã kiểm tra; không chứng minh hành vi vắng mặt trên toàn hệ thống.
- Parent-child creation không chứng minh completion, payload intent hoặc hành vi network.

Requirement `r2` — `evidence_provenance`: `{"process":null}`; support `supported`.

Requirements v1 không có source spans; không tạo trace ngôn ngữ giả cho E0/E2.

Các trường/source observation thực sự được trả về gắn event/provider/timestamp với source file và raw record reference.

Completeness/contradiction guards: {"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"status":"supported"}.

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/Image`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/Image`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> C:\Windows\System32\mshta.exe

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/SourceName`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/SourceName`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> Microsoft-Windows-Sysmon

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/Channel`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/Channel`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> Microsoft-Windows-Sysmon/Operational

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/EventID`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/EventID`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> 1

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/TimeCreated`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/TimeCreated`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> 2020-10-22T02:57:59.857Z

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/source_file`, context `/final_items/6/payload/attributes/attributes/source_observations/0/source_file`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/raw_record_ref`, context `/final_items/6/payload/attributes/attributes/source_observations/0/raw_record_ref`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> jsonl:line:275

Giới hạn:

- Trace được đối chiếu với final_items thực tế; runtime support không thay thế approved label hoặc rubric ngoài.
- Thiếu evidence chỉ mô tả context đã kiểm tra; không chứng minh hành vi vắng mặt trên toàn hệ thống.
- Không tự sửa xung đột TimeCreated/UtcTime hoặc suy timezone chưa được nguồn xác minh.

### E3: abstain->proceed

Legacy decision: `abstain`; scope `unspecified`. Final context: 39 items, 0 supplementary. Approved-label outcome: **TP**.

Rubric AI ngoài runtime: {"context_sufficiency_basis":"all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation","context_sufficient":true,"expected_evidence_ids":["evidence-b07a5ff4763e629715e6"],"missing_answer_units":[],"missing_evidence_diagnostics":[],"returned_evidence_ids":["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"],"satisfied_answer_units":["initial_observations"]}. Rubric này còn giới hạn exact text/semantic unknown và không phải independent validation.

Requirement `r1` — `process_relationship`: `{"chain":false,"child":"mshta.exe","parent":"cmd.exe"}`; support `supported`.

Parser source spans (exact original query offsets/text):

- {"clause_id":"c1","end":75,"role":"request","start":0,"text":"Nguồn log và raw record references nào hỗ trợ quan hệ cmd.exe tạo mshta.exe"}
- {"clause_id":"c1","end":61,"role":"parent","start":54,"text":"cmd.exe"}
- {"clause_id":"c1","end":75,"role":"child","start":66,"text":"mshta.exe"}
- {"clause_id":"c1","end":53,"role":"action","start":46,"text":"quan hệ"}

Trace ràng buộc parent và child đúng chiều, có instance identities và source references của process creation.

Completeness/contradiction guards: {"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"status":"supported"}.

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/ParentImage`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/ParentImage`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"mshta.exe","object_identity":"{39e4a257-2d77-5f91-6b13-000000000700}","subject":"cmd.exe","subject_identity":"{39e4a257-2d59-5f91-6813-000000000700}"}.

> C:\Windows\System32\cmd.exe

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/Image`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/Image`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"mshta.exe","object_identity":"{39e4a257-2d77-5f91-6b13-000000000700}","subject":"cmd.exe","subject_identity":"{39e4a257-2d59-5f91-6813-000000000700}"}.

> C:\Windows\System32\mshta.exe

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/ParentProcessGuid`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/ParentProcessGuid`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"mshta.exe","object_identity":"{39e4a257-2d77-5f91-6b13-000000000700}","subject":"cmd.exe","subject_identity":"{39e4a257-2d59-5f91-6813-000000000700}"}.

> {39e4a257-2d59-5f91-6813-000000000700}

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/ProcessGuid`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/ProcessGuid`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"mshta.exe","object_identity":"{39e4a257-2d77-5f91-6b13-000000000700}","subject":"cmd.exe","subject_identity":"{39e4a257-2d59-5f91-6813-000000000700}"}.

> {39e4a257-2d77-5f91-6b13-000000000700}

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/source_file`, context `/final_items/6/payload/attributes/attributes/source_observations/0/source_file`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/raw_record_ref`, context `/final_items/6/payload/attributes/attributes/source_observations/0/raw_record_ref`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> jsonl:line:275

Giới hạn:

- Trace được đối chiếu với final_items thực tế; runtime support không thay thế approved label hoặc rubric ngoài.
- Thiếu evidence chỉ mô tả context đã kiểm tra; không chứng minh hành vi vắng mặt trên toàn hệ thống.
- Parent-child creation không chứng minh completion, payload intent hoặc hành vi network.

Requirement `r2` — `evidence_provenance`: `{"process":"mshta.exe"}`; support `supported`.

Parser source spans (exact original query offsets/text):

- {"clause_id":"c1","end":75,"role":"request","start":0,"text":"Nguồn log và raw record references nào hỗ trợ quan hệ cmd.exe tạo mshta.exe"}
- {"clause_id":"c1","end":75,"role":"subject","start":66,"text":"mshta.exe"}
- {"clause_id":"c1","end":5,"role":"action","start":0,"text":"Nguồn"}

Các trường/source observation thực sự được trả về gắn event/provider/timestamp với source file và raw record reference.

Completeness/contradiction guards: {"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"status":"supported"}.

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/Image`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/Image`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> C:\Windows\System32\mshta.exe

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/SourceName`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/SourceName`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> Microsoft-Windows-Sysmon

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/Channel`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/Channel`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> Microsoft-Windows-Sysmon/Operational

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/EventID`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/EventID`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> 1

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/TimeCreated`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/TimeCreated`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> 2020-10-22T02:57:59.857Z

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/source_file`, context `/final_items/6/payload/attributes/attributes/source_observations/0/source_file`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/raw_record_ref`, context `/final_items/6/payload/attributes/attributes/source_observations/0/raw_record_ref`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> jsonl:line:275

Giới hạn:

- Trace được đối chiếu với final_items thực tế; runtime support không thay thế approved label hoặc rubric ngoài.
- Thiếu evidence chỉ mô tả context đã kiểm tra; không chứng minh hành vi vắng mặt trên toàn hệ thống.
- Không tự sửa xung đột TimeCreated/UtcTime hoặc suy timezone chưa được nguồn xác minh.

### E4: abstain->proceed

Legacy decision: `abstain`; scope `unspecified`. Final context: 39 items, 0 supplementary. Approved-label outcome: **TP**.

Rubric AI ngoài runtime: {"context_sufficiency_basis":"all_required_units_passed_conservative_ai_rubric_not_human_approved_semantic_evaluation","context_sufficient":true,"expected_evidence_ids":["evidence-b07a5ff4763e629715e6"],"missing_answer_units":[],"missing_evidence_diagnostics":[],"returned_evidence_ids":["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"],"satisfied_answer_units":["initial_observations"]}. Rubric này còn giới hạn exact text/semantic unknown và không phải independent validation.

Requirement `r1` — `process_relationship`: `{"chain":false,"child":"mshta.exe","parent":"cmd.exe"}`; support `supported`.

Parser source spans (exact original query offsets/text):

- {"clause_id":"c1","end":75,"role":"request","start":0,"text":"Nguồn log và raw record references nào hỗ trợ quan hệ cmd.exe tạo mshta.exe"}
- {"clause_id":"c1","end":61,"role":"parent","start":54,"text":"cmd.exe"}
- {"clause_id":"c1","end":75,"role":"child","start":66,"text":"mshta.exe"}
- {"clause_id":"c1","end":53,"role":"action","start":46,"text":"quan hệ"}

Trace ràng buộc parent và child đúng chiều, có instance identities và source references của process creation.

Completeness/contradiction guards: {"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"status":"supported"}.

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/ParentImage`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/ParentImage`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"mshta.exe","object_identity":"{39e4a257-2d77-5f91-6b13-000000000700}","subject":"cmd.exe","subject_identity":"{39e4a257-2d59-5f91-6813-000000000700}"}.

> C:\Windows\System32\cmd.exe

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/Image`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/Image`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"mshta.exe","object_identity":"{39e4a257-2d77-5f91-6b13-000000000700}","subject":"cmd.exe","subject_identity":"{39e4a257-2d59-5f91-6813-000000000700}"}.

> C:\Windows\System32\mshta.exe

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/ParentProcessGuid`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/ParentProcessGuid`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"mshta.exe","object_identity":"{39e4a257-2d77-5f91-6b13-000000000700}","subject":"cmd.exe","subject_identity":"{39e4a257-2d59-5f91-6813-000000000700}"}.

> {39e4a257-2d59-5f91-6813-000000000700}

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/ProcessGuid`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/ProcessGuid`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"process_spawn","object":"mshta.exe","object_identity":"{39e4a257-2d77-5f91-6b13-000000000700}","subject":"cmd.exe","subject_identity":"{39e4a257-2d59-5f91-6813-000000000700}"}.

> {39e4a257-2d77-5f91-6b13-000000000700}

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/source_file`, context `/final_items/6/payload/attributes/attributes/source_observations/0/source_file`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/raw_record_ref`, context `/final_items/6/payload/attributes/attributes/source_observations/0/raw_record_ref`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> jsonl:line:275

Giới hạn:

- Trace được đối chiếu với final_items thực tế; runtime support không thay thế approved label hoặc rubric ngoài.
- Thiếu evidence chỉ mô tả context đã kiểm tra; không chứng minh hành vi vắng mặt trên toàn hệ thống.
- Parent-child creation không chứng minh completion, payload intent hoặc hành vi network.

Requirement `r2` — `evidence_provenance`: `{"process":"mshta.exe"}`; support `supported`.

Parser source spans (exact original query offsets/text):

- {"clause_id":"c1","end":75,"role":"request","start":0,"text":"Nguồn log và raw record references nào hỗ trợ quan hệ cmd.exe tạo mshta.exe"}
- {"clause_id":"c1","end":75,"role":"subject","start":66,"text":"mshta.exe"}
- {"clause_id":"c1","end":5,"role":"action","start":0,"text":"Nguồn"}

Các trường/source observation thực sự được trả về gắn event/provider/timestamp với source file và raw record reference.

Completeness/contradiction guards: {"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"status":"supported"}.

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/Image`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/Image`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> C:\Windows\System32\mshta.exe

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/SourceName`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/SourceName`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> Microsoft-Windows-Sysmon

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/Channel`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/Channel`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> Microsoft-Windows-Sysmon/Operational

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/EventID`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/EventID`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> 1

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/original_fields/TimeCreated`, context `/final_items/6/payload/attributes/attributes/source_observations/0/original_fields/TimeCreated`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> 2020-10-22T02:57:59.857Z

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/source_file`, context `/final_items/6/payload/attributes/attributes/source_observations/0/source_file`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json

- `node:graph-node--20d644848d2ad2423f8b8b2c687bc68437fbba3297d473e4757483e5c72c0540` (traversal), field `/attributes/attributes/source_observations/0/raw_record_ref`, context `/final_items/6/payload/attributes/attributes/source_observations/0/raw_record_ref`, source `/facts/0`.
  Source binding: {"json_pointer":"/facts/0","object_id":"fact-cmd-spawns-mshta","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:275","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:4","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> jsonl:line:275

Giới hạn:

- Trace được đối chiếu với final_items thực tế; runtime support không thay thế approved label hoặc rubric ngoài.
- Thiếu evidence chỉ mô tả context đã kiểm tra; không chứng minh hành vi vắng mặt trên toàn hệ thống.
- Không tự sửa xung đột TimeCreated/UtcTime hoặc suy timezone chưa được nguồn xác minh.


## `rp-vi-service-action` (vi)

Lệnh liên quan đến dịch vụ được ghi nhận trên command line khi PowerShell được khởi chạy là gì?

Approved label: **proceed**; category `relevant_paraphrase`. Đây là đối chiếu ngoài runtime; không thay đổi nhãn.

| Arm | Decision | Parser | Support | Rubric context sufficient | Reasons |
| --- | --- | --- | --- | --- | --- |
| E0 | abstain | supported | supported | None | legacy_quality_gate_abstained |
| E1 | abstain | supported | supported | None | legacy_quality_gate_abstained |
| E2 | proceed | supported | supported | None | — |
| E3 | proceed | supported | supported | None | — |
| E4 | proceed | supported | supported | None | — |

Nhóm thay đổi: abstain_to_proceed.

### E2: abstain->proceed

Legacy decision: `abstain`; scope `unspecified`. Final context: 39 items, 0 supplementary. Approved-label outcome: **TP**.

Rubric AI ngoài runtime: {"context_sufficiency_basis":"semantic_context_sufficiency_unassessed_conservative_screen_incomplete","context_sufficient":null,"expected_evidence_ids":["evidence-b31714b888d1489a380c"],"missing_answer_units":["limitation_4"],"missing_evidence_diagnostics":[{"answer_unit_id":"limitation_4","reason":"no_exact_limitation_support_semantic_sufficiency_not_established","source_ground_truth_pointer":"/summary/limitations/4","support_status":"unassessed"}],"returned_evidence_ids":["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"],"satisfied_answer_units":["launch_command"]}. Rubric này còn giới hạn exact text/semantic unknown và không phải independent validation.

Requirement `r1` — `launch_command`: `{"process":"powershell.exe"}`; support `supported`.

Requirements v1 không có source spans; không tạo trace ngôn ngữ giả cho E0/E2.

Original CommandLine được trích từ process-creation observation gắn với process được hỏi và instance identity.

Completeness/contradiction guards: {"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"status":"supported"}.

- `chunk:retrieval-chunk--135ad46ae0c56b905d31ab531d5d565a01412b61f3600ad6b4d9dda6e2eef860` (ranked), field `/metadata/attributes/source_observations/0/original_fields/NewProcessName`, context `/final_items/1/payload/metadata/attributes/source_observations/0/original_fields/NewProcessName`, source `/facts/1`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"launched_with_command_line","object":"\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -noexit -command Get-Service sysmon","subject":"powershell.exe","subject_identity":"0x2564"}.

> C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

- `chunk:retrieval-chunk--135ad46ae0c56b905d31ab531d5d565a01412b61f3600ad6b4d9dda6e2eef860` (ranked), field `/metadata/attributes/source_observations/0/original_fields/NewProcessId`, context `/final_items/1/payload/metadata/attributes/source_observations/0/original_fields/NewProcessId`, source `/facts/1`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"launched_with_command_line","object":"\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -noexit -command Get-Service sysmon","subject":"powershell.exe","subject_identity":"0x2564"}.

> 0x2564

- `chunk:retrieval-chunk--135ad46ae0c56b905d31ab531d5d565a01412b61f3600ad6b4d9dda6e2eef860` (ranked), field `/metadata/attributes/source_observations/0/original_fields/CommandLine`, context `/final_items/1/payload/metadata/attributes/source_observations/0/original_fields/CommandLine`, source `/facts/1`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"launched_with_command_line","object":"\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -noexit -command Get-Service sysmon","subject":"powershell.exe","subject_identity":"0x2564"}.

> "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -noexit -command Get-Service sysmon

- `chunk:retrieval-chunk--135ad46ae0c56b905d31ab531d5d565a01412b61f3600ad6b4d9dda6e2eef860` (ranked), field `/metadata/attributes/source_observations/0/source_file`, context `/final_items/1/payload/metadata/attributes/source_observations/0/source_file`, source `/facts/1`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json

- `chunk:retrieval-chunk--135ad46ae0c56b905d31ab531d5d565a01412b61f3600ad6b4d9dda6e2eef860` (ranked), field `/metadata/attributes/source_observations/0/raw_record_ref`, context `/final_items/1/payload/metadata/attributes/source_observations/0/raw_record_ref`, source `/facts/1`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> jsonl:line:30

Giới hạn:

- Trace được đối chiếu với final_items thực tế; runtime support không thay thế approved label hoặc rubric ngoài.
- Thiếu evidence chỉ mô tả context đã kiểm tra; không chứng minh hành vi vắng mặt trên toàn hệ thống.
- Chỉ xác nhận command line khi launch; không xác nhận cmdlet hoàn tất, output hoặc service state.

### E3: abstain->proceed

Legacy decision: `abstain`; scope `unspecified`. Final context: 39 items, 0 supplementary. Approved-label outcome: **TP**.

Rubric AI ngoài runtime: {"context_sufficiency_basis":"semantic_context_sufficiency_unassessed_conservative_screen_incomplete","context_sufficient":null,"expected_evidence_ids":["evidence-b31714b888d1489a380c"],"missing_answer_units":["limitation_4"],"missing_evidence_diagnostics":[{"answer_unit_id":"limitation_4","reason":"no_exact_limitation_support_semantic_sufficiency_not_established","source_ground_truth_pointer":"/summary/limitations/4","support_status":"unassessed"}],"returned_evidence_ids":["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"],"satisfied_answer_units":["launch_command"]}. Rubric này còn giới hạn exact text/semantic unknown và không phải independent validation.

Requirement `r1` — `launch_command`: `{"process":"powershell.exe"}`; support `supported`.

Parser source spans (exact original query offsets/text):

- {"clause_id":"c1","end":94,"role":"request","start":0,"text":"Lệnh liên quan đến dịch vụ được ghi nhận trên command line khi PowerShell được khởi chạy là gì"}
- {"clause_id":"c1","end":73,"role":"subject","start":63,"text":"PowerShell"}
- {"clause_id":"c1","end":58,"role":"action","start":46,"text":"command line"}
- {"clause_id":"c1","end":58,"role":"requested_field","start":46,"text":"command line"}

Original CommandLine được trích từ process-creation observation gắn với process được hỏi và instance identity.

Completeness/contradiction guards: {"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"status":"supported"}.

- `chunk:retrieval-chunk--135ad46ae0c56b905d31ab531d5d565a01412b61f3600ad6b4d9dda6e2eef860` (ranked), field `/metadata/attributes/source_observations/0/original_fields/NewProcessName`, context `/final_items/1/payload/metadata/attributes/source_observations/0/original_fields/NewProcessName`, source `/facts/1`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"launched_with_command_line","object":"\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -noexit -command Get-Service sysmon","subject":"powershell.exe","subject_identity":"0x2564"}.

> C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

- `chunk:retrieval-chunk--135ad46ae0c56b905d31ab531d5d565a01412b61f3600ad6b4d9dda6e2eef860` (ranked), field `/metadata/attributes/source_observations/0/original_fields/NewProcessId`, context `/final_items/1/payload/metadata/attributes/source_observations/0/original_fields/NewProcessId`, source `/facts/1`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"launched_with_command_line","object":"\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -noexit -command Get-Service sysmon","subject":"powershell.exe","subject_identity":"0x2564"}.

> 0x2564

- `chunk:retrieval-chunk--135ad46ae0c56b905d31ab531d5d565a01412b61f3600ad6b4d9dda6e2eef860` (ranked), field `/metadata/attributes/source_observations/0/original_fields/CommandLine`, context `/final_items/1/payload/metadata/attributes/source_observations/0/original_fields/CommandLine`, source `/facts/1`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"launched_with_command_line","object":"\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -noexit -command Get-Service sysmon","subject":"powershell.exe","subject_identity":"0x2564"}.

> "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -noexit -command Get-Service sysmon

- `chunk:retrieval-chunk--135ad46ae0c56b905d31ab531d5d565a01412b61f3600ad6b4d9dda6e2eef860` (ranked), field `/metadata/attributes/source_observations/0/source_file`, context `/final_items/1/payload/metadata/attributes/source_observations/0/source_file`, source `/facts/1`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json

- `chunk:retrieval-chunk--135ad46ae0c56b905d31ab531d5d565a01412b61f3600ad6b4d9dda6e2eef860` (ranked), field `/metadata/attributes/source_observations/0/raw_record_ref`, context `/final_items/1/payload/metadata/attributes/source_observations/0/raw_record_ref`, source `/facts/1`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> jsonl:line:30

Giới hạn:

- Trace được đối chiếu với final_items thực tế; runtime support không thay thế approved label hoặc rubric ngoài.
- Thiếu evidence chỉ mô tả context đã kiểm tra; không chứng minh hành vi vắng mặt trên toàn hệ thống.
- Chỉ xác nhận command line khi launch; không xác nhận cmdlet hoàn tất, output hoặc service state.

### E4: abstain->proceed

Legacy decision: `abstain`; scope `unspecified`. Final context: 39 items, 0 supplementary. Approved-label outcome: **TP**.

Rubric AI ngoài runtime: {"context_sufficiency_basis":"semantic_context_sufficiency_unassessed_conservative_screen_incomplete","context_sufficient":null,"expected_evidence_ids":["evidence-b31714b888d1489a380c"],"missing_answer_units":["limitation_4"],"missing_evidence_diagnostics":[{"answer_unit_id":"limitation_4","reason":"no_exact_limitation_support_semantic_sufficiency_not_established","source_ground_truth_pointer":"/summary/limitations/4","support_status":"unassessed"}],"returned_evidence_ids":["evidence-b07a5ff4763e629715e6","evidence-b31714b888d1489a380c"],"satisfied_answer_units":["launch_command"]}. Rubric này còn giới hạn exact text/semantic unknown và không phải independent validation.

Requirement `r1` — `launch_command`: `{"process":"powershell.exe"}`; support `supported`.

Parser source spans (exact original query offsets/text):

- {"clause_id":"c1","end":94,"role":"request","start":0,"text":"Lệnh liên quan đến dịch vụ được ghi nhận trên command line khi PowerShell được khởi chạy là gì"}
- {"clause_id":"c1","end":73,"role":"subject","start":63,"text":"PowerShell"}
- {"clause_id":"c1","end":58,"role":"action","start":46,"text":"command line"}
- {"clause_id":"c1","end":58,"role":"requested_field","start":46,"text":"command line"}

Original CommandLine được trích từ process-creation observation gắn với process được hỏi và instance identity.

Completeness/contradiction guards: {"completeness":{"reason_codes":[],"status":"not_applicable"},"contradiction":{"reason_codes":[],"status":"none_detected"},"status":"supported"}.

- `chunk:retrieval-chunk--135ad46ae0c56b905d31ab531d5d565a01412b61f3600ad6b4d9dda6e2eef860` (ranked), field `/metadata/attributes/source_observations/0/original_fields/NewProcessName`, context `/final_items/1/payload/metadata/attributes/source_observations/0/original_fields/NewProcessName`, source `/facts/1`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"launched_with_command_line","object":"\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -noexit -command Get-Service sysmon","subject":"powershell.exe","subject_identity":"0x2564"}.

> C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

- `chunk:retrieval-chunk--135ad46ae0c56b905d31ab531d5d565a01412b61f3600ad6b4d9dda6e2eef860` (ranked), field `/metadata/attributes/source_observations/0/original_fields/NewProcessId`, context `/final_items/1/payload/metadata/attributes/source_observations/0/original_fields/NewProcessId`, source `/facts/1`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"launched_with_command_line","object":"\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -noexit -command Get-Service sysmon","subject":"powershell.exe","subject_identity":"0x2564"}.

> 0x2564

- `chunk:retrieval-chunk--135ad46ae0c56b905d31ab531d5d565a01412b61f3600ad6b4d9dda6e2eef860` (ranked), field `/metadata/attributes/source_observations/0/original_fields/CommandLine`, context `/final_items/1/payload/metadata/attributes/source_observations/0/original_fields/CommandLine`, source `/facts/1`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: {"action":"launched_with_command_line","object":"\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -noexit -command Get-Service sysmon","subject":"powershell.exe","subject_identity":"0x2564"}.

> "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -noexit -command Get-Service sysmon

- `chunk:retrieval-chunk--135ad46ae0c56b905d31ab531d5d565a01412b61f3600ad6b4d9dda6e2eef860` (ranked), field `/metadata/attributes/source_observations/0/source_file`, context `/final_items/1/payload/metadata/attributes/source_observations/0/source_file`, source `/facts/1`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json

- `chunk:retrieval-chunk--135ad46ae0c56b905d31ab531d5d565a01412b61f3600ad6b4d9dda6e2eef860` (ranked), field `/metadata/attributes/source_observations/0/raw_record_ref`, context `/final_items/1/payload/metadata/attributes/source_observations/0/raw_record_ref`, source `/facts/1`.
  Source binding: {"artifact_type":"scenario_ground_truth","json_pointer":"/facts/1","object_id":"fact-mshta-spawns-powershell","object_type":"fact"}; raw references [{"raw_record_ref":"jsonl:line:30","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"},{"raw_record_ref":"jsonl:line:398","source_file":"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"}].
  Role binding: null.

> jsonl:line:30

Giới hạn:

- Trace được đối chiếu với final_items thực tế; runtime support không thay thế approved label hoặc rubric ngoài.
- Thiếu evidence chỉ mô tả context đã kiểm tra; không chứng minh hành vi vắng mặt trên toàn hệ thống.
- Chỉ xác nhận command line khi launch; không xác nhận cmdlet hoàn tất, output hoặc service state.

