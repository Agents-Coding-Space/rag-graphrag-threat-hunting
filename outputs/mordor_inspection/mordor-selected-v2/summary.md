# Structural inspection summary: mordor-selected-v2

> Đây mới là structural inspection, chưa phải phát hiện tấn công, evidence extraction hoặc ground truth.

## Inputs

| Input | Format | Expected | Actual | Baseline | SHA-256 | Time range based on @timestamp | Distinct field paths |
| --- | --- | ---: | ---: | --- | --- | --- | ---: |
| purplesharp_ad_playbook_I_2020-10-22042947.json | jsonl | 25993 | 25993 | match | d86d22f0c02ab851564bb5e0c90c220e9df0319f5948bfc90dfa605b4511d4f0 | 2020-10-22T08:29:48.785000Z → 2020-10-22T08:30:42.832000Z | 195 |
| empire_launcher_sct_regsvr32_2020-07-21232741.json | jsonl | 2390 | 2390 | match | 8b619d07ad79713ae96234344c4ba9618eae7119c360ee008b5e0c2cfe4954d7 | 2020-07-22T03:27:42.455000Z → 2020-07-22T03:28:33.535000Z | 163 |
| cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json | jsonl | 1127 | 1127 | match | 25aa24b5f631f19ac23f64db116c23e632295fb5f59040e966fa47e7758b2a32 | 2020-10-22T02:57:55.601000Z → 2020-10-22T02:58:08.695000Z | 100 |

Coverage trong bảng input được tính trên toàn file. Coverage thấp của `CommandLine`, `ParentImage` hoặc field theo Event ID không có nghĩa field đó không hữu ích trong đúng structural context.

Event ID dưới đây chỉ là context để hiểu schema; không phải kết luận event hoặc dataset là tấn công.

Timestamp conflict là cảnh báo về các timestamp candidates không nhất quán; không đồng nghĩa record hoặc dataset invalid.

## Per-input highlights

### purplesharp_ad_playbook_I_2020-10-22042947.json

- Chi tiết đầy đủ: `files/purplesharp_ad_playbook_i_2020_10_22042947--d86d22f0c02a/inspection.json`
- Event ID phổ biến: `12` (17917), `7` (1537), `13` (1135), `4658` (761), `11` (629)
- Provider phổ biến: `Microsoft-Windows-Sysmon` (22054), `Microsoft-Windows-Security-Auditing` (2843), `Microsoft-Windows-PowerShell` (747), `PowerShell` (342), `Microsoft-Windows-WMI-Activity` (4)
- Security-relevant structural contexts: Security 4625 (7), Security 4776 (7), Security 4769 (17), Sysmon 1 (24), Security 4688 (24), Sysmon 3 (126), Security 5156 (197), Sysmon 10 (344), Sysmon 12 (17917), Sysmon 13 (1135), Sysmon 22 (13)

| Candidate canonical field | Status | Source candidates (context coverage) |
| --- | --- | --- |
| `timestamp` | ambiguous | `/@timestamp` [Microsoft-Windows-Security-Auditing / Event ID 4625] (100.0% context coverage), `/EventTime` [Microsoft-Windows-Security-Auditing / Event ID 4625] (100.0% context coverage), `/@timestamp` [Microsoft-Windows-Security-Auditing / Event ID 4688] (100.0% context coverage) |
| `host` | candidate | `/Hostname` [Microsoft-Windows-Security-Auditing / Event ID 4625] (100.0% context coverage), `/Hostname` [Microsoft-Windows-Security-Auditing / Event ID 4688] (100.0% context coverage), `/Hostname` [Microsoft-Windows-Security-Auditing / Event ID 4769] (100.0% context coverage) |
| `user` | candidate | `/User` [Microsoft-Windows-Sysmon / Event ID 1] (100.0% context coverage), `/User` [Microsoft-Windows-Sysmon / Event ID 3] (100.0% context coverage) |
| `subject_user` | candidate | `/SubjectUserName` [Microsoft-Windows-Security-Auditing / Event ID 4625] (100.0% context coverage), `/SubjectUserName` [Microsoft-Windows-Security-Auditing / Event ID 4688] (100.0% context coverage) |
| `target_user` | candidate | `/TargetUserName` [Microsoft-Windows-Security-Auditing / Event ID 4625] (100.0% context coverage), `/TargetUserName` [Microsoft-Windows-Security-Auditing / Event ID 4769] (100.0% context coverage), `/TargetUserName` [Microsoft-Windows-Security-Auditing / Event ID 4776] (100.0% context coverage) |
| `process_name` | candidate | `/ProcessName` [Microsoft-Windows-Security-Auditing / Event ID 4625] (100.0% context coverage), `/NewProcessName` [Microsoft-Windows-Security-Auditing / Event ID 4688] (100.0% context coverage), `/Image` [Microsoft-Windows-Sysmon / Event ID 1] (100.0% context coverage) |
| `parent_process_name` | candidate | `/ParentProcessName` [Microsoft-Windows-Security-Auditing / Event ID 4688] (100.0% context coverage), `/ParentImage` [Microsoft-Windows-Sysmon / Event ID 1] (100.0% context coverage) |
| `process_id` | candidate | `/NewProcessId` [Microsoft-Windows-Security-Auditing / Event ID 4688] (100.0% context coverage), `/ProcessId` [Microsoft-Windows-Sysmon / Event ID 1] (100.0% context coverage), `/ProcessId` [Microsoft-Windows-Sysmon / Event ID 12] (100.0% context coverage) |
| `parent_process_id` | candidate | `/ProcessId` [Microsoft-Windows-Security-Auditing / Event ID 4688] (100.0% context coverage), `/ParentProcessId` [Microsoft-Windows-Sysmon / Event ID 1] (100.0% context coverage) |
| `process_guid` | candidate | `/ProcessGuid` [Microsoft-Windows-Sysmon / Event ID 1] (100.0% context coverage), `/ProcessGuid` [Microsoft-Windows-Sysmon / Event ID 12] (100.0% context coverage), `/ProcessGuid` [Microsoft-Windows-Sysmon / Event ID 13] (100.0% context coverage) |
| `parent_process_guid` | candidate | `/ParentProcessGuid` [Microsoft-Windows-Sysmon / Event ID 1] (100.0% context coverage) |
| `command_line` | candidate | `/CommandLine` [Microsoft-Windows-Security-Auditing / Event ID 4688] (100.0% context coverage), `/CommandLine` [Microsoft-Windows-Sysmon / Event ID 1] (100.0% context coverage) |
| `parent_command_line` | candidate | `/ParentCommandLine` [Microsoft-Windows-Sysmon / Event ID 1] (100.0% context coverage) |
| `source_ip` | candidate | `/IpAddress` [Microsoft-Windows-Security-Auditing / Event ID 4769] (100.0% context coverage), `/SourceAddress` [Microsoft-Windows-Security-Auditing / Event ID 5156] (100.0% context coverage), `/SourceIp` [Microsoft-Windows-Sysmon / Event ID 3] (100.0% context coverage) |
| `destination_ip` | candidate | `/DestAddress` [Microsoft-Windows-Security-Auditing / Event ID 5156] (100.0% context coverage), `/DestinationIp` [Microsoft-Windows-Sysmon / Event ID 3] (100.0% context coverage) |
| `destination_port` | candidate | `/DestPort` [Microsoft-Windows-Security-Auditing / Event ID 5156] (100.0% context coverage), `/DestinationPort` [Microsoft-Windows-Sysmon / Event ID 3] (100.0% context coverage) |

Context-specific/unmapped process roles: `/SourceImage` (source_process_image), `/SourceProcessId` (source_process_id), `/SourceProcessGUID` (source_process_guid), `/TargetImage` (target_process_image), `/TargetProcessId` (target_process_id), `/TargetProcessGUID` (target_process_guid).

Warnings:
- Timestamp candidates differ by more than 60 seconds in 25993 records; timezone-naive values were compared only as wall-clock text and were not assumed to be UTC.
- Observed 48675 timezone-naive timestamp values. Their timezone semantics remain unresolved; no UTC timezone was assigned.
- UtcTime was observed but remains review-only until its timezone semantics are confirmed; it was not selected as an event occurrence timestamp.
- CreationUtcTime was observed as creation metadata and was excluded from event occurrence timestamp selection.
- Canonical integer port fields require validated string-to-integer transformation for observed source strings: source_port, destination_port. No transformation was applied during inspection.
- ProcessId changes semantic role by context: it is process_id in Sysmon Event ID 1 but parent_process_id in Security Event ID 4688.
- AccountName is not automatically mapped to target_user because its role varies across providers and Event IDs.
- Sysmon Event ID 10 SourceImage/TargetImage and related identifiers use source/target process roles. canonical-event/v2 does not force them into process_name or parent_process_name.
- Multiple context-aware candidates remain reviewable for: timestamp.

### empire_launcher_sct_regsvr32_2020-07-21232741.json

- Chi tiết đầy đủ: `files/empire_launcher_sct_regsvr32_2020_07_21232741--8b619d07ad79/inspection.json`
- Event ID phổ biến: `12` (682), `7` (535), `10` (265), `5156` (216), `13` (214)
- Provider phổ biến: `Microsoft-Windows-Sysmon` (1762), `Microsoft-Windows-Security-Auditing` (512), `Microsoft-Windows-PowerShell` (60), `PowerShell` (55), `Microsoft-Windows-WMI-Activity` (1)
- Security-relevant structural contexts: Sysmon 1 (7), Security 4688 (7), Sysmon 3 (25), Security 5156 (216), Sysmon 10 (265), Sysmon 12 (682), Sysmon 13 (214), Sysmon 22 (2)

| Candidate canonical field | Status | Source candidates (context coverage) |
| --- | --- | --- |
| `timestamp` | ambiguous | `/@timestamp` [Microsoft-Windows-Security-Auditing / Event ID 4688] (100.0% context coverage), `/EventTime` [Microsoft-Windows-Security-Auditing / Event ID 4688] (100.0% context coverage), `/@timestamp` [Microsoft-Windows-Security-Auditing / Event ID 5156] (100.0% context coverage) |
| `host` | candidate | `/Hostname` [Microsoft-Windows-Security-Auditing / Event ID 4688] (100.0% context coverage), `/Hostname` [Microsoft-Windows-Security-Auditing / Event ID 5156] (100.0% context coverage), `/Hostname` [Microsoft-Windows-Sysmon / Event ID 1] (100.0% context coverage) |
| `user` | candidate | `/User` [Microsoft-Windows-Sysmon / Event ID 1] (100.0% context coverage), `/User` [Microsoft-Windows-Sysmon / Event ID 3] (100.0% context coverage) |
| `subject_user` | candidate | `/SubjectUserName` [Microsoft-Windows-Security-Auditing / Event ID 4688] (100.0% context coverage) |
| `target_user` | unavailable | — |
| `process_name` | candidate | `/NewProcessName` [Microsoft-Windows-Security-Auditing / Event ID 4688] (100.0% context coverage), `/Image` [Microsoft-Windows-Sysmon / Event ID 1] (100.0% context coverage), `/Image` [Microsoft-Windows-Sysmon / Event ID 12] (100.0% context coverage) |
| `parent_process_name` | candidate | `/ParentProcessName` [Microsoft-Windows-Security-Auditing / Event ID 4688] (100.0% context coverage), `/ParentImage` [Microsoft-Windows-Sysmon / Event ID 1] (100.0% context coverage) |
| `process_id` | candidate | `/NewProcessId` [Microsoft-Windows-Security-Auditing / Event ID 4688] (100.0% context coverage), `/ProcessId` [Microsoft-Windows-Sysmon / Event ID 1] (100.0% context coverage), `/ProcessId` [Microsoft-Windows-Sysmon / Event ID 12] (100.0% context coverage) |
| `parent_process_id` | candidate | `/ProcessId` [Microsoft-Windows-Security-Auditing / Event ID 4688] (100.0% context coverage), `/ParentProcessId` [Microsoft-Windows-Sysmon / Event ID 1] (100.0% context coverage) |
| `process_guid` | candidate | `/ProcessGuid` [Microsoft-Windows-Sysmon / Event ID 1] (100.0% context coverage), `/ProcessGuid` [Microsoft-Windows-Sysmon / Event ID 12] (100.0% context coverage), `/ProcessGuid` [Microsoft-Windows-Sysmon / Event ID 13] (100.0% context coverage) |
| `parent_process_guid` | candidate | `/ParentProcessGuid` [Microsoft-Windows-Sysmon / Event ID 1] (100.0% context coverage) |
| `command_line` | candidate | `/CommandLine` [Microsoft-Windows-Security-Auditing / Event ID 4688] (100.0% context coverage), `/CommandLine` [Microsoft-Windows-Sysmon / Event ID 1] (100.0% context coverage) |
| `parent_command_line` | candidate | `/ParentCommandLine` [Microsoft-Windows-Sysmon / Event ID 1] (100.0% context coverage) |
| `source_ip` | candidate | `/SourceAddress` [Microsoft-Windows-Security-Auditing / Event ID 5156] (100.0% context coverage), `/SourceIp` [Microsoft-Windows-Sysmon / Event ID 3] (100.0% context coverage) |
| `destination_ip` | candidate | `/DestAddress` [Microsoft-Windows-Security-Auditing / Event ID 5156] (100.0% context coverage), `/DestinationIp` [Microsoft-Windows-Sysmon / Event ID 3] (100.0% context coverage) |
| `destination_port` | candidate | `/DestPort` [Microsoft-Windows-Security-Auditing / Event ID 5156] (100.0% context coverage), `/DestinationPort` [Microsoft-Windows-Sysmon / Event ID 3] (100.0% context coverage) |

Context-specific/unmapped process roles: `/SourceImage` (source_process_image), `/SourceProcessId` (source_process_id), `/SourceProcessGUID` (source_process_guid), `/TargetImage` (target_process_image), `/TargetProcessId` (target_process_id), `/TargetProcessGUID` (target_process_guid).

Warnings:
- Timestamp candidates differ by more than 60 seconds in 2390 records; timezone-naive values were compared only as wall-clock text and were not assumed to be UTC.
- Observed 4169 timezone-naive timestamp values. Their timezone semantics remain unresolved; no UTC timezone was assigned.
- UtcTime was observed but remains review-only until its timezone semantics are confirmed; it was not selected as an event occurrence timestamp.
- CreationUtcTime was observed as creation metadata and was excluded from event occurrence timestamp selection.
- Canonical integer port fields require validated string-to-integer transformation for observed source strings: source_port, destination_port. No transformation was applied during inspection.
- ProcessId changes semantic role by context: it is process_id in Sysmon Event ID 1 but parent_process_id in Security Event ID 4688.
- AccountName is not automatically mapped to target_user because its role varies across providers and Event IDs.
- Sysmon Event ID 10 SourceImage/TargetImage and related identifiers use source/target process roles. canonical-event/v2 does not force them into process_name or parent_process_name.
- Multiple context-aware candidates remain reviewable for: timestamp.

### cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json

- Chi tiết đầy đủ: `files/cmd_mshta_vbscript_execute_psh_2020_10_2202580804--25aa24b5f631/inspection.json`
- Event ID phổ biến: `12` (401), `7` (238), `10` (184), `4658` (95), `13` (48)
- Provider phổ biến: `Microsoft-Windows-Sysmon` (892), `Microsoft-Windows-Security-Auditing` (232), `Microsoft-Windows-Eventlog` (3)
- Security-relevant structural contexts: Sysmon 1 (3), Security 4688 (3), Security 5156 (1), Sysmon 10 (184), Sysmon 12 (401), Sysmon 13 (48)

| Candidate canonical field | Status | Source candidates (context coverage) |
| --- | --- | --- |
| `timestamp` | ambiguous | `/@timestamp` [Microsoft-Windows-Security-Auditing / Event ID 4688] (100.0% context coverage), `/TimeCreated` [Microsoft-Windows-Security-Auditing / Event ID 4688] (100.0% context coverage), `/@timestamp` [Microsoft-Windows-Security-Auditing / Event ID 5156] (100.0% context coverage) |
| `host` | candidate | `/Hostname` [Microsoft-Windows-Security-Auditing / Event ID 4688] (100.0% context coverage), `/Hostname` [Microsoft-Windows-Security-Auditing / Event ID 5156] (100.0% context coverage), `/Hostname` [Microsoft-Windows-Sysmon / Event ID 1] (100.0% context coverage) |
| `user` | candidate | `/User` [Microsoft-Windows-Sysmon / Event ID 1] (100.0% context coverage) |
| `subject_user` | candidate | `/SubjectUserName` [Microsoft-Windows-Security-Auditing / Event ID 4688] (100.0% context coverage) |
| `target_user` | unavailable | — |
| `process_name` | candidate | `/NewProcessName` [Microsoft-Windows-Security-Auditing / Event ID 4688] (100.0% context coverage), `/Image` [Microsoft-Windows-Sysmon / Event ID 1] (100.0% context coverage), `/Image` [Microsoft-Windows-Sysmon / Event ID 12] (100.0% context coverage) |
| `parent_process_name` | candidate | `/ParentProcessName` [Microsoft-Windows-Security-Auditing / Event ID 4688] (100.0% context coverage), `/ParentImage` [Microsoft-Windows-Sysmon / Event ID 1] (100.0% context coverage) |
| `process_id` | candidate | `/NewProcessId` [Microsoft-Windows-Security-Auditing / Event ID 4688] (100.0% context coverage), `/ProcessId` [Microsoft-Windows-Sysmon / Event ID 1] (100.0% context coverage), `/ProcessId` [Microsoft-Windows-Sysmon / Event ID 12] (100.0% context coverage) |
| `parent_process_id` | candidate | `/ProcessId` [Microsoft-Windows-Security-Auditing / Event ID 4688] (100.0% context coverage), `/ParentProcessId` [Microsoft-Windows-Sysmon / Event ID 1] (100.0% context coverage) |
| `process_guid` | candidate | `/ProcessGuid` [Microsoft-Windows-Sysmon / Event ID 1] (100.0% context coverage), `/ProcessGuid` [Microsoft-Windows-Sysmon / Event ID 12] (100.0% context coverage), `/ProcessGuid` [Microsoft-Windows-Sysmon / Event ID 13] (100.0% context coverage) |
| `parent_process_guid` | candidate | `/ParentProcessGuid` [Microsoft-Windows-Sysmon / Event ID 1] (100.0% context coverage) |
| `command_line` | candidate | `/CommandLine` [Microsoft-Windows-Security-Auditing / Event ID 4688] (100.0% context coverage), `/CommandLine` [Microsoft-Windows-Sysmon / Event ID 1] (100.0% context coverage) |
| `parent_command_line` | candidate | `/ParentCommandLine` [Microsoft-Windows-Sysmon / Event ID 1] (100.0% context coverage) |
| `source_ip` | candidate | `/SourceAddress` [Microsoft-Windows-Security-Auditing / Event ID 5156] (100.0% context coverage) |
| `destination_ip` | candidate | `/DestAddress` [Microsoft-Windows-Security-Auditing / Event ID 5156] (100.0% context coverage) |
| `destination_port` | candidate | `/DestPort` [Microsoft-Windows-Security-Auditing / Event ID 5156] (100.0% context coverage) |

Context-specific/unmapped process roles: `/SourceImage` (source_process_image), `/SourceProcessId` (source_process_id), `/SourceProcessGUID` (source_process_guid), `/TargetImage` (target_process_image), `/TargetProcessId` (target_process_id), `/TargetProcessGUID` (target_process_guid).

Warnings:
- Timestamp candidates differ by more than 60 seconds in 892 records; timezone-naive values were compared only as wall-clock text and were not assumed to be UTC.
- Observed 898 timezone-naive timestamp values. Their timezone semantics remain unresolved; no UTC timezone was assigned.
- UtcTime was observed but remains review-only until its timezone semantics are confirmed; it was not selected as an event occurrence timestamp.
- CreationUtcTime was observed as creation metadata and was excluded from event occurrence timestamp selection.
- Canonical integer port fields require validated string-to-integer transformation for observed source strings: source_port, destination_port. No transformation was applied during inspection.
- ProcessId changes semantic role by context: it is process_id in Sysmon Event ID 1 but parent_process_id in Security Event ID 4688.
- Sysmon Event ID 10 SourceImage/TargetImage and related identifiers use source/target process roles. canonical-event/v2 does not force them into process_name or parent_process_name.
- Multiple context-aware candidates remain reviewable for: timestamp.

Danh sách field đầy đủ và toàn bộ thống kê vẫn nằm trong `inspection.json` của từng file.
