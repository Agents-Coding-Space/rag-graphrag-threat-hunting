# Báo cáo normalization: mordor-selected-v2

> Đây là kết quả normalization, chưa phải phát hiện hoặc kết luận tấn công.

| Dataset | Input records | Canonical events | Dropped | Events có issue | Total issues | Timestamp null | Status |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| purplesharp_ad_playbook_I_2020-10-22042947.json | 25993 | 25993 | 0 | 25993 | 32175 | 0 | completed |
| empire_launcher_sct_regsvr32_2020-07-21232741.json | 2390 | 2390 | 0 | 2390 | 3362 | 0 | completed |
| cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json | 1127 | 1127 | 0 | 1123 | 1379 | 0 | completed |

## Tổng cộng

- Input records: 29510
- Canonical events: 29510
- Dropped records: 0
- Events có issue: 29506
- Total issues: 36916

## Issues và integrity theo dataset

### purplesharp_ad_playbook_I_2020-10-22042947.json

- Issue counts: `timestamp_conflict`: 25993, `unsupported_context`: 6182
- Raw SHA-256: `d86d22f0c02ab851564bb5e0c90c220e9df0319f5948bfc90dfa605b4511d4f0`
- Canonical events: [files/purplesharp_ad_playbook_i_2020_10_22042947--d86d22f0c02a/canonical_events.jsonl](files/purplesharp_ad_playbook_i_2020_10_22042947--d86d22f0c02a/canonical_events.jsonl)
- Normalization issues: [files/purplesharp_ad_playbook_i_2020_10_22042947--d86d22f0c02a/normalization_issues.jsonl](files/purplesharp_ad_playbook_i_2020_10_22042947--d86d22f0c02a/normalization_issues.jsonl)

### empire_launcher_sct_regsvr32_2020-07-21232741.json

- Issue counts: `timestamp_conflict`: 2390, `unsupported_context`: 972
- Raw SHA-256: `8b619d07ad79713ae96234344c4ba9618eae7119c360ee008b5e0c2cfe4954d7`
- Canonical events: [files/empire_launcher_sct_regsvr32_2020_07_21232741--8b619d07ad79/canonical_events.jsonl](files/empire_launcher_sct_regsvr32_2020_07_21232741--8b619d07ad79/canonical_events.jsonl)
- Normalization issues: [files/empire_launcher_sct_regsvr32_2020_07_21232741--8b619d07ad79/normalization_issues.jsonl](files/empire_launcher_sct_regsvr32_2020_07_21232741--8b619d07ad79/normalization_issues.jsonl)

### cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json

- Issue counts: `timestamp_conflict`: 892, `unsupported_context`: 487
- Raw SHA-256: `25aa24b5f631f19ac23f64db116c23e632295fb5f59040e966fa47e7758b2a32`
- Canonical events: [files/cmd_mshta_vbscript_execute_psh_2020_10_2202580804--25aa24b5f631/canonical_events.jsonl](files/cmd_mshta_vbscript_execute_psh_2020_10_2202580804--25aa24b5f631/canonical_events.jsonl)
- Normalization issues: [files/cmd_mshta_vbscript_execute_psh_2020_10_2202580804--25aa24b5f631/normalization_issues.jsonl](files/cmd_mshta_vbscript_execute_psh_2020_10_2202580804--25aa24b5f631/normalization_issues.jsonl)

`timestamp_conflict` là review warning khi các timestamp candidates lệch quá policy threshold; không làm record bị loại.

`unsupported_context` nghĩa là provider/Event ID chưa có mapping chuyên biệt; base fields vẫn được giữ khi hợp lệ.

Pipeline không filtering hoặc deduplication. Event có issue vẫn được ghi theo contract 1:1.
