# AGENTS.md

## 1. Project context

This repository implements the graduation project:

> **Nghiên cứu mô hình kết hợp RAG, GraphRAG, LLM và ứng dụng truy tìm mối đe dọa ATTT**

Before planning, analyzing data, or editing code, read `PROJECT_CONTEXT.md` in the repository root. Treat it as the authoritative project brief. If an instruction in the current user prompt conflicts with `PROJECT_CONTEXT.md`, follow the current prompt and note the conflict.

Do not bring unrelated SOC labs, NIDS/CIC-IDS-2017, Solana, Hyperledger Fabric, IAM/Keycloak, or other projects into this repository.

## 2. Current objective

The immediate goal is to build a small, reproducible pipeline that:

1. Inspects the selected Security Datasets/Mordor logs without modifying them.
2. Identifies their schemas and useful security fields.
3. Extracts evidence for three threat-hunting scenarios.
4. Compares the evidence with the selected Sigma rules.
5. Maps supported behavior to MITRE ATT&CK.
6. Produces a reviewable draft of `scenario_ground_truth.json`.

Do not start the full RAG, GraphRAG, LLM, vector database, graph database, or user-interface implementation until the data schema and ground truth have been reviewed.

## 3. Selected input files

Only the filenames are fixed. Their directory paths may vary between machines. Discover their real locations in the repository before running scripts.

### Security Datasets/Mordor logs

- `purplesharp_ad_playbook_I_2020-10-22042947.json`
- `empire_launcher_sct_regsvr32_2020-07-21232741.json`
- `cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json`

### MITRE ATT&CK

- `enterprise-attack.json`

### Sigma rules: password spraying and Kerberoasting

- `win_security_susp_rc4_kerberos.yml`

The password-spraying detector is a derived, project-defined Sigma correlation. It is not a raw external input and will be created later as `win_security_password_spray_correlation.yml`. Its intended logic is at least five distinct `TargetUserName` values from the same source context within one minute, using Event IDs `4625` and/or `4776`. Correlated endpoint and domain-controller records must not be double-counted.

### Sigma rules: C2 through Regsvr32

- `proc_creation_win_regsvr32_http_ip_pattern.yml`
- `proc_creation_win_regsvr32_susp_child_process.yml`
- `proc_creation_win_regsvr32_susp_parent.yml`

### Sigma rules: suspicious PowerShell execution through MSHTA

- `proc_creation_win_mshta_susp_child_processes.yml`
- `proc_creation_win_mshta_susp_execution.yml`

### Excluded inputs

The following files remain read-only reference material but are excluded from the active experiment because they do not match the observed telemetry or scenario behavior:

- `psh_powershell_httplistener_2020-11-0204130683.json`
- `win_security_susp_failed_logon_reasons.yml`
- `win_security_susp_failed_logon_source.yml`
- `win_security_susp_kerberos_manipulation.yml`
- `proc_creation_win_regsvr32_flags_anomaly.yml`
- `proc_creation_win_regsvr32_remote_share.yml`
- `posh_ps_susp_download.yml`
- `posh_ps_susp_invocation_specific.yml`
- `proc_creation_win_powershell_base64_encoded_cmd.yml`
- `proc_creation_win_powershell_download_patterns.yml`
- `proc_creation_win_powershell_susp_download_patterns.yml`

If a selected file cannot be found, stop the affected task and report the missing filename. Do not silently replace it with a similar file.

## 4. Non-negotiable data rules

- Treat original Mordor, Sigma, MITRE, and CTI files as read-only.
- Never overwrite, reformat, rename, move, truncate, or delete raw input files.
- Write derived data only to a clearly separate processed or output directory.
- Do not fabricate IP addresses, users, hosts, timestamps, processes, command lines, Event IDs, Sigma matches, or MITRE techniques.
- Do not treat a Sigma rule match as unquestionable ground truth. Record the matching evidence and allow human review.
- Do not assign a MITRE technique only because it appears plausible. Every confirmed mapping must cite log evidence, a Sigma rule, or an ATT&CK object.
- Distinguish `observed`, `inferred`, `candidate`, and `confirmed` values in generated ground truth.
- Preserve Unicode and read text files with UTF-8 or UTF-8-SIG where appropriate.
- Do not include secrets, credentials, API keys, personal data, or unrelated machine paths in committed outputs.

## 5. Data discovery and inspection

Before writing a parser, inspect the actual files and report:

- Resolved file location.
- File size and encoding.
- JSON format: array, object, JSON Lines, or another structure.
- Record count, when it can be obtained safely.
- Representative top-level and nested fields.
- Candidate fields for timestamp, host, user, IP, process, parent process, command line, Event ID, channel, provider, file, registry, DNS, and network destination.
- Distribution of Event IDs and providers.
- Minimum and maximum timestamps after normalization.
- Missing, inconsistent, or multi-valued fields.

Large logs should be processed as streams when practical. Do not load an entire large JSON/JSONL file into memory merely for convenience. Sampling is allowed for schema discovery, but final counts and evidence extraction must process the complete selected file.

## 6. Canonical event schema

Propose and document a minimal canonical schema before normalizing all logs. Prefer the following field names where the source data supports them:

```text
event_id
timestamp
channel
provider
host
user
source_ip
source_port
destination_ip
destination_port
process_name
process_id
parent_process_name
parent_process_id
command_line
file_path
registry_key
dns_query
raw_record_ref
source_file
```

Do not force absent values into the schema. Use `null` for unavailable scalar fields and document every source-to-canonical mapping.

`raw_record_ref` must make it possible to trace a normalized event back to its original record, such as a stable line number, array index, event record ID, or deterministic hash.

## 7. Scenario boundaries

Only implement these scenarios initially:

### Password spraying and Kerberoasting

Look for multiple distinct user accounts receiving failed authentication from the same source context within a short interval, plus suspicious RC4 Kerberos service-ticket requests. Event IDs `4625`, `4776`, and `4769` are candidates, not ground truth by themselves. Treat corresponding endpoint `4625` and domain-controller `4776` records as two views of the same authentication attempt when their entities and timestamps align.

### Suspicious PowerShell execution through MSHTA

Look for `mshta.exe` executing a `vbscript:` command and spawning `powershell.exe`. The selected dataset demonstrates proxy execution and a suspicious parent-child relationship, but it does not demonstrate a PowerShell download, C2 channel, data theft, or destructive payload. Do not infer those behaviors.

### C2 through Regsvr32

Look for `regsvr32.exe`, remote `.sct` or scriptlet usage, a suspicious PowerShell parent and child, direct-IP HTTP command lines, and outbound network connections. The selected dataset uses HTTP rather than a remote UNC share, and its `/i` command includes `/n`; do not label it as a remote-share or missing-`/n` flag anomaly.

Do not add a fourth scenario without an explicit user decision.

## 8. Ground-truth requirements

Create the ground truth as a reviewable artifact, not an automatic final answer. Each scenario entry should contain at least:

```text
scenario_id
scenario_name
source_log_file
analysis_status
time_window
observed_entities
evidence
sigma_rules
mitre_techniques
expected_relationships
expected_summary
investigation_questions
review_notes
```

Each evidence item should include:

- A stable reference to the raw event.
- Timestamp when available.
- Relevant original fields.
- A concise explanation of why it matters.
- The Sigma rule or MITRE mapping it supports, if any.
- Confidence or review status.

Generated ground truth must be valid JSON, deterministically ordered where practical, and validated before delivery. Keep an intermediate human-readable report so the user can review the evidence before labels are marked `confirmed`.

## 9. MITRE and Sigma handling

- Parse `enterprise-attack.json` as STIX 2.1 data.
- Resolve MITRE technique IDs from ATT&CK objects instead of maintaining an unverified handwritten lookup table.
- Preserve the ATT&CK version or collection metadata used by each experiment.
- Parse Sigma YAML safely; do not execute arbitrary YAML tags.
- Retain Sigma metadata such as title, ID, status, log source, detection condition, tags, level, and references when available.
- A selected Sigma rule is a knowledge source and detection hypothesis. It is not proof that the corresponding event exists in a Mordor log.
- Record unsupported Sigma fields or backend-specific assumptions instead of silently ignoring them.

## 10. Python engineering conventions

- Prefer Python 3.11 or newer unless the repository already specifies another supported version.
- Use `pathlib.Path` for filesystem paths.
- Use type hints for public functions and important data structures.
- Keep functions focused and modules small.
- Use `argparse` or the repository's existing CLI framework for runnable scripts.
- Use the standard `logging` module instead of scattered debug prints in production scripts.
- Provide clear errors containing the filename and failed operation.
- Keep input discovery separate from parsing, normalization, detection, mapping, and output generation.
- Avoid adding a heavy framework when the standard library or a small dependency is sufficient.
- Pin direct dependencies in the repository's chosen dependency file.
- Do not introduce Jupyter notebooks as the only implementation of core pipeline logic. Notebooks may demonstrate results but reusable logic belongs in Python modules.

## 11. Suggested module boundaries

Adapt to the existing repository instead of creating duplicate structures. If no structure exists, prefer:

```text
src/
  data_discovery.py
  mordor_parser.py
  normalizer.py
  sigma_loader.py
  mitre_loader.py
  evidence_extractor.py
  ground_truth.py
scripts/
  inspect_mordor.py
  build_ground_truth.py
tests/
outputs/
```

Do not create all modules up front. Add them only as their responsibility becomes necessary.

## 12. Tests and verification

For every parser or transformation:

- Add a small fixture that does not duplicate the full raw dataset.
- Test JSON array and JSON Lines handling when both are supported.
- Test missing and nested fields.
- Test stable `raw_record_ref` generation.
- Test that raw input files remain unchanged.
- Validate generated JSON by reading it back.
- Report record counts before and after normalization or filtering.
- Explain any dropped records.

Use the repository's existing test command. If none exists and Python is used, prefer `pytest`. Do not claim success without running the relevant checks or clearly stating why they could not run.

## 13. Working style for Codex

- Start by inspecting the repository; do not assume paths or installed dependencies.
- Present a short plan before broad or multi-file changes.
- Implement one small milestone at a time.
- Explain outcomes in Vietnamese; keep identifiers, filenames, code, and standard technical terms in English.
- When code is changed, report the files changed, commands run, tests run, and remaining limitations.
- Ask for user input only when a missing choice would materially change the result.
- Do not edit thesis documents unless the current task explicitly requests document work.
- Preserve unrelated user changes in the working tree.
- Do not commit, push, create a pull request, or publish data unless explicitly requested.

## 14. Current milestone

The first milestone is complete only when:

1. All 10 external selected inputs are found: 3 Security Datasets/Mordor logs, 6 Sigma rules, and 1 MITRE file.
2. The three selected log formats and schemas are documented, including a fresh inspection of the replacement MSHTA dataset.
3. A proposed source-to-canonical field mapping is produced.
4. No raw input file has changed.
5. The inspection command is reproducible.
6. The next evidence-extraction step is based on observed fields rather than assumptions.

Do not generate final ground-truth labels during this first milestone.

## 15. Verified data-selection decisions (2026-07-16)

The active experiment is fixed to the following three scenarios and verified evidence anchors. These findings came from complete streaming reads of the selected JSONL files; they are not assumptions based on filenames.

### Password spraying and Kerberoasting

- Source: `purplesharp_ad_playbook_I_2020-10-22042947.json`
- Records: `25,993`
- SHA-256: `d86d22f0c02ab851564bb5e0c90c220e9df0319f5948bfc90dfa605b4511d4f0`
- Password-spraying evidence: seven Event ID `4625` records targeting seven distinct accounts within 12 milliseconds at `jsonl:line:788`, `790`, `792`, `794`, `796`, `798`, and `803`.
- Corresponding Event ID `4776` records on the domain controller are duplicate telemetry views of the same seven attempts.
- `win_security_susp_rc4_kerberos.yml` matches five Event ID `4769` records at `jsonl:line:1125`, `1136`, `1140`, `1144`, and `1148`.
- The three excluded authentication/Kerberos Sigma rules each produced zero matches on the complete file.

### C2 through Regsvr32

- Source: `empire_launcher_sct_regsvr32_2020-07-21232741.json`
- Records: `2,390`
- SHA-256: `8b619d07ad79713ae96234344c4ba9618eae7119c360ee008b5e0c2cfe4954d7`
- `jsonl:line:97`: PowerShell spawns `regsvr32.exe` with `/i:http://10.10.10.5:8444/launcher.sct`; matches the HTTP-IP and suspicious-parent rules.
- `jsonl:line:224`: `regsvr32.exe` spawns encoded `powershell.exe`; matches the suspicious-child rule.
- `jsonl:line:1001`: `regsvr32.exe` connects from `172.18.39.5` to `10.10.10.5:8444`.
- The child PowerShell process repeatedly connects to `10.10.10.5:80`.
- The excluded flag-anomaly and remote-share rules each produced zero matches on the complete file.

### Suspicious PowerShell execution through MSHTA

- Source: `cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json`
- Records: `1,127`
- SHA-256: `25aa24b5f631f19ac23f64db116c23e632295fb5f59040e966fa47e7758b2a32`
- `jsonl:line:275`: `cmd.exe` spawns `mshta.exe` with a `vbscript:Execute` command; matches `proc_creation_win_mshta_susp_execution.yml`.
- `jsonl:line:398`: `mshta.exe` spawns `powershell.exe`; matches `proc_creation_win_mshta_susp_child_processes.yml`.
- Security Event ID `4688` records at lines `4`, `30`, and `36` duplicate the Sysmon process telemetry and must not be counted as additional processes.
- The PowerShell payload only runs `Get-Service sysmon`; no download, C2, credential theft, or destructive behavior is observed.

Candidate MITRE techniques are `T1110.003`, `T1558.003`, `T1218.010`, and `T1218.005`. Resolve and verify them from `enterprise-attack.json` before marking mappings as confirmed.
