> Distribution note: this is the staged handover copy. Inputs are now included under data/. See START_HERE.md and packaging/path_migration.json for portable paths; dated instructions below describe earlier tasks.

# AGENTS.md

**Status updated:** 01/11/2026

> **ĐỌC TRƯỚC:** trạng thái hiện hành ở [docs/CURRENT_STATUS.md](docs/CURRENT_STATUS.md). Profile hiện hành là **integrated-final-direct-v14**, không phải v7. Các chỉ dẫn ngày 31/10 dưới đây là lịch sử; phần "Working source đã khác pin" đã được xử lý bằng pin v14.

## 1. Project context

This repository implements the graduation project:

> **Nghiên cứu mô hình kết hợp RAG, GraphRAG, LLM và ứng dụng truy tìm mối đe dọa ATTT**

Before planning, analyzing data, or editing code, read `PROJECT_CONTEXT.md` in the repository root. Treat it as the authoritative project brief. If an instruction in the current user prompt conflicts with `PROJECT_CONTEXT.md`, follow the current prompt and note the conflict.

Do not bring unrelated SOC labs, NIDS/CIC-IDS-2017, Solana, Hyperledger Fabric, IAM/Keycloak, or other projects into this repository.

## 2. Current objective

Read `PROJECT_CONTEXT.md`, `HANDOVER.md` and the latest appended summary in `PROJECT_PROGRESS.md` before continuing. Earlier dated checkpoints describe history, not the current implementation boundary.

The repository now has evidence/correlation, Sigma/STIX/CTI integration, Ground Truth consumers, E5 retrieval, JSON graph, source-evidence gate, generation/validation and the existing three-column dashboard for all three scenarios. The latest frozen study is `configs/evaluation/integrated_final_direct_v7.json`, with `outputs/final/20261031_direct_v7/runtime_pin.json` and consumers selected by `configs/runtime_artifacts_integrated_v5.json`.

The final live comparison is incomplete: its first request returned HTTP402 without a model answer; the original checkpoint has one row. Derived closeout has 8 abstain, 1 provider_error and 15 not_run across 24 branches. Do not call this a completed generation evaluation or infer semantic accuracy from gate eligibility.

Current working source differs from the v7 pin: four changed runtime files and new `llm/error_diagnostics.py`; `outputs/offline/http402_recovery_20261031_v1/` currently only contains a before-hash snapshot. Review and verify this work before creating a compatible execution delta or a new study pin. Preserve existing changes; do not bypass pin checks or rewrite historical pins to force startup.

Human approval metadata exists for the historical MSHTA review bundle dated 15/10/2026. The three integrated consumers remain `draft_reviewable` / `pending_human_review`; do not transfer approval or promote evidence/technique labels automatically. Reference answers, expected decisions and rubrics remain evaluation-only, excluded from runtime corpus/gate/messages.

Continue ordinary implementation and verification already authorized by the current task without adding approval stops based on obsolete checkpoints. Human label approval, external publication and real API spending remain separate actions governed by the current user request and actual runtime policy. The present handover task authorizes documentation and a secret-free `.env.example` only: no runtime/config/pin/output changes, new experiments, generation, Word edits, ZIP, commit or push.

The receiving developer may choose local/API LLMs and providers. Existing model/provider values are checkpoint settings, not requirements to use Gemma, OpenRouter or 9Router. Version config/pin/results when changing them; use the same LLM and relevant generation parameters for both branches within one comparison.

## 3. Selected input files

Only the filenames are fixed. Their directory paths may vary between machines. Discover their real locations in the repository and the documented external data roots before running scripts; the ten current inputs are in the sibling data directory listed in `PACKAGING_CHECKLIST.md`.

### Security Datasets/Mordor logs

- `purplesharp_ad_playbook_I_2020-10-22042947.json`
- `empire_launcher_sct_regsvr32_2020-07-21232741.json`
- `cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json`

### MITRE ATT&CK

- `enterprise-attack.json`

### Sigma rules: password spraying and Kerberoasting

- `win_security_susp_rc4_kerberos.yml`

The password-spraying detector is a derived, project-defined Sigma correlation. It is not a raw external input. It now exists at `configs/knowledge/derived/win_security_password_spray_correlation.yml`, alongside the authentication correlation implementation; its findings still require review. Its intended logic is at least five distinct `TargetUserName` values from the same source context within one minute, using Event IDs `4625` and/or `4776`. Correlated endpoint and domain-controller records must not be double-counted.

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

Look for `mshta.exe` executing a `vbscript:` command and spawning `powershell.exe`. The reviewed core supports proxy execution and a suspicious parent-child relationship. PowerShell was launched with `-noexit -command Get-Service sysmon`; process-creation telemetry does not establish successful cmdlet completion, output or the Sysmon service state. The reviewed evidence does not demonstrate a PowerShell download, C2 channel, data theft or destructive payload. Do not infer those behaviors.

Keep the two process-creation evidence groups distinct from the full file. The file also contains a `conhost.exe` child, temporary-file deletion and event-log clearing telemetry outside that core. Do not claim that deletion is globally absent, infer destructive intent from those records or add positive technique labels without a separate evidence review.

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

Prepare a reviewable handover from actual source/config/pin/artifact state, preserving the project title, chapter structure and all three scenarios. Keep the existing three-column dashboard. Technical implementation, offline verification, live execution and human acceptance must be reported separately.

Use `HANDOVER.md` for the prioritized remaining work: finish generation configuration and source/pin compatibility, verify end-to-end behavior, review source semantics/citations, assess retrieval/gate abstentions, freeze a consistent evaluation, review answer quality/timing, validate the final dashboard and align the thesis/reproduction guide. Tests passed or accepted_draft do not substitute for semantic review; correct abstention is valid.

Use `PACKAGING_CHECKLIST.md` for the ten external inputs currently in the sibling data directory, model cache, absolute-path migration, provenance closure and secret exclusions. This checkout has no `.git`; do not claim clean git status. Preserve progress history by appending, and distinguish current instructions from old dated stopping points.

## 15. Verified data-selection decisions (16/07/2026; MSHTA reviewed 14/10/2026)

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
- Security Event ID `4688` at line `4` and Sysmon Event ID `1` at line `275` describe the same `mshta.exe` creation; Security line `30` and Sysmon line `398` describe the same `powershell.exe` creation. These four observations support two behavior groups and must not be counted as four process creations.
- Security line `36` and Sysmon line `422` describe the same `conhost.exe` child of PowerShell. This process is outside the two-group ground-truth core and must not be counted as another copy of the MSHTA or PowerShell behavior.
- The observed PowerShell launch command is `-noexit -command Get-Service sysmon`; it does not prove cmdlet completion or service state. No download, C2, credential theft or destructive payload is supported by these two reviewed process-creation groups.
- The complete raw file contains temporary-file deletion and event-log clearing telemetry outside the core. Preserve those records and scope limitations without asserting destructive intent or global absence of deletion.
- Sysmon `UtcTime` differs from `TimeCreated` by about four hours and is timezone-naive in the source. Preserve the conflict and do not invent a timezone correction.

Candidate MITRE techniques for the selected scenarios are `T1110.003`, `T1558.003`, `T1218.010`, and `T1218.005`. Resolve and verify them from `enterprise-attack.json`, cite the supporting evidence and obtain human review before marking mappings as `confirmed`.

The local ATT&CK snapshot is pinned to `v19.1` by `configs/knowledge/mitre_enterprise_attack.json`. The MSHTA audit validated that manifest and the active STIX objects. `T1218.005` has `supported_by_observed_behavior`; Sigma-derived `T1059.007` (JavaScript) has `not_supported_by_observed_command` because the command is VBScript; Sigma-derived `T1140` has `not_assessed`. These assessments remain `candidate`, with no label promotions. Rule descriptions and tags do not prove download, decoding, disguised file extensions or CVE exploitation.
