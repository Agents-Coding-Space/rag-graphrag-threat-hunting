# FIX2 design — bounded query requirements and returned-evidence verification

Written before implementation, 16/10/2026. This experiment preserves all FIX1
artifacts and legacy APIs. The current request authorizes this implementation;
older pending-approval checkpoints remain historical. No model inference, index
rebuild, raw-log dereferencing, threshold search, LLM or production CLI changes
are needed. A reuses the frozen FIX1 contexts and verifies their saved decisions;
B/C/D derive their new results from the same ranked retrieval, model and index.

## Runtime boundaries and public APIs

New modules live under `threat_hunting.graphrag`; callers import them directly.
Existing `__init__`, schemas, algorithms, policy and fixtures remain unchanged.
All APIs operate on detached finite JSON values and perform no file/network IO.

1. `analyze_query_requirements(query, *, vocabulary=None, scope_metadata=None)`
   in `query_requirements.py` returns `query-requirements/v1`:
   `query`, `analysis_status` (supported/ambiguous/unsupported), `scope`,
   `entities`, mandatory `requirements`, `reason_codes`, and `limitations`.
   Scope uses `requested_platforms`, `excluded_platforms`, `mechanisms`,
   `comparison`, `status` (in_scope/mismatch/ambiguous/unspecified), reason codes.
   Each requirement has `requirement_id`, `kind`, `mandatory`, `parameters`,
   `analysis_status`, `reason_codes`. IDs are local r1/r2, never evaluation IDs.
2. `enrich_query_context(initial_context, corpus, graph, requirements, *,
   budget=None, enabled=True)` in `query_context.py` returns
   `query-evidence-context/v1`: unchanged `initial_context`, `supplementary_items`,
   `final_items`, public `source_inventory`, selection/cut trace and budget state.
   Item = `{kind: chunk|node|edge, item_id, payload: exact source object,
   origin: ranked|traversal|supplementary, requirement_ids, reason_codes}`.
   Supplements carry no rank/BM25/cosine/RRF and create no graph edges/paths.
3. `assess_evidence_support(requirements, final_context)` in `query_support.py`
   returns `query-evidence-support/v1`, status supported/missing/unknown and a
   per-requirement trace. Trace entries identify actual returned item IDs,
   field/pointer, value/quotation and subject/action/object when applicable.
4. Root adds `assess_query_aware_gate(...)` in `query_gate.py`: separate original
   legacy decision, requirements, scope, support, recomputed ranked signals and
   supplemental/final-context diagnostics, final experimental eligibility only.

Runtime inputs exclude case IDs, labels/categories, answers, expected evidence,
GT review metadata and the evaluation rubric. Scope metadata is public evidence
source metadata (Windows/process creation, source provenance and inventory counts).

## Supported information and conservative parsing

Kinds: process_relationship, launch_command, command_completion, service_state,
network_url, evidence_provenance, review_limitations, technique_assessment.
Parameters use generic process/parent/child/actor names, action, requested field,
technique_id, certainty, facets; a process chain may set `chain=true`.
Review facets are all/scope/timestamp/completion/negative_scan/candidate_status/
core_boundaries. No full benchmark-query matches or case-to-requirement tables.

EN/VI concept lexicons, accent normalization and explicit roles/arrows handle a
declared subset. Executable recognition is generic; public aliases are vocabulary,
not an allowed-process whitelist. Clear flat conjunction creates mandatory
subrequirements. Direct Linux/Unix/cron requests can establish scope mismatch;
an excluded Linux mention does not. Comparisons, mixed active platform scopes,
unclear negation, unresolved roles or unsupported clauses are ambiguous/unsupported,
not automatic out-of-scope. Unknown semantics never default to sufficient.

## Enrichment, evidence and budgets

Select source-backed candidates by requirement kinds/entities/facets, preserving
observation/assessment/limitation distinctions. Prefer corpus representations,
use graph representations when needed, deduplicate IDs and equivalent source
objects, retain deterministic ordering and per-item selection reasons. No
reference-answer reader or rubric/GT-pointer dereference exists in runtime.

Default maximums: 12 supplementary items, 64 total final items, 131072 canonical
serialized UTF-8 bytes for final_items. These are bytes, not tokens. Initial items
are never discarded/truncated; an already oversized baseline admits no addition
and reports incomplete context. Whole items are cut, with IDs/reasons recorded.
All-limitations requests may select every limitation within budget. Public source
inventory counts allow verifying completeness without expected evidence IDs.

Positive relationships require directed identities/roles plus source references;
mere co-occurrence is insufficient. Original CommandLine supports launch only.
Completion/output/service state require separate explicit observations. URL
presence is insufficient: a structured observed fact must bind correct actor,
action (download versus connection), and URL/endpoint. Limitations support answers
about limits, never missing positive claims. MITRE candidate/review assessments
support assessment questions without becoming confirmed techniques.
Missing means inspected context lacks required evidence, not real-world absence;
unknown covers unresolved parsing or unsupported verification capabilities.

The current parameter contract does not select an individual command invocation
or service identity. Creation alone is missing completion/state evidence; even
an additional completion/state fact remains unknown when that requested object
cannot be bound. Raw multi-hop identity uses host and GUID/PID kind, never an
unscoped reused PID. Generic parser tests guard against dropping named entities,
unanchored words such as "chain", ignored assertion complements, and unresolved
platform negation being mislabeled as a clear scope mismatch.

## Signals, gate and external evaluation

Every B/D run recomputes legacy signals from the final envelope's unchanged ranked
initial_context, plus new separate final-item/supplement diagnostics. Supplements
cannot inflate old ranked hit/path counts. B old-policy decisions may thus equal
A while context sufficiency improves; this is an intended, reported ablation.
C/D require all mandatory support, scope compatibility and `legacy proceed`.
Clear mismatch blocks topical; ambiguous/unsupported analysis and unknown/missing
support block explicitly. All blockers and the legacy result remain visible; no
threshold is replaced or legacy topical failure silently bypassed.

A/B/C/D use the same 32 development labels outside runtime. Unchanged external
AI rubric evaluates actual final_items through an evaluation-only shape adapter;
it does not judge success using the new support checker. Report its exact-match
and semantic-unknown limits, EN/VI metrics, context sizes/cuts, transitions and
support traces. No 11 proposed probes or held-out queries are run. New synthetic
tests are development tests. Stop for review after tests, hashes and safe ZIP.

An initial development run is retained under `iterations/initial/`. Independent
code review found the generic parsing invariants above; they were corrected and
tested with synthetic renamed examples before the final rerun. This is normal
development reuse of the same exposed 32 queries, not an independent experiment,
threshold search or held-out validation. Initial runtime code hashes were not
captured at inference time; final runtime/runner hashes are explicitly bound in
the final configuration and checked after the run.
