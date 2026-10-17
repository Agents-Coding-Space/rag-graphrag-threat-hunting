# FIX3 design and frozen policy — 17/10/2026

Written before implementing or evaluating E0–E4. Current authorization supersedes
historical pending-approval checkpoints. Preserve every existing source/fixture,
FIX1/FIX2 artifact and ZIP. New versioned modules provide a separate experiment;
no corpus/index rebuild, ranking/embedding/model/LLM call, production integration,
threshold sweep, 11 probes or held-out use.

## Contracts and ownership

`query_requirements_v2.py`: `analyze_query_requirements_v2(query, *, vocabulary=None,
scope_metadata=None)`, `validate_query_requirements_document_v2(document)` and
`requirements_v1_projection(document)`. Schema `query-requirements/v2` retains
the eight kinds and core parameters. Root adds `clauses` with original Unicode
start/end/text and request/background role. Requirements add `source_spans`
with clause ID/start/end/text and role request/subject/action/object/parent/child/
target/requested_field/context. Every span must resolve to exact original text.
No data/labels/answers/case IDs enter parsing. V1 public APIs remain untouched.

Clause-local grammar handles target-only ancestor chain requests without guessing
ancestors (`parent=null, child=target, chain=true`), directed A-to-B creation
relationships, passive launch commands and URL actor/action/main request separate
from contextual chain mentions. Explicit independent requests remain mandatory.
EN/VI negation, comparison, uncovered claims and unresolved roles stay ambiguous.
General review/follow-up asks are supported only when explicitly grounded in
evidence/review scope. V2 adds limitation facet `review_status`, meaning scenario
analysis_status only; human reviewer/time/approval questions remain unsupported.
Projection maps this facet to scope for old selectors, never to human confirmed.

`query_context_v2.py`: `upgrade_evidence_context(context, corpus, graph)` adds an
authenticated exact source inventory in `query-evidence-context/v2` without
altering final_items or ranked retrieval. Inventory includes source-GT binding,
exact limitation sources `{object_type,object_id,json_pointer,facets}` and explicit
source process relationships `{source_identity,parent_identity,child_identity}`.
The relationship inventory includes authenticated raw process-creation facts when
host-scoped GUIDs map to source entity instance IDs. It records the explicit fields
`process_relationship_inventory_complete` and
`unresolved_process_relationship_sources`; unresolved mappings keep target-only
source boundaries unknown. A relationship source identity may name a relationship
or a fact. Neither inventory nor coverage metadata supplies positive support.
`enrich_query_context_v2(initial_context,corpus,graph,requirements,*,budget,
max_chain_depth)` selects source-backed items with existing v1 selectors plus
bounded exact-identity ancestor support. No new edges/paths/ranks are created.
Budget is explicitly passed: 12 supplements, 64 final items, 131072 serialized
UTF-8 bytes. Preserve full initial evidence; report whole-item cuts/incomplete.

`query_support_v2.py`: `assess_evidence_support_v2(requirements,final_context,*,
max_chain_depth)` accepts exact supported v1/v2 requirements/context versions;
reuses old field verifiers for unchanged kinds. V2 support adds per-requirement
completeness complete/incomplete/unknown/not_applicable and structured contradiction
none_detected/detected/unknown. Positive support uses returned final_items only.
Source inventory establishes completeness boundaries, never positive evidence.

Chains traverse observed directed relationships linked by actual source entity
instance IDs or host-scoped GUIDs. Never join basename or raw PID across records
without a lifetime identity. Target-only requests walk incoming identities until
authenticated source boundaries; minimum one actual relation. Depth limit 8,
cycle detection and missing source-boundary evidence produce incomplete/unknown.
All-limitations and facet subsets compare exact source identities, never counts.
review_status requires actual scenario analysis_status. A generic limitation
cannot support unrelated positive behavior, download, completion or service state.
URL support binds observed actor–action–endpoint; incidental URL prose fails.
Completion/service-invocation selector limitations from FIX2 remain explicit.

`query_policy.py`: `validate_combined_policy(policy)` and
`assess_combined_query_gate(context,requirements,*,corpus,graph,policy,legacy_policy)`.
New `query-evidence-eligibility-policy/v1` is fully configured in combined_policy.json.
Recompute legacy decision for diagnostics; never require its proceed result.
Authenticate final payloads exactly against runtime corpus/graph and shared
provenance; source documents are used for authentication/inventory only, never to
silently supply missing support. New decision has its own version and all blockers.

## Hard requirements versus diagnostics

Hard: valid query/source context, >=1 real ranked hit with finite existing scores,
exact ranked/final payload source binding, supported parsed mandatory requirements,
no resolved mismatch/ambiguous scope, all mandatory evidence supported with
nonempty field-resolved traces, kind-specific identity/source anchors, no relevant
contradiction or required-identity/completeness gaps. Partial/missing/unknown blocks.
Unspecified scope may pass only when each requirement has authenticated role/
identity-bound observations or requested source-associated limitation/scenario/
assessment metadata. Similarity alone never establishes scope.

Diagnostic: legacy decision and old cosine/token/count/traversal thresholds.
Remove those thresholds from the new hard gate because they were not validated
for EN/VI evidence eligibility; replace them with explicit source-bound ranked
presence, finite scores, actual evidence anchors and completeness checks. Do not
interpret BM25/cosine/RRF as probabilities. Direct evidence does not require graph
traversal. Supplements retain no invented score. Unrelated selection cuts remain
diagnostic if mandatory support/completeness is established; relevant cuts block.
Contradictions cover explicit functional conflicts for the same stable instance,
not arbitrary prose and not legitimate multiple network destinations.

## E0–E4 and causal accounting

E0 uses old parser, exact saved FIX2 enriched context and old checker/AND branch;
replay must match FIX2 D byte-for-byte decisions. E1 uses parser v2 and unchanged
FIX2 final_items with required v2 checker compatibility plus legacy-quality AND.
E2 uses old parser/checker with the same FIX2 final_items and the new combination
policy's independent authentication/identity/completeness/contradiction guards.
E3 uses parser v2, unchanged FIX2 final_items and new combination policy. E4 recomputes
only supplementation from new requirements on the same frozen FIX1 ranked context.
Inventory-only upgrades for E1–E3 must assert final_items/initial_context equality.
The v2 chain/completeness adapter is part of the new requirement contract in E1;
report this boundary rather than pretending verifier representation never changed.

Old requirement versions keep old support assessment available; new policy guards
are reported separately. No legacy meaning or saved FIX2 result is rewritten.
Capture policy/config/code hashes before the first E-arm run and verify afterward.
If a genuine bug is repaired after inspecting results, archive the full earlier
development iteration and explain it; do not search alternative policies.

External approved dataset labels and unchanged AI diagnostic rubric remain outside
runtime. A shape adapter reads actual final items without pretending supplements
were ranked. Report all arm metrics, EN/VI, unknowns, false abstains, context bytes,
transitions, evidence and limits for every newly permitted query. All these 32
queries and new synthetic tests are exposed development data. Stop for review.
