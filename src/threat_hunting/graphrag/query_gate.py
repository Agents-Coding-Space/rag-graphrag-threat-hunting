"""Experimental query-aware eligibility, preserving the legacy quality gate.

Ranked retrieval signals describe ranked hits only. Supplemental evidence has
separate diagnostics and never receives an invented rank, score or graph path.
This module neither reads artifacts nor produces a security conclusion.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from copy import deepcopy
import json
from typing import Any

from .gate_signals import extract_graphrag_gate_signals
from .query_context import validate_query_evidence_context
from .query_requirements import validate_query_requirements_document
from .query_support import assess_evidence_support
from .two_stage_gate import assess_graphrag_two_stage_gate


class QueryAwareGateError(ValueError):
    """Experimental input cannot preserve the runtime evidence boundary."""


def _snapshot(value: object) -> Any:
    try:
        return json.loads(json.dumps(value, ensure_ascii=False, allow_nan=False))
    except (TypeError, ValueError, RecursionError) as exc:
        raise QueryAwareGateError(f'Expected finite JSON: {exc}') from exc


def _context(value: Mapping[str, Any]) -> dict[str, Any]:
    root = _snapshot(value)
    validate_query_evidence_context(root)
    if not isinstance(root, dict) or root.get('schema_version') != 'query-evidence-context/v1':
        raise QueryAwareGateError('Expected query-evidence-context/v1')
    if not isinstance(root.get('initial_context'), dict) or not isinstance(root.get('final_items'), list):
        raise QueryAwareGateError('Context requires initial_context and final_items')
    seen = set()
    for item in root['final_items']:
        if not isinstance(item, dict) or item.get('kind') not in ('chunk', 'node', 'edge'):
            raise QueryAwareGateError('Malformed final evidence item')
        key = (item['kind'], item.get('item_id'))
        if not isinstance(key[1], str) or not key[1] or key in seen:
            raise QueryAwareGateError('Final evidence IDs must be nonempty and unique by kind')
        seen.add(key)
        payload = item.get('payload')
        id_field = {'chunk': 'chunk_id', 'node': 'node_id', 'edge': 'edge_id'}[item['kind']]
        if not isinstance(payload, dict) or payload.get(id_field) != item['item_id']:
            raise QueryAwareGateError('Final item ID differs from returned payload')
        if item.get('origin') not in ('ranked', 'traversal', 'supplementary'):
            raise QueryAwareGateError('Unknown final evidence origin')
    # Every original payload must still be present exactly; an envelope cannot
    # silently replace ranked evidence with a different source object.
    initial = root['initial_context']
    expected = [('chunk', hit['chunk']) for hit in initial['retrieval']['hits']]
    traversal = initial.get('traversal') or {}
    expected += [('node', item) for item in traversal.get('nodes', [])]
    expected += [('edge', item) for item in traversal.get('edges', [])]
    actual = {(item['kind'], item['item_id']): item['payload'] for item in root['final_items']}
    for kind, payload in expected:
        id_field = {'chunk': 'chunk_id', 'node': 'node_id', 'edge': 'edge_id'}[kind]
        if actual.get((kind, payload[id_field])) != payload:
            raise QueryAwareGateError('Initial evidence missing or changed in final context')
    return root


def extract_query_evidence_signals(final_context: Mapping[str, Any]) -> dict[str, Any]:
    """Recompute ranked signals and independent final-context diagnostics."""
    try:
        context = _context(final_context)
        ranked = extract_graphrag_gate_signals(context['initial_context'])
        items = context['final_items']
        refs = {
            (ref['source_file'], ref['raw_record_ref'])
            for item in items for ref in item['payload'].get('source_references', [])
            if isinstance(ref, dict) and isinstance(ref.get('source_file'), str)
            and isinstance(ref.get('raw_record_ref'), str)
        }
        evidence = sorted({identifier for item in items
                           for identifier in item['payload'].get('evidence_ids', [])})
        diagnostics = {
            'final_item_count': len(items),
            'supplementary_item_count': sum(item['origin'] == 'supplementary' for item in items),
            'item_kind_counts': dict(sorted(Counter(item['kind'] for item in items).items())),
            'source_object_type_counts': dict(sorted(Counter(
                item['payload'].get('source', {}).get('object_type', 'unknown') for item in items
            ).items())),
            'unique_source_reference_count': len(refs), 'returned_evidence_ids': evidence,
            'serialized_final_items_utf8_bytes': len(json.dumps(items, ensure_ascii=False,
                sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')),
            'incomplete_context': context['incomplete_context'],
            'unranked_items_have_no_retrieval_scores_or_paths': True,
        }
        return {'schema_version': 'query-evidence-signals/v1',
                'ranked_retrieval': ranked, 'final_evidence_context': diagnostics}
    except QueryAwareGateError:
        raise
    except Exception as exc:
        raise QueryAwareGateError(f'Invalid query evidence context: {exc}') from exc


def assess_query_aware_gate(
    final_context: Mapping[str, Any], requirements: Mapping[str, Any], *,
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    """Require explicit scope/requirements/support AND the unchanged old policy.

    Blockers are reported independently even when the old topical gate fails.
    Their order is scope, parsing, support, then legacy quality. The final stage
    names the first blocker; the original decision and every blocker remain
    visible. No unsupported requirement is described as a scope mismatch.
    """
    try:
        context = _context(final_context)
        requested = _snapshot(requirements)
        validate_query_requirements_document(requested)
        if requested['query'] != context['initial_context']['query']['text']:
            raise QueryAwareGateError('Requirements query differs from ranked context query')
        signals = extract_query_evidence_signals(context)
        legacy = assess_graphrag_two_stage_gate(signals['ranked_retrieval'], policy=policy)
        support = assess_evidence_support(requested, context)
        blockers = []
        scope = requested['scope']
        if scope['status'] == 'mismatch':
            blockers.append({'stage': 'topical_relevance', 'reason_code': 'requested_scope_mismatch'})
        elif scope['status'] == 'ambiguous':
            blockers.append({'stage': 'query_requirements', 'reason_code': 'query_scope_ambiguous'})
        if requested['analysis_status'] != 'supported':
            blockers.append({'stage': 'query_requirements',
                             'reason_code': 'query_requirements_' + requested['analysis_status']})
        if support['status'] != 'supported':
            blockers.append({'stage': 'evidence_answerability',
                             'reason_code': 'required_evidence_' + support['status']})
        if legacy['decision'] != 'proceed':
            blockers.append({'stage': legacy['abstention_stage'], 'reason_code': 'legacy_quality_gate_abstained',
                             'legacy_reason_codes': deepcopy(legacy['reason_codes'])})
        return {
            'schema_version': 'query-aware-gate-decision/v1',
            'configuration': {'schema_version': 'query-aware-eligibility-policy/v1',
                              'legacy_quality_mode': 'require_legacy_proceed',
                              'all_mandatory_requirements_must_be_supported': True},
            'legacy_decision': legacy, 'query_requirements': requested,
            'scope_assessment': deepcopy(scope), 'support_assessment': support,
            'signals': signals,
            'final_decision': 'abstain' if blockers else 'proceed',
            'abstention_stage': blockers[0]['stage'] if blockers else None,
            'reason_codes': [blocker['reason_code'] for blocker in blockers],
            'blockers': blockers, 'security_conclusion_made': False,
        }
    except QueryAwareGateError:
        raise
    except Exception as exc:
        raise QueryAwareGateError(f'Invalid query-aware gate input: {exc}') from exc
