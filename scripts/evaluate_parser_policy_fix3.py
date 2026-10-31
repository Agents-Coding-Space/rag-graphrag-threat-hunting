"""E0–E4 development comparison on frozen evidence, without model or raw-log IO.

This research runner alone joins approved labels and the unchanged external AI
rubric. Runtime parser/policy/verifiers never receive evaluation annotations.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import logging
from pathlib import Path
from typing import Any

from threat_hunting.evaluation.two_stage_review import load_approved_evaluation_bundle
from threat_hunting.graph import load_knowledge_graph
from threat_hunting.graphrag.gate_signals import extract_graphrag_gate_signals
from threat_hunting.graphrag.query_context_v2 import upgrade_evidence_context, enrich_query_context_v2
from threat_hunting.graphrag.query_gate import assess_query_aware_gate
from threat_hunting.graphrag.query_policy import assess_combined_query_gate, validate_combined_policy
from threat_hunting.graphrag.query_requirements_v2 import analyze_query_requirements_v2
from threat_hunting.graphrag.query_support_v2 import assess_evidence_support_v2
from threat_hunting.graphrag.two_stage_gate import assess_graphrag_two_stage_gate
from threat_hunting.retrieval import load_retrieval_corpus, load_vector_index


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'outputs/experiments/graphrag-2d3-fix3'
FIX1 = ROOT / 'outputs/experiments/graphrag-2d3-fix1'
FIX2 = ROOT / 'outputs/experiments/graphrag-2d3-fix2'
APPROVED = ROOT / 'outputs/review/mshta-ground-truth'
AUDIT = ROOT / 'outputs/review/graphrag-two-stage-gate-calibration/consumer_audit.json'
PUBLIC_SCOPE = {'platforms': ['windows'], 'mechanisms': ['process_creation']}
BUDGET = {'max_supplementary_items': 12, 'max_final_items': 64, 'max_serialized_bytes': 131072}
ARMS = {
    'E0': 'FIX2 parser + fixed FIX2 context + exact FIX2 checker/AND legacy',
    'E1': 'Parser v2 + fixed FIX2 evidence + v2 contract compatibility + AND legacy',
    'E2': 'FIX2 parser/checker + fixed FIX2 evidence + new combination guards/policy',
    'E3': 'Parser v2 + fixed FIX2 evidence + new combination policy',
    'E4': 'Parser v2 + recomputed unranked enrichment + new combination policy',
}
NEW_RUNTIME = tuple('src/threat_hunting/graphrag/' + name for name in (
    'query_requirements_v2.py', 'query_context_v2.py', 'query_support_v2.py', 'query_policy.py'))


def digest(path: Path) -> str:
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def read(path: Path) -> Any:
    return json.loads(path.read_text(encoding='utf-8'))


def encoded(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(',', ':')).encode('utf-8')


def write(name: str, value: object) -> None:
    path = OUT / name
    path.write_bytes((json.dumps(value, ensure_ascii=False, allow_nan=False, indent=2) + '\n').encode('utf-8'))
    assert read(path) == value


def old_helpers():
    """Reuse existing external diagnostics/metrics without editing their criteria."""
    spec = importlib.util.spec_from_file_location('fix2_external_evaluation_helpers', ROOT / 'scripts/evaluate_query_aware_gate.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def and_legacy_v2(context, requirements, legacy_policy, *, max_chain_depth):
    """Versioned requirement compatibility; retain old AND-quality semantics."""
    ranked = extract_graphrag_gate_signals(context['initial_context'])
    legacy = assess_graphrag_two_stage_gate(ranked, policy=legacy_policy)
    support = assess_evidence_support_v2(requirements, context, max_chain_depth=max_chain_depth)
    blockers = []
    scope = requirements['scope']['status']
    if scope == 'mismatch':
        blockers.append({'stage': 'topical_relevance', 'reason_code': 'requested_scope_mismatch'})
    elif scope == 'ambiguous':
        blockers.append({'stage': 'query_requirements', 'reason_code': 'query_scope_ambiguous'})
    if requirements['analysis_status'] != 'supported':
        blockers.append({'stage': 'query_requirements', 'reason_code': 'query_requirements_' + requirements['analysis_status']})
    if support['status'] != 'supported':
        blockers.append({'stage': 'evidence_answerability', 'reason_code': 'required_evidence_' + support['status']})
    if legacy['decision'] != 'proceed':
        blockers.append({'stage': legacy['abstention_stage'], 'reason_code': 'legacy_quality_gate_abstained'})
    return {'schema_version': 'query-aware-compatibility-decision/v2',
        'legacy_decision': legacy, 'query_requirements': requirements,
        'scope_assessment': requirements['scope'], 'support_assessment': support,
        'final_decision': 'abstain' if blockers else 'proceed',
        'abstention_stage': blockers[0]['stage'] if blockers else None,
        'reason_codes': [item['reason_code'] for item in blockers],
        'blockers': blockers, 'security_conclusion_made': False}


def context_metrics(context):
    items = context['final_items']
    return {'serialized_final_items_utf8_bytes': len(encoded(items)),
            'supplementary_item_count': len(context['supplementary_items']),
            'final_item_count': len(items), 'incomplete_context': context['incomplete_context']}


def load_inputs():
    before = read(OUT / 'preflight.json')['protected_hashes']
    for name, expected in before.items():
        if name.startswith(('src/', 'scripts/', 'tests/')) or name.startswith('outputs/experiments/graphrag-2d3-fix2/') or name.startswith('outputs/review/mshta-ground-truth/'):
            assert digest(ROOT / name) == expected, f'Protected FIX3 dependency changed: {name}'
    gt, answers, _ = load_approved_evaluation_bundle(APPROVED)
    corpus = load_retrieval_corpus(FIX1 / 'retrieval_corpus.json')
    graph = load_knowledge_graph(FIX1 / 'knowledge_graph.json')
    index = load_vector_index(FIX1 / 'vector_index.json')
    old_helpers().check_index_bindings(corpus, index, digest(FIX1 / 'retrieval_corpus.json'))
    assert corpus['source_ground_truth'] == graph['source_ground_truth']
    return gt, answers, corpus, graph


def main() -> int:
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    assert not (OUT / 'ablation_results.json').exists(), 'Refusing to overwrite completed FIX3 experiment'
    gt, answers, corpus, graph = load_inputs()
    helper = old_helpers()
    fixed_contexts = read(FIX2 / 'enriched_contexts.json')
    old_requirements = read(FIX2 / 'query_requirements.json')
    old_decisions = read(FIX2 / 'decisions.json')['D']
    legacy_policy = read(FIX2 / 'fixed_policy.json')
    policy = read(OUT / 'combined_policy.json')
    validate_combined_policy(policy)
    audit = read(AUDIT)
    units = audit['answer_units']
    assert all('known_absent_from_frozen_consumers' not in value for value in units.values())
    descriptors = {case['case_id']: case for case in audit['cases']}
    config = {'schema_version': 'parser-policy-fix3-experiment/v1', 'arms': ARMS,
        'public_source_scope': PUBLIC_SCOPE, 'context_budget': BUDGET,
        'combined_policy': policy, 'legacy_policy': legacy_policy,
        'policy_written_before_benchmark': True, 'policy_designs': 1,
        'threshold_sweep': False, 'model_calls': 0, 'proposed_probes': 0, 'heldout': False,
        'ranked_retrieval_source': 'FIX1 frozen ranked contexts retained within FIX2 evidence contexts',
        'fixed_context_evidence_unchanged_E0_E1_E2_E3': True,
        'verifier_compatibility': 'E1/E3/E4 use v2 chain/identity semantics; E2 retains v1 support with separate new policy hard guards',
        'source_hashes': {name: digest(FIX1 / name) for name in ('retrieval_corpus.json', 'knowledge_graph.json', 'vector_index.json')},
        'frozen_FIX2_contexts_sha256': digest(FIX2 / 'enriched_contexts.json'),
        'frozen_policy_sha256': digest(OUT / 'combined_policy.json'),
        'runtime_code_sha256': {name: digest(ROOT / name) for name in NEW_RUNTIME},
        'runner_sha256': digest(Path(__file__)), 'design_note_sha256': digest(OUT / 'design_note.md')}
    # Persist the lock before looking at any new arm result.
    write('experiment_configuration.json', config)
    write('pre_evaluation_freeze.json', {'combined_policy_sha256': config['frozen_policy_sha256'],
        'runtime_code_sha256': config['runtime_code_sha256'], 'runner_sha256': config['runner_sha256'],
        'design_note_sha256': config['design_note_sha256'], 'benchmark_results_existed': False})
    requirements = {arm: {} for arm in ARMS}
    contexts = {arm: {} for arm in ARMS}
    decisions = {arm: {} for arm in ARMS}
    diagnostics = {arm: {} for arm in ARMS}
    signals = {arm: {} for arm in ARMS}
    records = {arm: [] for arm in ARMS}
    for case in answers['cases']:
        identifier, query = case['case_id'], case['query']
        frozen = fixed_contexts[identifier]
        assert frozen['initial_context']['query']['text'] == query
        old_req = old_requirements[identifier]
        new_req = analyze_query_requirements_v2(query, scope_metadata=PUBLIC_SCOPE)
        upgraded = upgrade_evidence_context(frozen, corpus, graph)
        assert encoded(upgraded['final_items']) == encoded(frozen['final_items'])
        assert upgraded['initial_context'] == frozen['initial_context']
        enriched = enrich_query_context_v2(frozen['initial_context'], corpus, graph, new_req,
            budget=BUDGET, max_chain_depth=policy['max_chain_depth'])
        assert enriched == enrich_query_context_v2(frozen['initial_context'], corpus, graph, new_req,
            budget=BUDGET, max_chain_depth=policy['max_chain_depth'])
        original = assess_query_aware_gate(frozen, old_req, policy=legacy_policy)
        assert original == old_decisions[identifier]['trace']
        traces = {
            'E0': original,
            'E1': and_legacy_v2(upgraded, new_req, legacy_policy, max_chain_depth=policy['max_chain_depth']),
            'E2': assess_combined_query_gate(upgraded, old_req, corpus=corpus, graph=graph, policy=policy, legacy_policy=legacy_policy),
            'E3': assess_combined_query_gate(upgraded, new_req, corpus=corpus, graph=graph, policy=policy, legacy_policy=legacy_policy),
            'E4': assess_combined_query_gate(enriched, new_req, corpus=corpus, graph=graph, policy=policy, legacy_policy=legacy_policy),
        }
        for arm in ARMS:
            req = old_req if arm in ('E0', 'E2') else new_req
            context = frozen if arm == 'E0' else enriched if arm == 'E4' else upgraded
            trace = traces[arm]
            requirements[arm][identifier], contexts[arm][identifier] = req, context
            decisions[arm][identifier] = {'decision': trace['final_decision'],
                'abstention_stage': trace['abstention_stage'], 'reason_codes': trace['reason_codes'], 'trace': trace}
            ranked = extract_graphrag_gate_signals(context['initial_context'])
            assert ranked == original['signals']['ranked_retrieval']
            metrics = context_metrics(context)
            signals[arm][identifier] = {'schema_version': 'fix3-evidence-signals/v1', 'ranked_retrieval': ranked,
                                        'final_evidence_context': metrics}
            diagnostic = helper.external_diagnostic(context, descriptors[identifier], units, gt)
            diagnostics[arm][identifier] = diagnostic
            records[arm].append({'case_id': identifier, 'language': case['language'], 'category': case['category'],
                'expected_decision': case['expected_decision'], 'actual_decision': trace['final_decision'],
                'topical_relevant': descriptors[identifier]['topical_relevant'],
                'dataset_answerable': descriptors[identifier]['dataset_answerable'],
                'context_sufficient': diagnostic['context_sufficient'], 'context_sufficiency_basis': diagnostic['context_sufficiency_basis'],
                'gate_decision': trace['legacy_decision'], 'query_analysis_status': req['analysis_status'],
                'scope_status': req['scope']['status'], 'support_status': trace['support_assessment']['status'], 'context_metrics': metrics})
        logging.info('Compared E0–E4 development case %s', identifier)
    for name, expected in config['runtime_code_sha256'].items():
        assert digest(ROOT / name) == expected, 'Runtime code changed during evaluation'
    assert digest(OUT / 'combined_policy.json') == config['frozen_policy_sha256']
    summaries = {arm: helper.summarize_arm(values) for arm, values in records.items()}
    assert summaries['E0']['dataset_label_confusion_matrix'] == read(FIX2 / 'ablation_results.json')['summaries']['D']['dataset_label_confusion_matrix']
    transitions = [{
        'case_id': case['case_id'], 'language': case['language'], 'expected_decision': case['expected_decision'],
        'decisions': {arm: {key: decisions[arm][case['case_id']][key] for key in ('decision', 'abstention_stage', 'reason_codes')} for arm in ARMS},
        'from_E0': {arm: decisions['E0'][case['case_id']]['decision'] + '->' + decisions[arm][case['case_id']]['decision'] for arm in ('E1', 'E2', 'E3', 'E4')},
        'external_context_sufficiency': {arm: diagnostics[arm][case['case_id']]['context_sufficient'] for arm in ARMS},
    } for case in answers['cases']]
    for name, value in (('requirements.json', requirements), ('contexts.json', contexts), ('decisions.json', decisions),
        ('signals.json', signals), ('external_context_adjudication.json', diagnostics), ('evaluation_records.json', records), ('case_transitions.json', transitions)):
        write(name, value)
    write('ablation_results.json', {'schema_version': 'parser-policy-fix3-ablation/v1', 'arms': ARMS,
        'summaries': summaries, 'development_queries': 32, 'independent_validation': False,
        'policy_designs_evaluated': 1, 'model_calls': 0, 'proposed_probes': 0,
        'initial_contexts_identical_all_arms': True, 'E0_replay_matches_FIX2': True})
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
