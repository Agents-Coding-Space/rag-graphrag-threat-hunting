"""A/B/C/D development ablation on frozen FIX1 ranked retrieval contexts.

Labels, approved answers and the old AI rubric are loaded only in this research
runner. Pure runtime modules receive query text, public scope, corpus/graph and
actual returned items. No embedding/model, raw-log or held-out call is made.
"""
from __future__ import annotations

from collections import Counter
import argparse
from copy import deepcopy
import hashlib
import json
import logging
from pathlib import Path
import shutil
from typing import Any

from threat_hunting.evaluation.two_stage_calibration import ratio, summarize_cases
from threat_hunting.evaluation.two_stage_review import audit_returned_context, load_approved_evaluation_bundle
from threat_hunting.graph import load_knowledge_graph
from threat_hunting.graphrag.gate_signals import extract_graphrag_gate_signals
from threat_hunting.graphrag.query_context import DEFAULT_CONTEXT_BUDGET, enrich_query_context
from threat_hunting.graphrag.query_gate import assess_query_aware_gate, extract_query_evidence_signals
from threat_hunting.graphrag.query_requirements import analyze_query_requirements, DEFAULT_QUERY_VOCABULARY
from threat_hunting.graphrag.two_stage_gate import assess_graphrag_two_stage_gate
from threat_hunting.retrieval import load_retrieval_corpus, load_vector_index


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'outputs/experiments/graphrag-2d3-fix2'
BASE = ROOT / 'outputs/experiments/graphrag-2d3-fix1'
AUDIT = ROOT / 'outputs/review/graphrag-two-stage-gate-calibration/consumer_audit.json'
APPROVED = ROOT / 'outputs/review/mshta-ground-truth'
PUBLIC_SCOPE = {'platforms': ['windows'], 'mechanisms': ['process_creation']}
ARMS = {'A': 'FIX1 ranked context + old policy', 'B': 'enriched evidence context + old policy',
        'C': 'FIX1 context + query-aware scope/support AND old policy',
        'D': 'enriched context + query-aware scope/support AND old policy'}
RUNTIME_FILES = tuple('src/threat_hunting/graphrag/' + name for name in (
    'query_requirements.py', 'query_context.py', 'query_support.py', 'query_gate.py'))
RUN_OUTPUTS = ('experiment_configuration.json', 'fixed_policy.json', 'initial_contexts.json',
    'query_requirements.json', 'base_evidence_contexts.json', 'enriched_contexts.json',
    'signals.json', 'decisions.json', 'external_context_adjudication.json',
    'evaluation_records.json', 'case_transitions.json', 'ablation_results.json')


def digest(path: Path) -> str:
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def read(path: Path) -> Any:
    return json.loads(path.read_text(encoding='utf-8'))


def write(name: str, document: object) -> None:
    path = OUT / name
    payload = (json.dumps(document, ensure_ascii=False, allow_nan=False, indent=2) + '\n').encode('utf-8')
    path.write_bytes(payload)
    assert read(path) == document


def evaluation_context_projection(context: dict[str, Any]) -> dict[str, Any]:
    """Evaluation-only shape adapter for the unchanged external AI rubric.

    The legacy rubric inspects payloads through these collection paths; it does
    not use scores/ranks. This projection is not a runtime GraphRAG context and
    is never passed to retrieval, signals, support or gates. No item is invented.
    """
    items = context['final_items']
    return {
        'metadata': {'evaluation_only_projection': True, 'not_a_ranked_retrieval_result': True},
        'retrieval': {'hits': [{'chunk': deepcopy(item['payload'])} for item in items if item['kind'] == 'chunk']},
        'traversal': {plural: [deepcopy(item['payload']) for item in items if item['kind'] == kind]
                      for kind, plural in (('node', 'nodes'), ('edge', 'edges'))},
    }


def external_diagnostic(context: dict[str, Any], descriptor: dict[str, Any], units: dict[str, Any], gt: dict[str, Any]) -> dict[str, Any]:
    case = deepcopy(descriptor)
    refs = {(ref['source_file'], ref['raw_record_ref']) for ref in case['raw_reference_requirements']}
    case['expected_evidence_ids'] = [item['evidence_id'] for item in gt['evidence']
        if refs.intersection((ref['source_file'], ref['raw_record_ref']) for ref in item['source_references'])]
    return audit_returned_context(evaluation_context_projection(context), case, units)


def summarize_arm(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Reuse existing external dataset/context metrics, with explicit layer scope."""
    result = summarize_cases(records)
    result['layer_summary_semantics'] = 'unchanged_legacy_gate_stages; query_scope_support_counts_are_separate'
    result['by_language'] = {language: summarize_cases([case for case in records if case['language'] == language])
                             for language in sorted({case['language'] for case in records})}
    result['query_analysis_counts'] = dict(sorted(Counter(case['query_analysis_status'] for case in records).items()))
    result['scope_counts'] = dict(sorted(Counter(case['scope_status'] for case in records).items()))
    result['evidence_support_counts'] = dict(sorted(Counter(case['support_status'] for case in records).items()))
    result['unsupported_query_rate'] = ratio(sum(case['query_analysis_status'] == 'unsupported' for case in records), len(records))
    result['ambiguous_query_rate'] = ratio(sum(case['query_analysis_status'] == 'ambiguous' for case in records), len(records))
    result['unknown_support_rate'] = ratio(sum(case['support_status'] == 'unknown' for case in records), len(records))
    sizes = [case['context_metrics']['serialized_final_items_utf8_bytes'] for case in records]
    additions = [case['context_metrics']['supplementary_item_count'] for case in records]
    result['context'] = {
        'size_measurement': 'canonical_serialized_final_items_utf8_bytes_not_tokens',
        'min_bytes': min(sizes), 'max_bytes': max(sizes), 'mean_bytes': sum(sizes) / len(sizes),
        'supplementary_items_total': sum(additions), 'max_supplementary_items': max(additions),
        'incomplete_context_count': sum(case['context_metrics']['incomplete_context'] for case in records),
    }
    return result


def check_index_bindings(corpus: dict[str, Any], index: dict[str, Any], corpus_sha256: str) -> None:
    """Bind index records to exact corpus bytes and actual UTF-8 content."""
    assert index['corpus_provenance']['sha256'] == corpus_sha256
    assert index['corpus_provenance']['corpus_id'] == corpus['corpus_id']
    chunks = {item['chunk_id']: item for item in corpus['chunks']}
    assert len(index['records']) == len(chunks)
    assert set(chunks) == {item['chunk_id'] for item in index['records']}
    assert all(record['content_sha256'] == hashlib.sha256(
        chunks[record['chunk_id']]['content'].encode('utf-8')).hexdigest() for record in index['records'])


def load_inputs() -> tuple[dict[str, Any], ...]:
    before = read(OUT / 'preflight.json')['protected_hashes']
    names = [*(BASE / name for name in ('retrieval_corpus.json', 'knowledge_graph.json', 'vector_index.json',
             'fixed_policy.json', 'experiment_configuration.json', 'contexts.json', 'signals.json', 'decisions.json', 'comparison.json')),
             *(APPROVED / name for name in ('scenario_ground_truth.json', 'reference_answers.json', 'review_manifest.json')), AUDIT]
    for path in names:
        assert digest(path) == before[path.relative_to(ROOT).as_posix()], f'Protected FIX2 input changed: {path.name}'
    # This milestone must not alter any existing runtime/evaluation semantics.
    for name in before:
        if name.startswith('src/') and name.endswith('.py'):
            assert digest(ROOT / name) == before[name], f'Existing source changed: {name}'
    gt, answers, _ = load_approved_evaluation_bundle(APPROVED)
    corpus, graph, index = (load_retrieval_corpus(BASE / 'retrieval_corpus.json'),
                            load_knowledge_graph(BASE / 'knowledge_graph.json'),
                            load_vector_index(BASE / 'vector_index.json'))
    assert corpus['source_ground_truth'] == graph['source_ground_truth']
    check_index_bindings(corpus, index, digest(BASE / 'retrieval_corpus.json'))
    config = read(BASE / 'experiment_configuration.json')
    assert index['embedding'] == config['embedding']
    return gt, answers, corpus, graph, config


def archive_development_iteration() -> None:
    """Copy this runner's own previous results; never move/delete protected input."""
    target = OUT / 'iterations/initial'
    assert target.resolve().is_relative_to(OUT.resolve())
    assert not target.exists(), 'Refusing to overwrite an archived iteration'
    target.mkdir(parents=True)
    hashes = {}
    for name in RUN_OUTPUTS:
        path = OUT / name
        assert path.is_file(), f'Incomplete development iteration: {name}'
        shutil.copyfile(path, target / name)
        assert digest(path) == digest(target / name)
        hashes[name] = digest(path)
    (target / 'iteration_manifest.json').write_bytes((json.dumps({
        'kind': 'earlier_development_iteration_not_an_independent_experiment',
        'artifact_sha256': hashes,
        'reason_for_rerun': 'Generic parser invariant bugs: lost named constraints, unanchored process concept, uncovered requested positive claim',
        'threshold_search_or_new_probes': False,
        'initial_runtime_source_hashes_not_captured_at_run_time': True,
    }, indent=2) + '\n').encode('utf-8'))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive-development-iteration', action='store_true',
                        help='Preserve this runner\'s own earlier outputs before a documented development rerun')
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    if (OUT / 'ablation_results.json').exists():
        if not args.archive_development_iteration:
            raise ValueError('Refusing to overwrite an existing FIX2 evaluation')
        archive_development_iteration()
    gt, answers, corpus, graph, config = load_inputs()
    policy = read(BASE / 'fixed_policy.json')
    contexts = read(BASE / 'contexts.json')
    saved_signals = read(BASE / 'signals.json')
    saved_decisions = {case['case_id']: case for case in read(BASE / 'decisions.json')['cases']}
    audit = read(AUDIT)
    descriptors = {case['case_id']: case for case in audit['cases']}
    units = deepcopy(audit['answer_units'])
    assert all('known_absent_from_frozen_consumers' not in unit for unit in units.values())
    assert len(answers['cases']) == len(contexts) == len(descriptors) == 32
    experiment = {
        'schema_version': 'query-aware-gate-development-ablation/v1', 'arms': ARMS,
        'source_configuration': config, 'public_source_scope': PUBLIC_SCOPE,
        'scope_basis': 'Configured Windows process-creation source capability, not benchmark category',
        'vocabulary': DEFAULT_QUERY_VOCABULARY, 'context_budget': DEFAULT_CONTEXT_BUDGET,
        'quality_mode': 'require_legacy_proceed', 'policy': policy,
        'ranked_context_source': 'frozen FIX1 contexts; identical for all arms',
        'supplements_have_no_rank_scores_or_paths': True,
        'no_model_calls_no_index_rebuild_no_threshold_search': True,
        'no_heldout_no_proposed_probes': True,
        'external_evaluation': 'unchanged conservative AI rubric + approved dataset labels; support checker is not ground truth',
        'runtime_code_sha256': {name: digest(ROOT / name) for name in RUNTIME_FILES},
        'runner_sha256': digest(Path(__file__)),
        'input_hashes': {name: digest(BASE / name) for name in ('retrieval_corpus.json', 'knowledge_graph.json',
            'vector_index.json', 'fixed_policy.json', 'experiment_configuration.json', 'contexts.json', 'signals.json', 'decisions.json')},
    }
    write('experiment_configuration.json', experiment)
    write('fixed_policy.json', policy)
    requirements, base_evidence, enriched_evidence = {}, {}, {}
    signal_documents = {arm: {} for arm in ARMS}
    decisions = {arm: {} for arm in ARMS}
    diagnostics = {arm: {} for arm in ARMS}
    records = {arm: [] for arm in ARMS}
    for case in answers['cases']:
        identifier, query = case['case_id'], case['query']
        initial = contexts[identifier]
        assert initial['query']['text'] == query
        requested = analyze_query_requirements(query, scope_metadata=PUBLIC_SCOPE)
        requirements[identifier] = requested
        base = enrich_query_context(initial, corpus, graph, requested, enabled=False)
        enriched = enrich_query_context(initial, corpus, graph, requested)
        assert enriched == enrich_query_context(initial, corpus, graph, requested)
        assert base['initial_context'] == enriched['initial_context'] == initial
        base_evidence[identifier], enriched_evidence[identifier] = base, enriched
        for arm, evidence_context in (('A', base), ('B', enriched), ('C', base), ('D', enriched)):
            # Recompute even B/D: old v1 signals describe only ranked retrieval;
            # the new envelope separately describes actual supplemental evidence.
            signals = extract_query_evidence_signals(evidence_context)
            assert signals['ranked_retrieval'] == saved_signals[identifier]
            legacy = assess_graphrag_two_stage_gate(signals['ranked_retrieval'], policy=policy)
            assert legacy == saved_decisions[identifier]['gate_decision']
            checked = assess_query_aware_gate(evidence_context, requested, policy=policy)
            assert checked['legacy_decision'] == legacy
            if arm in ('A', 'B'):
                decision, stage, reasons = legacy['decision'], legacy['abstention_stage'], legacy['reason_codes']
            else:
                decision, stage, reasons = checked['final_decision'], checked['abstention_stage'], checked['reason_codes']
            # Support traces for A/B are diagnostics only, not old-policy input.
            decisions[arm][identifier] = {'decision': decision, 'abstention_stage': stage,
                'reason_codes': reasons, 'query_aware_checks_enforced': arm in ('C', 'D'), 'trace': checked}
            signal_documents[arm][identifier] = signals
            diagnostic = external_diagnostic(evidence_context, descriptors[identifier], units, gt)
            diagnostics[arm][identifier] = diagnostic
            records[arm].append({
                'case_id': identifier, 'language': case['language'], 'category': case['category'],
                'expected_decision': case['expected_decision'], 'actual_decision': decision,
                'topical_relevant': descriptors[identifier]['topical_relevant'],
                'dataset_answerable': descriptors[identifier]['dataset_answerable'],
                'context_sufficient': diagnostic['context_sufficient'],
                'context_sufficiency_basis': diagnostic['context_sufficiency_basis'],
                'gate_decision': legacy,
                'query_analysis_status': requested['analysis_status'], 'scope_status': requested['scope']['status'],
                'support_status': checked['support_assessment']['status'],
                'context_metrics': signals['final_evidence_context'],
            })
        logging.info('Ablated development query %s', identifier)
    summary = {arm: summarize_arm(members) for arm, members in records.items()}
    assert all(digest(ROOT / name) == expected for name, expected in experiment['runtime_code_sha256'].items()), 'Runtime source changed during ablation'
    assert summary['A']['dataset_label_confusion_matrix'] == read(BASE / 'comparison.json')['after_summary']['dataset_label_confusion_matrix']
    transitions = [{
        'case_id': case['case_id'], 'language': case['language'], 'expected_decision': case['expected_decision'],
        'decisions': {arm: {key: decisions[arm][case['case_id']][key] for key in ('decision', 'abstention_stage', 'reason_codes')} for arm in ARMS},
        'from_A': {arm: decisions['A'][case['case_id']]['decision'] + '->' + decisions[arm][case['case_id']]['decision'] for arm in ('B', 'C', 'D')},
        'external_context_sufficiency': {arm: diagnostics[arm][case['case_id']]['context_sufficient'] for arm in ARMS},
    } for case in answers['cases']]
    for name, value in (('initial_contexts.json', contexts), ('query_requirements.json', requirements),
                        ('base_evidence_contexts.json', base_evidence), ('enriched_contexts.json', enriched_evidence),
                        ('signals.json', signal_documents), ('decisions.json', decisions),
                        ('external_context_adjudication.json', diagnostics), ('evaluation_records.json', records),
                        ('case_transitions.json', transitions)):
        write(name, value)
    write('ablation_results.json', {'schema_version': 'query-aware-ablation-results/v1', 'arms': ARMS, 'summaries': summary,
        'development_case_count': 32, 'independent_validation': False,
        'new_probe_queries_executed': 0, 'model_calls': 0, 'threshold_candidates_evaluated': 0,
        'ranked_context_and_old_policy_unchanged': True,
        'B_uses_final_context_evidence_but_old_policy_reads_only_ranked_signals': True,
        'query_aware_support_is_not_external_ground_truth': True})
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
