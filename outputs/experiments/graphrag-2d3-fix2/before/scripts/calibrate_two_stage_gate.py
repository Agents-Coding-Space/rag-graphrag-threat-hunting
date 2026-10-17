"""Diagnostic calibration against frozen consumers; no production CLI policy.

The current query text is the only evaluation text sent to retrieval/embedding.
Labels, answers and expected evidence are joined after context/signals exist.
No held-out file is opened by any calibration phase.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any

from threat_hunting.evaluation.relevance_dataset import load_relevance_calibration_dataset
from threat_hunting.evaluation.two_stage_calibration import (
    SELECTION_RULE, build_split_manifest, canonical_sha256, evaluate_policy,
    freeze_policy, select_policy,
)
from threat_hunting.evaluation.two_stage_review import (
    audit_returned_context, load_approved_evaluation_bundle,
)
from threat_hunting.graph.schema import load_knowledge_graph
from threat_hunting.graphrag import build_graphrag_context, extract_graphrag_gate_signals
from threat_hunting.retrieval.embedding_backend import SentenceTransformerEmbeddingBackend
from threat_hunting.retrieval.schema import load_retrieval_corpus
from threat_hunting.retrieval.vector_schema import load_vector_index


ROOT = Path(__file__).resolve().parents[1]
REVIEW = ROOT / 'outputs/review/graphrag-two-stage-gate-calibration'
APPROVED = ROOT / 'outputs/review/mshta-ground-truth'
SOURCE_PATHS = {
    'ground_truth': 'outputs/review/mshta-ground-truth/scenario_ground_truth.json',
    'answers': 'outputs/review/mshta-ground-truth/reference_answers.json',
    'manifest': 'outputs/review/mshta-ground-truth/review_manifest.json',
    'dataset': 'outputs/review/mshta-ground-truth/mshta_relevance_calibration_reviewed.json',
    'corpus': 'outputs/retrieval/mshta-powershell/retrieval_corpus.json',
    'graph': 'outputs/graph/mshta-powershell/knowledge_graph.json',
    'index': 'outputs/evaluation/mshta-powershell/vector_index_multilingual_e5_small.json',
}


def file_sha256(path: Path) -> str:
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding='utf-8'))


def write_json(name: str, document: object) -> None:
    REVIEW.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(document, ensure_ascii=False, indent=2, allow_nan=False) + '\n'
    (REVIEW / name).write_text(payload, encoding='utf-8', newline='\n')
    assert read_json(REVIEW / name) == document


def load_sources() -> dict[str, Any]:
    snapshot = read_json(REVIEW / 'preflight.json')['protected_hashes']
    for relative in SOURCE_PATHS.values():
        if file_sha256(ROOT / relative) != snapshot[relative]:
            raise ValueError(f'Protected calibration source changed: {relative}')
    gt, answers, manifest = load_approved_evaluation_bundle(APPROVED)
    sources = {
        'ground_truth': gt, 'answers': answers, 'manifest': manifest,
        'dataset': load_relevance_calibration_dataset(ROOT / SOURCE_PATHS['dataset']),
        'corpus': load_retrieval_corpus(ROOT / SOURCE_PATHS['corpus']),
        'graph': load_knowledge_graph(ROOT / SOURCE_PATHS['graph']),
        'index': load_vector_index(ROOT / SOURCE_PATHS['index']),
    }
    answer_cases = {case['case_id']: case for case in answers['cases']}
    for case in sources['dataset']['cases']:
        approved_case = answer_cases.pop(case['case_id'])
        for field in ('query', 'category', 'expected_decision'):
            if case[field] != approved_case[field]:
                raise ValueError(f'Reviewed dataset and approved answers differ: {case["case_id"]}.{field}')
    if answer_cases:
        raise ValueError('Reviewed dataset is missing approved cases')
    return sources


def prepare(sources: dict[str, Any]) -> dict[str, Any]:
    audit = read_json(REVIEW / 'consumer_audit.json')
    descriptors = [{
        'case_id': case['case_id'], 'group_id': case['semantic_group'],
        'label_source': SOURCE_PATHS['answers'] + '#' + case['approved_answer_pointer'],
        'grouping_rationale': 'Same question intent and reviewed evidence; all exposed development groups remain calibration.',
    } for case in audit['cases']]
    groups = {case['group_id'] for case in descriptors}
    history = ['Embedding comparison/model selection on these 32 cases',
               'Legacy MiniLM calibration: 672 policies on all 32 cases',
               'Legacy E5 calibration: 672 policies on all 32 cases',
               'Technical review/error analysis and two wording corrections']
    split = build_split_manifest(
        descriptors, dataset_id=sources['dataset']['dataset_id'],
        dataset_sha256=file_sha256(ROOT / SOURCE_PATHS['dataset']),
        assignments={case['case_id']: 'calibration' for case in descriptors},
        usage_history={group: history for group in groups},
        split_rationale='All 32 cases previously exposed. No independent heldout partition exists; no reshuffling or paraphrase split.',
    )
    config = {
        'schema_version': 'two-stage-review-retrieval/v1',
        'sources': {key: {'path': path, 'sha256': file_sha256(ROOT / path)} for key, path in SOURCE_PATHS.items()},
        'consumer_ground_truth': sources['corpus']['source_ground_truth'],
        'evaluation_ground_truth': {'path': SOURCE_PATHS['ground_truth'], 'schema_version': sources['ground_truth']['schema_version'], 'sha256': file_sha256(ROOT / SOURCE_PATHS['ground_truth'])},
        'embedding': sources['index']['embedding'],
        'model_selection_status': 'Existing provisional E5 recommendation reused, no new model selection',
        'retrieval': {'top_k': 5, 'candidate_k': 20, 'chunk_types': None, 'required_dimensions': None},
        'fusion': {'method': 'reciprocal_rank_fusion', 'rrf_k': 60},
        'seed_mapping': 'Existing exact ID/JSON-pointer mapping, unchanged',
        'traversal': {'direction': 'both', 'max_depth': 2, 'allowed_edge_types': None, 'max_nodes': 100, 'max_edges': 200},
        'context_budget': {'retrieval_hits': 5, 'traversal_nodes': 100, 'traversal_edges': 200, 'additional_token_truncation': None},
        'runtime': {'device': 'cpu', 'offline': True, 'batch_size': 1, 'show_progress_bar': False},
        'query_input_boundary': 'Only the current query text is embedded/retrieved; never the question collection, answers, categories, decisions or expected evidence.',
    }
    selection_plan = {
        'schema_version': 'two-stage-calibration-selection-plan/v1',
        'selection_rule': SELECTION_RULE,
        'tunable_conditions': ['min_returned_top_cosine_score', 'min_query_token_coverage', 'min_hits_with_source_references'],
        'threshold_construction': 'No labels: cosine thresholds disabled plus empirical Q25/Q50/Q75 of returned top cosine; coverage zero or empirical median; source-reference hit minimum zero or one. At most 20 unique combinations, plus an all-abstain negative control.',
        'acceptance_criteria': {'max_false_proceed_unrelated': 0, 'max_false_proceed_insufficient_evidence': 0, 'min_retained_context_sufficient_positives': 1, 'allow_all_abstain_success': False, 'require_consumer_evidence_consistency': True, 'require_approved_independent_evaluation': True},
        'fixed_conditions': {'topical_relevance.min_retrieval_hit_count': 1, 'evidence_answerability.min_mapped_hit_count': 1, 'evidence_answerability.min_seed_node_count': 1, 'evidence_answerability.require_traversal': True},
        'disabled_condition_rationales': {
            'other_topical_counts': 'Counts largely saturate under fixed top5; no justified extra search dimension.',
            'rrf_bm25_thresholds': 'RRF is rank fusion and BM25 language dependent; no additional scale tuning on 32 exposed cases.',
            'other_evidence_and_traversal_minima': 'Graph density/counts do not prove query-specific evidence sufficiency.',
            'max_traversed_limitation_node_count': 'Limitations are necessary context; their presence must not be penalized.',
        },
        'qualification_blockers': audit['stale_evidence_findings'],
        'policy_qualified': False,
    }
    for name, document in [('split_manifest.json', split), ('retrieval_configuration.json', config), ('selection_plan.json', selection_plan)]:
        target = REVIEW / name
        if target.exists() and read_json(target) != document:
            raise ValueError(f'Predeclared configuration changed: {name}')
        write_json(name, document)
    return config


def collect_contexts(sources: dict[str, Any], config: dict[str, Any], *, embedder: Any = None) -> None:
    if (REVIEW / 'contexts.json').exists():
        raise ValueError('Contexts already collected; replay uses saved signals, never recollects/tunes heldout')
    model = config['embedding']
    snapshot = Path.home() / '.cache/huggingface/hub' / ('models--' + model['model_id'].replace('/', '--')) / 'snapshots' / model['model_revision']
    if embedder is None:
        if not (snapshot / 'modules.json').is_file():
            raise ValueError(f'Pinned offline model snapshot missing for {model["model_id"]}@{model["model_revision"]}')
        def factory(_model_id: str, *, revision: str, device: str) -> Any:
            if revision != model['model_revision']:
                raise ValueError('Model revision changed')
            for setting in ('HF_HUB_OFFLINE', 'TRANSFORMERS_OFFLINE', 'HF_HUB_DISABLE_TELEMETRY', 'HF_HUB_DISABLE_IMPLICIT_TOKEN', 'DO_NOT_TRACK'):
                os.environ[setting] = '1'
            from sentence_transformers import SentenceTransformer
            return SentenceTransformer(str(snapshot), device=device, local_files_only=True, token=False, trust_remote_code=False)
        embedder = SentenceTransformerEmbeddingBackend(
            model_id=model['model_id'], model_revision=model['model_revision'], dimension=model['dimension'],
            device='cpu', batch_size=1, show_progress_bar=False, model_factory=factory,
        )
    embeddings = {}
    def embed_query(texts: list[str]) -> object:
        # Existing vector retriever owns the query prefix. Cache exactly what it sent.
        if len(texts) != 1:
            raise ValueError('Expected one current query per embedding call')
        vectors = embedder.embed_documents(texts)
        embeddings[texts[0]] = vectors[0]
        return vectors
    contexts, signals = {}, {}
    for case in sources['dataset']['cases']:
        context = build_graphrag_context(
            sources['corpus'], sources['index'], sources['graph'], case['query'],
            corpus_sha256=config['sources']['corpus']['sha256'], embed_query=embed_query,
            **config['retrieval'], **config['traversal'],
        )
        contexts[case['case_id']] = context
        signals[case['case_id']] = extract_graphrag_gate_signals(context)
        logging.info('Collected returned context/signals: %s', case['case_id'])
    write_json('query_embeddings.json', {'input_contract': config['query_input_boundary'], 'embedding': model, 'vectors_by_exact_model_input': embeddings})
    write_json('contexts.json', contexts)
    write_json('signals.json', signals)


def generate_candidates(signals: dict[str, Any]) -> list[dict[str, Any]]:
    """Use only unlabeled observed signals; three explicitly named dimensions."""
    cosines = sorted(signal['topical_relevance']['returned_top_cosine_score'] for signal in signals.values() if signal['topical_relevance']['returned_top_cosine_score'] is not None)
    coverages = sorted(signal['topical_relevance']['query_token_coverage'] for signal in signals.values())
    if not cosines or not coverages:
        raise ValueError('Observed calibration signals are empty')
    def quantile(values: list[float], q: float) -> float:
        return values[int((len(values) - 1) * q)]
    cosine_grid = [None, *sorted({quantile(cosines, q) for q in (0.25, 0.5, 0.75)})]
    coverage_grid = sorted({0, quantile(coverages, 0.5)})
    policies = []
    for cosine in cosine_grid:
        for coverage in coverage_grid:
            for refs in (0, 1):
                policy = {
                    'schema_version': 'graphrag-two-stage-gate-policy/v1', 'policy_id': '',
                    'topical_relevance': {'min_retrieval_hit_count': 1, 'min_lexical_hit_count': 0, 'min_vector_hit_count': 0, 'min_joint_lexical_vector_hit_count': 0, 'min_query_token_coverage': coverage, 'min_returned_top_rrf_score': None, 'min_returned_top_bm25_score': None, 'min_returned_top_cosine_score': cosine},
                    'evidence_answerability': {'min_hits_with_evidence_ids': 0, 'min_hits_with_source_references': refs, 'min_unique_source_reference_count': 0, 'min_mapped_hit_count': 1, 'min_seed_node_count': 1, 'require_traversal': True, 'min_traversal_node_count': 0, 'min_traversal_edge_count': 0, 'min_traversal_path_count': 0, 'min_traversed_evidence_node_count': 0, 'min_support_edge_count': 0, 'max_traversed_limitation_node_count': None},
                }
                policy['policy_id'] = 'two-stage-dev-' + canonical_sha256({k: v for k, v in policy.items() if k != 'policy_id'})[:16]
                policies.append(policy)
    control = deepcopy(policies[0])
    control['policy_id'] = 'negative-control-all-abstain'
    control['topical_relevance']['min_returned_top_cosine_score'] = min(1.0, max(cosines) + 0.000001)
    policies.append(control)
    return policies


def evaluation_records(sources: dict[str, Any]) -> list[dict[str, Any]]:
    audit = read_json(REVIEW / 'consumer_audit.json')
    contexts, signals = read_json(REVIEW / 'contexts.json'), read_json(REVIEW / 'signals.json')
    missing_pointers = {pointer for finding in audit['stale_evidence_findings']
                        for pointer in finding.get('missing_approved_ground_truth_pointers', [])}
    for unit in audit['answer_units'].values():
        if unit['source_ground_truth_pointer'] in missing_pointers:
            unit['known_absent_from_frozen_consumers'] = True
    records = []
    for case in audit['cases']:
        requested_refs = {(item['source_file'], item['raw_record_ref']) for item in case['raw_reference_requirements']}
        case['expected_evidence_ids'] = [item['evidence_id'] for item in sources['ground_truth']['evidence']
                                         if requested_refs.intersection((ref['source_file'], ref['raw_record_ref']) for ref in item['source_references'])]
        diagnostic = audit_returned_context(contexts[case['case_id']], case, audit['answer_units'])
        records.append({
            'case_id': case['case_id'], 'signals': signals[case['case_id']],
            'category': case['category'], 'expected_decision': case['expected_decision'],
            'topical_relevant': case['topical_relevant'], 'dataset_answerable': case['dataset_answerable'],
            **{key: diagnostic[key] for key in ('context_sufficient', 'context_sufficiency_basis', 'missing_evidence_diagnostics', 'expected_evidence_ids', 'returned_evidence_ids')},
        })
    write_json('external_context_adjudication.json', {'status': 'AI_derived_conservative_support_rubric_not_new_human_labels', 'context_cannot_be_augmented_from_expected_evidence': True, 'cases': [{k: v for k, v in record.items() if k != 'signals'} for record in records]})
    return records


def calibrate(sources: dict[str, Any]) -> None:
    records = evaluation_records(sources)
    policies = generate_candidates(read_json(REVIEW / 'signals.json'))
    write_json('candidate_policies.json', policies)
    result = select_policy(policies, records, split_manifest=read_json(REVIEW / 'split_manifest.json'))
    result['qualification_blockers'] = read_json(REVIEW / 'consumer_audit.json')['stale_evidence_findings']
    result['interpretation'] = 'Development diagnostics on stale frozen consumers; no qualified or production-ready policy'
    chosen = result['selected_result']
    result['calibration_acceptance_failures'] = []
    if chosen is None:
        result['calibration_acceptance_failures'].append('No non-all-abstain candidate')
    else:
        for category, rate in chosen['summary']['false_proceed_by_category'].items():
            if rate['numerator']:
                result['calibration_acceptance_failures'].append('False proceed remains: ' + category)
        if not chosen['summary']['retained_context_sufficient_positives']:
            result['calibration_acceptance_failures'].append('No context-sufficient positives retained')
    result['meets_calibration_error_constraints'] = not result['calibration_acceptance_failures']
    write_json('calibration_results.json', result)
    write_json('selected_policy.json', result['selected_policy'])


def freeze_and_replay(sources: dict[str, Any]) -> None:
    result = read_json(REVIEW / 'calibration_results.json')
    policy = result['selected_policy']
    if policy is None:
        write_json('replay_result.json', {'status': 'not_run_no_nontrivial_policy', 'heldout_run': False})
        return
    code_paths = ['scripts/calibrate_two_stage_gate.py', *sorted(path.relative_to(ROOT).as_posix() for path in (ROOT / 'src/threat_hunting').rglob('*.py'))]
    code_hashes = {name: file_sha256(ROOT / name) for name in code_paths}
    code_digest = canonical_sha256(code_hashes)
    config, split, criteria, signals = (read_json(REVIEW / name) for name in ('retrieval_configuration.json', 'split_manifest.json', 'selection_plan.json', 'signals.json'))
    # Fingerprint quarantined bytes only in the freeze phase. No proposed label
    # or question is parsed or supplied to calibration/retrieval/gate execution.
    config = {**config, 'query_embeddings_sha256': file_sha256(REVIEW / 'query_embeddings.json'), 'external_context_adjudication_sha256': file_sha256(REVIEW / 'external_context_adjudication.json'), 'consumer_audit_sha256': file_sha256(REVIEW / 'consumer_audit.json'), 'quarantined_test_manifest_sha256': file_sha256(REVIEW / 'proposed_test_set.json')}
    frozen = freeze_policy(policy, retrieval_config=config, split_manifest=split,
                           evaluation_code_sha256=code_digest, criteria=criteria, calibration_signals=signals)
    write_json('frozen_retrieval_configuration.json', config)
    write_json('evaluation_code_hashes.json', code_hashes)
    write_json('policy_freeze.json', frozen)
    replay = evaluate_policy(evaluation_records(sources), policy=policy, split_manifest=split,
                             freeze=frozen, replay=True, retrieval_config=config, evaluation_code_sha256=code_digest,
                             criteria=criteria, calibration_signals=signals)
    if replay['cases'] != result['selected_result']['cases'] or replay['summary'] != result['selected_result']['summary']:
        raise ValueError('Frozen-policy replay differs from calibration observations')
    write_json('replay_result.json', {'status': 'identical_saved_signal_replay', 'independent_experiment': False, 'heldout_run': False, 'result': replay})
    write_json('heldout_status.json', {'status': 'not_run', 'reasons': ['All32 prior cases exposed to development', 'New AI-proposed stress probes lack human-approved labels and independent-core eligibility', 'Frozen consumers contain material stale evidence contradiction'], 'labels_approved': False, 'heldout_queries_embedded': 0, 'heldout_gate_calls': 0})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', choices=('prepare', 'collect', 'calibrate', 'freeze-replay'), required=True)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    sources = load_sources()
    config = prepare(sources)
    if args.phase == 'collect':
        collect_contexts(sources, config)
    elif args.phase == 'calibrate':
        calibrate(sources)
    elif args.phase == 'freeze-replay':
        freeze_and_replay(sources)
    logging.info('Completed phase %s; no production consumer modified', args.phase)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
