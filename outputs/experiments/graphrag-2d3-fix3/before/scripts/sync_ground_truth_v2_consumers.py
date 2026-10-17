"""Build isolated v2 evidence consumers and compare a fixed development policy.

No thresholds, policies, rubric criteria, production defaults or held-out cases
are changed. Builders receive Ground Truth only; evaluation labels are joined
after new returned contexts and gate signals have been collected.
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

from threat_hunting.evaluation.two_stage_calibration import evaluate_policy
from threat_hunting.evaluation.two_stage_review import audit_returned_context, load_approved_evaluation_bundle
from threat_hunting.graph import build_knowledge_graph, load_knowledge_graph
from threat_hunting.graphrag import build_graphrag_context, extract_graphrag_gate_signals
from threat_hunting.retrieval import (
    SentenceTransformerEmbeddingBackend, build_retrieval_corpus, build_vector_index,
    load_retrieval_corpus, load_vector_index,
)


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'outputs/experiments/graphrag-2d3-fix1'
BASE = ROOT / 'outputs/review/graphrag-two-stage-gate-calibration'
APPROVED = ROOT / 'outputs/review/mshta-ground-truth'
GT_RELATIVE = 'outputs/review/mshta-ground-truth/scenario_ground_truth.json'
FIXED_POLICY_ID = 'two-stage-dev-5a4b308b106699e0'
FOCUS_CASES = ('rd-vi-reviewed-scope-limitations', 'rp-vi-final-review-limits', 'rp-vi-service-action')


def digest(path: Path) -> str:
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def read(path: Path) -> Any:
    return json.loads(path.read_text(encoding='utf-8'))


def encoded(document: object) -> bytes:
    return (json.dumps(document, ensure_ascii=False, indent=2, allow_nan=False) + '\n').encode('utf-8')


def write(name: str, document: object) -> str:
    path = OUT / name
    payload = encoded(document)
    path.write_bytes(payload)
    assert read(path) == document, f'JSON readback failed: {name}'
    return hashlib.sha256(payload).hexdigest()


def verify_original(path: Path) -> None:
    before = read(OUT / 'preflight.json')['protected_hashes']
    relative = path.relative_to(ROOT).as_posix()
    if digest(path) != before[relative]:
        raise ValueError(f'Protected source differs from FIX1 baseline: {relative}')


def load_inputs() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    for path in [*(APPROVED / name for name in ('scenario_ground_truth.json', 'reference_answers.json', 'review_manifest.json')),
                 *(BASE / name for name in ('selected_policy.json', 'frozen_retrieval_configuration.json', 'consumer_audit.json', 'calibration_results.json', 'contexts.json', 'signals.json', 'external_context_adjudication.json', 'split_manifest.json'))]:
        verify_original(path)
    gt, answers, _ = load_approved_evaluation_bundle(APPROVED)
    if digest(APPROVED / 'scenario_ground_truth.json') != '8676d7a1df41058e7f4b1460a0d4bf909fca5d8f20992753e63be7d024268461':
        raise ValueError('Unexpected approved MSHTA Ground Truth version')
    config = read(BASE / 'frozen_retrieval_configuration.json')
    policy = read(BASE / 'selected_policy.json')
    if policy['policy_id'] != FIXED_POLICY_ID:
        raise ValueError('FIX1 requires the original fixed policy')
    # These algorithms/criteria are fixed; provenance allowlists may be extended.
    before = read(OUT / 'preflight.json')['protected_hashes']
    for name in ('src/threat_hunting/graphrag/two_stage_gate.py', 'src/threat_hunting/graphrag/gate_signals.py',
                 'src/threat_hunting/evaluation/two_stage_calibration.py', 'src/threat_hunting/evaluation/two_stage_review.py'):
        if digest(ROOT / name) != before[name]:
            raise ValueError(f'Fixed evaluator/rubric changed: {name}')
    return gt, answers, config, policy


def local_backend(embedding: dict[str, Any]) -> SentenceTransformerEmbeddingBackend:
    snapshot = Path.home() / '.cache/huggingface/hub' / ('models--' + embedding['model_id'].replace('/', '--')) / 'snapshots' / embedding['model_revision']
    if not (snapshot / 'modules.json').is_file():
        raise ValueError('Pinned local E5 snapshot is unavailable; no downloads are permitted')
    def factory(model_id: str, *, revision: str, device: str) -> Any:
        if model_id != embedding['model_id'] or revision != embedding['model_revision']:
            raise ValueError('Embedding identity changed')
        for setting in ('HF_HUB_OFFLINE', 'TRANSFORMERS_OFFLINE', 'HF_HUB_DISABLE_TELEMETRY', 'HF_HUB_DISABLE_IMPLICIT_TOKEN', 'DO_NOT_TRACK'):
            os.environ[setting] = '1'
        from sentence_transformers import SentenceTransformer
        return SentenceTransformer(str(snapshot), device=device, local_files_only=True, token=False, trust_remote_code=False)
    return SentenceTransformerEmbeddingBackend(
        model_id=embedding['model_id'], model_revision=embedding['model_revision'], dimension=embedding['dimension'],
        device='cpu', batch_size=1, show_progress_bar=False, model_factory=factory,
    )


def content_audit(gt: dict[str, Any], corpus: dict[str, Any], graph: dict[str, Any]) -> dict[str, Any]:
    """Check actual returned payload fields, not just provenance addresses."""
    chunks = {chunk['source']['json_pointer']: chunk for chunk in corpus['chunks']}
    nodes = {node['source']['json_pointer']: node for node in graph['nodes']}
    commands = []
    for index, fact in enumerate(gt['facts']):
        pointer = f'/facts/{index}'
        observations = fact['attributes'].get('source_observations', [])
        assert chunks[pointer]['metadata']['attributes'] == fact['attributes']
        assert nodes[pointer]['attributes']['attributes'] == fact['attributes']
        for observation in observations:
            fields = observation['original_fields']
            command = fields.get('CommandLine')
            if command:
                # Corpus content is serialized JSON: test escaped literal values.
                assert json.dumps(command, ensure_ascii=False) in chunks[pointer]['content']
                assert observation in nodes[pointer]['attributes']['attributes']['source_observations']
                commands.append({'source_pointer': pointer, 'raw_record_ref': observation['raw_record_ref'], 'CommandLine': command})
    for index, limitation in enumerate(gt['summary']['limitations']):
        pointer = f'/summary/limitations/{index}'
        assert limitation in chunks[pointer]['content']
        assert nodes[pointer]['label'] == limitation
    text = '\n'.join(chunk['content'] for chunk in corpus['chunks'])
    graph_text = json.dumps({'nodes': graph['nodes'], 'edges': graph['edges']}, ensure_ascii=False)
    for forbidden in ('PowerShell ran Get-Service sysmon', 'PowerShell runs Get-Service sysmon'):
        assert forbidden not in text and forbidden not in graph_text
    for value in (gt['review']['reviewer'], gt['review']['reviewed_at']):
        assert value not in json.dumps(corpus, ensure_ascii=False) and value not in json.dumps(graph, ensure_ascii=False)
    assert 'confirmed' not in [chunk['status'] for chunk in corpus['chunks']]
    assert all(item['status'] != 'confirmed' for item in [*graph['nodes'], *graph['edges']])
    return {'source_observation_values_preserved': True, 'original_commands': commands,
            'limitation_count': len(gt['summary']['limitations']), 'all_limitations_in_corpus_and_graph': True,
            'overstated_completion_wording_absent': True, 'source_approval_metadata_absent': True}


def build(*, backend: Any = None) -> None:
    gt, answers, config, _ = load_inputs()
    if any((OUT / name).exists() for name in ('retrieval_corpus.json', 'knowledge_graph.json', 'vector_index.json')):
        raise ValueError('FIX1 consumer outputs already exist; refusing to overwrite')
    source_hash = digest(APPROVED / 'scenario_ground_truth.json')
    corpus = build_retrieval_corpus(gt, source_ground_truth_path=GT_RELATIVE, source_ground_truth_sha256=source_hash)
    graph = build_knowledge_graph(gt, ground_truth_path=GT_RELATIVE, ground_truth_sha256=source_hash)
    assert corpus == build_retrieval_corpus(gt, source_ground_truth_path=GT_RELATIVE, source_ground_truth_sha256=source_hash)
    assert graph == build_knowledge_graph(gt, ground_truth_path=GT_RELATIVE, ground_truth_sha256=source_hash)
    audit = content_audit(gt, corpus, graph)
    # Evaluation data is used only for this external leakage check after building.
    runtime_text = json.dumps({'corpus': corpus, 'graph': graph}, ensure_ascii=False)
    for case in answers['cases']:
        for field in ('case_id', 'query', 'reference_answer'):
            assert case[field] not in runtime_text, f'Evaluation text leaked: {field}'
    audit['approved_case_ids_queries_answers_absent'] = True
    corpus_hash = write('retrieval_corpus.json', corpus)
    graph_hash = write('knowledge_graph.json', graph)
    embedding = deepcopy(config['embedding'])
    backend = backend if backend is not None else local_backend(embedding)
    observed_inputs, observed_vectors = [], []
    def embed_documents(texts: list[str]) -> object:
        expected = [embedding['document_prefix'] + chunk['content'] for chunk in sorted(corpus['chunks'], key=lambda item: item['chunk_id'])]
        if texts != expected:
            raise ValueError('Document embedding input differs from exact prefixed corpus content')
        vectors = backend.embed_documents(texts)
        observed_inputs.extend(texts)
        observed_vectors.extend(vectors)
        return vectors
    corpus_path = (OUT / 'retrieval_corpus.json').relative_to(ROOT).as_posix()
    index = build_vector_index(corpus, corpus_path=corpus_path, corpus_sha256=corpus_hash, embedding=embedding, embed_documents=embed_documents)
    # Exact-input in-run replay only; no old vector is attached to changed text.
    def replay_vectors(texts: list[str]) -> object:
        if texts != observed_inputs:
            raise ValueError('Determinism replay embedding inputs differ')
        return deepcopy(observed_vectors)
    assert index == build_vector_index(corpus, corpus_path=corpus_path, corpus_sha256=corpus_hash, embedding=embedding, embed_documents=replay_vectors)
    index_hash = write('vector_index.json', index)
    load_retrieval_corpus(OUT / 'retrieval_corpus.json')
    load_knowledge_graph(OUT / 'knowledge_graph.json')
    load_vector_index(OUT / 'vector_index.json')
    ids = {chunk['chunk_id'] for chunk in corpus['chunks']}
    assert ids == {record['chunk_id'] for record in index['records']} and len(ids) == len(index['records'])
    write('build_manifest.json', {
        'schema_version': 'graphrag-v2-consumer-sync-build/v1', 'experimental_only': True,
        'source_ground_truth': corpus['source_ground_truth'],
        'approved_bundle_hashes': {name: digest(APPROVED / name) for name in ('scenario_ground_truth.json', 'reference_answers.json', 'review_manifest.json')},
        'outputs': {'retrieval_corpus.json': corpus_hash, 'knowledge_graph.json': graph_hash, 'vector_index.json': index_hash},
        'embedding': embedding, 'preprocessing': config['runtime'],
        'embedding_cache': {'old_vector_reuse': False, 'document_cache_hits': 0, 'document_cache_misses': len(observed_inputs), 'determinism_replay_exact_input_hits': len(observed_inputs)},
        'counts': {'chunks': len(corpus['chunks']), 'nodes': len(graph['nodes']), 'edges': len(graph['edges']), 'vectors': len(index['records']), 'dimension': embedding['dimension']},
        'validation': {'approved_bundle': True, 'corpus_graph_source_identical': corpus['source_ground_truth'] == graph['source_ground_truth'], 'complete_vector_coverage': True, 'deterministic_builders': True},
        'content_audit': audit,
        'embedding_input_sha256': [hashlib.sha256(text.encode('utf-8')).hexdigest() for text in observed_inputs],
    })
    logging.info('Built %s chunks, %s graph nodes, %s fresh vectors', len(ids), len(graph['nodes']), len(index['records']))


def record_for_context(context: dict[str, Any], signals: dict[str, Any], descriptor: dict[str, Any], units: dict[str, Any], gt: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    case = deepcopy(descriptor)
    refs = {(item['source_file'], item['raw_record_ref']) for item in case['raw_reference_requirements']}
    case['expected_evidence_ids'] = [item['evidence_id'] for item in gt['evidence'] if refs.intersection((ref['source_file'], ref['raw_record_ref']) for ref in item['source_references'])]
    diagnostic = audit_returned_context(context, case, units)
    record = {'case_id': case['case_id'], 'signals': signals, 'category': case['category'], 'expected_decision': case['expected_decision'], 'topical_relevant': case['topical_relevant'], 'dataset_answerable': case['dataset_answerable'],
              **{key: diagnostic[key] for key in ('context_sufficient', 'context_sufficiency_basis', 'missing_evidence_diagnostics', 'expected_evidence_ids', 'returned_evidence_ids')}}
    return record, diagnostic


def pointer_value(document: object, pointer: str) -> object:
    value: Any = document
    for token in pointer.lstrip('/').split('/'):
        token = token.replace('~1', '/').replace('~0', '~')
        value = value[int(token)] if isinstance(value, list) else value[token]
    return value


def compare(*, backend: Any = None) -> None:
    gt, answers, old_config, policy = load_inputs()
    if (OUT / 'contexts.json').exists():
        raise ValueError('FIX1 contexts already collected; refusing to overwrite')
    manifest = read(OUT / 'build_manifest.json')
    for filename, expected in manifest['outputs'].items():
        assert digest(OUT / filename) == expected
    corpus, graph, index = load_retrieval_corpus(OUT / 'retrieval_corpus.json'), load_knowledge_graph(OUT / 'knowledge_graph.json'), load_vector_index(OUT / 'vector_index.json')
    config = {key: deepcopy(old_config[key]) for key in ('embedding', 'retrieval', 'fusion', 'seed_mapping', 'traversal', 'context_budget', 'runtime', 'query_input_boundary')}
    config.update(schema_version='graphrag-v2-consumer-sync-experiment/v1', fixed_policy={'path': 'outputs/review/graphrag-two-stage-gate-calibration/selected_policy.json', 'sha256': digest(BASE / 'selected_policy.json'), 'policy_id': FIXED_POLICY_ID},
                  sources={name: {'path': (OUT / name).relative_to(ROOT).as_posix(), 'sha256': digest(OUT / name)} for name in ('retrieval_corpus.json', 'knowledge_graph.json', 'vector_index.json')},
                  source_ground_truth=corpus['source_ground_truth'], intentional_changes=['Actual approved Ground Truth v2 source/provenance', 'Evidence content and fresh document embeddings synchronized', 'Strict supported-source compatibility'], no_threshold_search=True, no_heldout=True)
    write('experiment_configuration.json', config)
    write('fixed_policy.json', policy)
    backend = backend if backend is not None else local_backend(config['embedding'])
    model_inputs = []
    def embed_query(texts: list[str]) -> object:
        model_inputs.extend(texts)
        return backend.embed_documents(texts)
    audit = read(BASE / 'consumer_audit.json')
    # Keep the same semantic rubric. Old known-absent markers describe only the
    # old consumers; do not apply those stale factual assertions to a v2 build.
    units = deepcopy(audit['answer_units'])
    assert all('known_absent_from_frozen_consumers' not in unit for unit in units.values())
    descriptors = {item['case_id']: item for item in audit['cases']}
    contexts, signals, records, diagnostics = {}, {}, [], {}
    for case in answers['cases']:
        context = build_graphrag_context(corpus, index, graph, case['query'], corpus_sha256=manifest['outputs']['retrieval_corpus.json'], embed_query=embed_query, **config['retrieval'], **config['traversal'])
        signal = extract_graphrag_gate_signals(context)
        identifier = case['case_id']
        contexts[identifier], signals[identifier] = context, signal
        record, diagnostic = record_for_context(context, signal, descriptors[identifier], units, gt)
        records.append(record); diagnostics[identifier] = diagnostic
        logging.info('Collected new FIX1 context: %s', identifier)
    assert model_inputs == [config['embedding']['query_prefix'] + case['query'] for case in answers['cases']]
    split = read(BASE / 'split_manifest.json')
    result = evaluate_policy(records, policy=policy, split_manifest=split)
    result['evaluation_kind'] = 'fixed_policy_development_before_after_comparison'
    result['policy_qualified'] = False
    old = read(BASE / 'calibration_results.json')['selected_result']
    old_contexts = read(BASE / 'contexts.json')
    old_adjudication = {item['case_id']: item for item in read(BASE / 'external_context_adjudication.json')['cases']}
    previous = {item['case_id']: item for item in old['cases']}
    transitions = []
    for item in result['cases']:
        identifier = item['case_id']; before = previous[identifier]
        transitions.append({'case_id': identifier, 'expected_decision': item['expected_decision'],
                            'before': {'decision': before['actual_decision'], 'abstention_stage': before['gate_decision']['abstention_stage'], 'reason_codes': before['gate_decision']['reason_codes'], 'context_sufficient': before['context_sufficient']},
                            'after': {'decision': item['actual_decision'], 'abstention_stage': item['gate_decision']['abstention_stage'], 'reason_codes': item['gate_decision']['reason_codes'], 'context_sufficient': item['context_sufficient']},
                            'transition': before['actual_decision'] + '->' + item['actual_decision'],
                            'before_hit_sources': [hit['chunk']['source']['json_pointer'] for hit in old_contexts[identifier]['retrieval']['hits']],
                            'after_hit_sources': [hit['chunk']['source']['json_pointer'] for hit in contexts[identifier]['retrieval']['hits']],
                            'before_signals': before['signals'], 'after_signals': item['signals'],
                            'before_returned_evidence_ids': old_adjudication[identifier]['returned_evidence_ids'],
                            'after_returned_evidence_ids': diagnostics[identifier]['returned_evidence_ids'],
                            'after_missing_evidence': diagnostics[identifier]['missing_evidence_diagnostics']})
    all_context = {'retrieval': {'hits': [{'chunk': chunk} for chunk in corpus['chunks']]}, 'traversal': {'nodes': graph['nodes'], 'edges': graph['edges']}}
    focus = {}
    for identifier in FOCUS_CASES:
        full = audit_returned_context(all_context, descriptors[identifier], units)
        source_units = {unit_id: all(pointer_value(gt, field['pointer']) == field['value'] for field in units[unit_id]['required_ground_truth_fields'])
                        for unit_id in descriptors[identifier]['minimal_answer_unit_ids']}
        focus[identifier] = {'source_has_required_units': all(source_units.values()), 'source_unit_validation': source_units,
                             'all_consumer_payload_support': full,
                             'actual_returned_context_support': diagnostics[identifier],
                             'actual_hit_sources': [hit['chunk']['source']['json_pointer'] for hit in contexts[identifier]['retrieval']['hits']],
                             'context_evidence_not_injected': True,
                             'full_consumer_audit_not_supplied_to_runtime_gate': True}
    for name, document in [('contexts.json', contexts), ('signals.json', signals), ('decisions.json', result), ('context_adjudication.json', diagnostics), ('focus_case_analysis.json', focus), ('case_transitions.json', transitions)]:
        write(name, document)
    write('comparison.json', {'schema_version': 'graphrag-v2-consumer-sync-comparison/v1', 'fixed_policy_id': FIXED_POLICY_ID,
                               'before_summary': old['summary'], 'after_summary': result['summary'],
                               'policy_bytes_unchanged': encoded(policy) == (BASE / 'selected_policy.json').read_bytes(),
                               'retrieval_parameters_unchanged': True, 'evaluator_and_rubric_criteria_unchanged': True,
                               'query_embedding_cache': {'hits': 0, 'misses': len(model_inputs), 'old_context_or_signal_reuse': False},
                               'transition_counts': {kind: sum(item['transition'] == kind for item in transitions) for kind in ('proceed->proceed', 'proceed->abstain', 'abstain->proceed', 'abstain->abstain')},
                               'new_probe_queries_executed': 0, 'heldout_validation': False})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', required=True, choices=('build', 'compare'))
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    if args.phase == 'build':
        build()
    else:
        compare()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
