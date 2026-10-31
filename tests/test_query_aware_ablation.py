"""External evaluation adapter tests; these are development tests, not held-out."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import hashlib
import json

import pytest

from threat_hunting.evaluation.two_stage_review import audit_returned_context


def _module():
    path = Path(__file__).resolve().parents[1] / 'scripts/evaluate_query_aware_gate.py'
    spec = importlib.util.spec_from_file_location('query_aware_development_runner', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _context():
    return {'final_items': [
        {'kind': 'chunk', 'item_id': 'limitation-1', 'origin': 'supplementary', 'payload': {
            'chunk_id': 'limitation-1', 'chunk_type': 'limitation', 'content': 'Only the fictional record was inspected.',
            'status': 'reviewable', 'source': {'object_type': 'limitation', 'json_pointer': '/summary/limitations/0'},
            'metadata': {}, 'evidence_ids': [], 'source_references': []}},
        {'kind': 'node', 'item_id': 'entity-1', 'origin': 'traversal', 'payload': {
            'node_id': 'entity-1', 'node_type': 'entity', 'label': 'Synthetic item',
            'attributes': {}, 'status': 'observed', 'source': {'object_type': 'entity', 'json_pointer': '/entities/0'},
            'evidence_ids': [], 'source_references': []}},
    ]}


def test_projection_transports_exact_payloads_without_scores_ranks_or_new_evidence():
    context = _context()
    original = deepcopy(context)
    result = _module().evaluation_context_projection(context)
    assert context == original
    assert result['retrieval']['hits'] == [{'chunk': context['final_items'][0]['payload']}]
    assert result['traversal'] == {'nodes': [context['final_items'][1]['payload']], 'edges': []}
    assert result['metadata']['evaluation_only_projection'] is True
    assert result['metadata']['not_a_ranked_retrieval_result'] is True
    assert set(result['retrieval']['hits'][0]) == {'chunk'}
    result['retrieval']['hits'][0]['chunk']['content'] = 'Caller mutation'
    assert context == original


def test_unchanged_external_rubric_requires_actual_added_limitation_content():
    module = _module()
    context = _context()
    descriptor = {'category': 'relevant_direct', 'minimal_answer_unit_ids': ['scope'], 'expected_evidence_ids': []}
    units = {'scope': {'source_ground_truth_pointer': '/summary/limitations/0', 'required_ground_truth_fields': [
        {'pointer': '/summary/limitations/0', 'value': 'Only the fictional record was inspected.'}]}}
    present = audit_returned_context(module.evaluation_context_projection(context), descriptor, units)
    assert present['context_sufficient'] is True
    context['final_items'].pop(0)
    # Expected pointers and values remain in the external rubric; neither can
    # replace the absent payload or make a runtime evidence item appear.
    absent = audit_returned_context(module.evaluation_context_projection(context), descriptor, units)
    assert absent['context_sufficient'] is None
    assert absent['missing_answer_units'] == ['scope']


def test_projection_is_not_accepted_as_a_legacy_runtime_context():
    import pytest
    from threat_hunting.graphrag.gate_signals import GraphRAGGateSignalError, extract_graphrag_gate_signals
    projection = _module().evaluation_context_projection(_context())
    with pytest.raises(GraphRAGGateSignalError):
        extract_graphrag_gate_signals(projection)


@pytest.mark.parametrize('mutation', [None, 'content', 'missing', 'duplicate', 'corpus_hash'])
def test_index_binding_uses_actual_chunk_content_and_exact_coverage(mutation):
    root = Path(__file__).resolve().parents[1]
    path = root / 'tests/fixtures/retrieval/builder/expected_retrieval_corpus.json'
    corpus = json.loads(path.read_text(encoding='utf-8'))
    index = json.loads((root / 'tests/fixtures/retrieval/vector_builder/expected_vector_index.json').read_text(encoding='utf-8'))
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if mutation == 'content':
        corpus['chunks'][0]['content'] += ' Changed fixture content.'
    elif mutation == 'missing':
        index['records'].pop()
    elif mutation == 'duplicate':
        index['records'][-1] = deepcopy(index['records'][0])
    elif mutation == 'corpus_hash':
        digest = 'f' * 64
    if mutation is None:
        _module().check_index_bindings(corpus, index, digest)
    else:
        with pytest.raises(AssertionError):
            _module().check_index_bindings(corpus, index, digest)


def test_development_archive_preserves_inputs_and_refuses_existing_archive(tmp_path, monkeypatch):
    module = _module()
    monkeypatch.setattr(module, 'OUT', tmp_path)
    expected = {}
    for name in module.RUN_OUTPUTS:
        payload = json.dumps({'synthetic_output': name}).encode('utf-8')
        (tmp_path / name).write_bytes(payload)
        expected[name] = payload
    (tmp_path / 'preflight.json').write_bytes(b'{"protected": true}')
    module.archive_development_iteration()
    assert (tmp_path / 'preflight.json').read_bytes() == b'{"protected": true}'
    for name, payload in expected.items():
        assert (tmp_path / name).read_bytes() == payload
        assert (tmp_path / 'iterations/initial' / name).read_bytes() == payload
    with pytest.raises(AssertionError, match='overwrite an archived iteration'):
        module.archive_development_iteration()
