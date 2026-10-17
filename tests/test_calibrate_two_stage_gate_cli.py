"""Review runner contracts with synthetic contexts and fake local embeddings."""
from __future__ import annotations

from copy import deepcopy
import importlib.util
import json
from pathlib import Path

import pytest

from threat_hunting.graphrag.two_stage_gate import _validated_policy


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def runner():
    spec = importlib.util.spec_from_file_location('two_stage_review_runner', ROOT / 'scripts/calibrate_two_stage_gate.py')
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_candidates_have_all_conditions_and_only_three_tuned_dimensions(runner) -> None:
    signals = {str(i): {'topical_relevance': {'returned_top_cosine_score': value,
                                             'query_token_coverage': value}}
               for i, value in enumerate((0.1, 0.2, 0.4, 0.8))}
    before = deepcopy(signals)
    policies = runner.generate_candidates(signals)
    assert 1 < len(policies) <= 21
    assert signals == before
    allowed = {'min_returned_top_cosine_score', 'min_query_token_coverage', 'min_hits_with_source_references'}
    for policy in policies:
        _validated_policy(policy)
        assert len(policy['topical_relevance']) == 8
        assert len(policy['evidence_answerability']) == 12
        for stage in ('topical_relevance', 'evidence_answerability'):
            for key, value in policy[stage].items():
                if key not in allowed:
                    assert value == policies[0][stage][key]
    renamed = {'opaque-' + name: document for name, document in reversed(list(signals.items()))}
    assert runner.generate_candidates(renamed) == policies


def test_collection_embeds_only_current_query_never_labels_answers_or_expected_evidence(runner, monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(runner, 'REVIEW', tmp_path)
    observed_model_inputs = []
    observed_runtime_inputs = []
    written = {}
    class FakeEmbedder:
        def embed_documents(self, texts):
            observed_model_inputs.extend(texts)
            return [[1.0, 0.0] for _ in texts]
    def fake_context(corpus, index, graph, query, *, embed_query, **kwargs):
        observed_runtime_inputs.append((corpus, index, graph, query, kwargs))
        embed_query(['query: ' + query])
        return {'returned_only': query}
    monkeypatch.setattr(runner, 'build_graphrag_context', fake_context)
    monkeypatch.setattr(runner, 'extract_graphrag_gate_signals', lambda ctx: {'returned_only': ctx['returned_only']})
    monkeypatch.setattr(runner, 'write_json', lambda name, document: written.update({name: deepcopy(document)}))
    sources = {
        'dataset': {'cases': [{'case_id': 'dev', 'query': 'actual runtime query',
                               'expected_decision': 'DO_NOT_EMBED_LABEL',
                               'expected_answers': ['DO_NOT_EMBED_ANSWER'],
                               'relevant_source_pointers': ['DO_NOT_INJECT_EVIDENCE']}]},
        'answers': {'heldout_oracle': 'NEVER_RUNTIME'},
        'corpus': {'existing': 'corpus'}, 'index': {'existing': 'index'}, 'graph': {'existing': 'graph'},
    }
    config = {'embedding': {'model_id': 'synthetic/local', 'model_revision': 'a' * 40},
              'sources': {'corpus': {'sha256': 'b' * 64}},
              'query_input_boundary': 'current query only', 'retrieval': {}, 'traversal': {}}
    runner.collect_contexts(sources, config, embedder=FakeEmbedder())
    assert observed_model_inputs == ['query: actual runtime query']
    assert observed_runtime_inputs[0][:4] == (sources['corpus'], sources['index'], sources['graph'], 'actual runtime query')
    assert 'DO_NOT_' not in json.dumps(written)
    assert 'NEVER_RUNTIME' not in json.dumps(written)
    assert written['signals.json'] == {'dev': {'returned_only': 'actual runtime query'}}


def test_collection_refuses_to_recollect_contexts(runner, monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(runner, 'REVIEW', tmp_path)
    (tmp_path / 'contexts.json').write_text('{}', encoding='utf-8')
    with pytest.raises(ValueError, match='already collected'):
        runner.collect_contexts({}, {}, embedder=object())
