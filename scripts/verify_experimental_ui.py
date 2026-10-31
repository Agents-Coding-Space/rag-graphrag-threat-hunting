"""Compare original evaluated operations, refactored harness and UI offline.

Requires only the locally cached pinned E5; never constructs a provider client.
Writes new demo evidence only, leaving the frozen 15x2 results untouched.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from threat_hunting.evaluation import experimental_comparison as pipeline
from threat_hunting.server.experimental import CONFIG, DEMO_IDS, ExperimentalRequest, ExperimentalSession


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--original-source', type=Path, help='Optional pre-refactor harness snapshot to verify unchanged behavior')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    os.environ['HF_HUB_OFFLINE'] = '1'
    os.environ['TRANSFORMERS_OFFLINE'] = '1'
    backend = None
    def backend_factory(**kw):
        nonlocal backend
        if backend is None:
            backend = pipeline.SentenceTransformerEmbeddingBackend(**kw)
        return backend
    def forbidden(**kw):
        raise AssertionError('No LLM API calls are permitted by this verification')
    runs = [('shared_harness', pipeline)]
    if args.original_source:
        spec = importlib.util.spec_from_file_location('threat_hunting.evaluation._pre_ui_harness', args.original_source)
        original = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(original)
        original.ROOT = ROOT
        runs.insert(0, ('original_harness', original))
    results = {}
    for name, module in runs:
        results[name] = module.run_comparison(CONFIG, args.output / name, case_ids=DEMO_IDS,
            embedding_factory=backend_factory, client_factory=forbidden)
    session = ExperimentalSession(args.output / 'ui_adapter', backend=backend, client_factory=forbidden)
    presets = session.presets()
    checks = []
    for preset in presets:
        for branch in pipeline.BRANCHES:
            response = session.run(ExperimentalRequest(query=preset['query'], scenario_id=preset['scenario_id'], branch=branch))
            case_key = f"{preset['case_id']}_{branch}"
            compared = {}
            for name, _ in runs:
                directory = args.output / name / case_key
                for artifact in ('scope', 'context', 'gate', 'messages', 'eligibility', 'evidence_contract'):
                    path = directory / f'{artifact}.json'
                    expected = json.loads(path.read_text(encoding='utf-8')) if path.exists() else None
                    actual = response[artifact]
                    compared[f'{name}/{artifact}'] = expected == actual
                harness_row = next(row for row in results[name]['rows'] if row['case_id'] == preset['case_id'] and row['branch'] == branch)
                compared[f'{name}/outcome'] = harness_row['outcome'] == response['outcome']
            checks.append({'case_id': preset['case_id'], 'branch': branch, 'outcome': response['outcome'],
                'eligibility': response['result'].get('eligibility_decision'), 'equal': compared,
                'llm_http_attempts': response['result']['llm_http_attempts'],
                'demo_response_directory': response['provenance']['directory']})
    summary = {'checks': checks, 'all_equal': all(all(c['equal'].values()) for c in checks),
        'llm_http_attempts': session.attempts + sum(r['llm_http_attempts'] for r in results.values()),
        'expected_live_requests_for_six_branches': sum(c['eligibility'] == 'proceed' for c in checks),
        'benchmark_result': False, 'human_review_required': True}
    pipeline._write(args.output / 'parity.json', summary)
    print(json.dumps(summary, ensure_ascii=True, indent=2))
    if not summary['all_equal'] or summary['llm_http_attempts']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
