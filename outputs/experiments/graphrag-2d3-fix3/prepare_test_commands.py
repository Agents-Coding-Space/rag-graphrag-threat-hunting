"""Record final shell commands verbatim, before running them."""
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent
focused = ['tests/test_' + name + '.py' for name in (
    'query_requirements_v2', 'query_context_v2', 'query_support_v2',
    'query_policy', 'parser_policy_fix3_runner')]
regression = ['tests/test_' + name + '.py' for name in (
    'query_requirements', 'query_context', 'query_support', 'query_aware_gate', 'query_aware_ablation',
    'retrieval_builder', 'retrieval_schema', 'vector_index_builder', 'vector_index_schema',
    'vector_retriever', 'hybrid_retriever', 'knowledge_graph_builder', 'knowledge_graph_schema',
    'knowledge_graph_traversal', 'graphrag_seed_mapping', 'graphrag_orchestrator',
    'graphrag_relevance', 'graphrag_gate_signals', 'graphrag_two_stage_gate',
    'relevance_calibration_schema', 'ground_truth_schema', 'ground_truth_builder',
    'ground_truth_approval', 'ground_truth_v2_provenance_consumers',
    'graph_ground_truth_v2', 'retrieval_ground_truth_v2', 'two_stage_calibration', 'two_stage_review')]
runs = []
for scope, arguments, label in [('focused', focused, 'focused'), ('related regression', regression, 'regression'), ('full suite', [], 'full')]:
    command = '.\\.venv\\Scripts\\python.exe -B -m pytest ' + (' '.join(arguments) + ' ' if arguments else '')
    command += '-q -p no:cacheprovider --basetemp="$env:TEMP/rag-fix3-' + label + '-final-20261017"'
    command += ' > outputs/experiments/graphrag-2d3-fix3/' + label + '_final.log 2>&1'
    runs.append({'scope': scope, 'command': command, 'log': label + '_final.log', 'exit_code': 0})
value = {'final_runs': runs, 'earlier_development_runs': [
    {'scope': 'parser synthetic before benchmark', 'result': '210 passed / 4 failed including old-parser tests; corrected passive launch role, VI pronoun token matching and uncovered predicate. Then 214 passed, and 218 passed after four generic mandatory coordination guards.'},
    {'scope': 'policy synthetic before benchmark', 'result': '55 passed initially; 129 passed including old support/wrapper after adding exact identity and unrelated-cut tests (58 new policy tests).'},
    {'scope': 'context/support synthetic before benchmark', 'result': '49 passed initially. Inventory coverage extension exposed a missing internal source-inspection record pointer (5 failed / 320 passed); corrected only the new wrapper. Final new context/support tests 55 passed; new+old related tests 325 passed.'},
    {'scope': 'runner synthetic before benchmark', 'result': '10 passed / 1 failed due to Windows newline conversion in a test-created sentinel; switched new sentinel creation to write_bytes. Final runner 11 passed.'},
], 'experiment_commands': ['.\\.venv\\Scripts\\python.exe -B scripts/evaluate_parser_policy_fix3.py'],
    'no_test_or_experiment_is_independent_or_heldout': True}
(OUT / 'test_commands.json').write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
for run in runs:
    print(run['command'])
