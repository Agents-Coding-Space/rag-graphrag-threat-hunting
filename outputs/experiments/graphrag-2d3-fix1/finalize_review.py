"""Verify preserved bytes and package the isolated FIX1 experiment for review."""
from __future__ import annotations

import argparse
from collections import Counter
import difflib
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import platform
import subprocess
from zipfile import ZipFile

from threat_hunting.evaluation.review_package import create_review_zip, verify_review_zip
from threat_hunting.evaluation.two_stage_review import load_approved_evaluation_bundle
from threat_hunting.graph import build_knowledge_graph, load_knowledge_graph
from threat_hunting.graphrag import (
    assess_graphrag_two_stage_gate, extract_graphrag_gate_signals,
    validate_graphrag_gate_signals,
)
from threat_hunting.retrieval import build_retrieval_corpus, load_retrieval_corpus, load_vector_index


ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
REVIEW = ROOT / 'outputs/review/graphrag-ground-truth-v2-consumer-sync'
ZIP = ROOT / 'outputs/review/graphrag_ground_truth_v2_consumer_sync_review.zip'
MODIFIED_SOURCE = (
    'src/threat_hunting/evaluation/calibration_schema.py',
    'src/threat_hunting/graph/builder.py', 'src/threat_hunting/graph/schema.py',
    'src/threat_hunting/graphrag/relevance.py',
    'src/threat_hunting/retrieval/builder.py', 'src/threat_hunting/retrieval/schema.py',
)
NEW_SOURCE = (
    'scripts/sync_ground_truth_v2_consumers.py',
    'tests/test_graph_ground_truth_v2.py',
    'tests/test_ground_truth_v2_provenance_consumers.py',
    'tests/test_retrieval_ground_truth_v2.py',
    'tests/test_sync_ground_truth_v2_consumers.py',
)


def digest(path: Path) -> str:
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def read(path: Path) -> object:
    return json.loads(path.read_text(encoding='utf-8'))


def write(path: Path, document: object) -> None:
    path.write_bytes((json.dumps(document, ensure_ascii=False, indent=2, allow_nan=False) + '\n').encode('utf-8'))
    assert read(path) == document


def git(*arguments: str) -> str:
    return subprocess.check_output(['git', *arguments], cwd=ROOT, text=True, encoding='utf-8')


def protected_audit() -> dict:
    baseline = read(OUT / 'preflight.json')
    assert git('branch', '--show-current').strip() == baseline['branch']
    assert git('rev-parse', 'HEAD').strip() == baseline['head']
    assert not git('diff', '--cached', '--name-only')
    entries, changed = {}, []
    for name, before in baseline['protected_hashes'].items():
        after = digest(ROOT / name)
        entries[name] = {'before': before, 'after': after, 'unchanged': before == after}
        if before != after:
            changed.append(name)
    assert set(changed) <= {*MODIFIED_SOURCE, 'PROJECT_PROGRESS.md'}, changed
    assert all(name in changed for name in MODIFIED_SOURCE)
    # Existing Markdown bytes are preserved; progress may only gain an appendix.
    for name in ('AGENTS.md', 'PROJECT_CONTEXT.md', 'README.md'):
        assert entries[name]['unchanged']
    old_progress = (OUT / 'before/PROJECT_PROGRESS.md').read_bytes()
    assert (ROOT / 'PROJECT_PROGRESS.md').read_bytes().startswith(old_progress)
    current_files = set(git('ls-files', '--cached', '--others', '--exclude-standard').splitlines())
    assert current_files - set(baseline['protected_hashes']) == set(NEW_SOURCE)
    return {
        'schema_version': 'graphrag-v2-consumer-sync-protected-hashes/v1',
        'baseline_file_count': len(entries), 'unchanged_count': len(entries) - len(changed),
        'changed_existing_files': changed,
        'allowed_existing_changes_only': True, 'progress_baseline_bytes_preserved_as_prefix': True,
        'all_raw_inputs_approved_bundle_old_consumers_and_review_artifacts_unchanged': all(
            item['unchanged'] for name, item in entries.items() if name.startswith(('data/', 'outputs/'))
        ),
        'entries': entries,
    }


def validate_new_outputs() -> dict:
    gt, answers, _ = load_approved_evaluation_bundle(ROOT / 'outputs/review/mshta-ground-truth')
    corpus = load_retrieval_corpus(OUT / 'retrieval_corpus.json')
    graph = load_knowledge_graph(OUT / 'knowledge_graph.json')
    index = load_vector_index(OUT / 'vector_index.json')
    manifest = read(OUT / 'build_manifest.json')
    for name, expected in manifest['outputs'].items():
        assert digest(OUT / name) == expected
    assert corpus['source_ground_truth'] == graph['source_ground_truth']
    assert corpus['source_ground_truth']['schema_version'] == gt['schema_version']
    assert len(index['records']) == len(corpus['chunks'])
    assert {record['chunk_id'] for record in index['records']} == {chunk['chunk_id'] for chunk in corpus['chunks']}
    contexts, signals = read(OUT / 'contexts.json'), read(OUT / 'signals.json')
    decisions, policy = read(OUT / 'decisions.json'), read(OUT / 'fixed_policy.json')
    case_ids = {case['case_id'] for case in answers['cases']}
    assert set(contexts) == set(signals) == case_ids
    by_id = {case['case_id']: case for case in decisions['cases']}
    assert set(by_id) == case_ids and len(by_id) == 32
    for identifier in sorted(case_ids):
        assert extract_graphrag_gate_signals(contexts[identifier]) == signals[identifier]
        validate_graphrag_gate_signals(signals[identifier])
        assert assess_graphrag_two_stage_gate(signals[identifier], policy=policy) == by_id[identifier]['gate_decision']
        assert by_id[identifier]['gate_decision']['metadata']['security_conclusion_made'] is False
    legacy_v1 = {}
    for name, builder in (
        ('outputs/retrieval/mshta-powershell/retrieval_corpus.json', build_retrieval_corpus),
        ('outputs/graph/mshta-powershell/knowledge_graph.json', build_knowledge_graph),
    ):
        old = read(ROOT / name)
        source = old['source_ground_truth']
        legacy_gt = read(ROOT / source['path'])
        assert source['schema_version'] == legacy_gt['schema_version'] == 'scenario-ground-truth/v1'
        options = ({'source_ground_truth_path': source['path'], 'source_ground_truth_sha256': source['sha256']}
                   if builder is build_retrieval_corpus else {'ground_truth_path': source['path'], 'ground_truth_sha256': source['sha256']})
        assert builder(legacy_gt, **options) == old
        legacy_v1[name] = True
    json_files = []
    for path in sorted(OUT.glob('*.json')):
        read(path)
        json_files.append(path.name)
    limits = {f'/summary/limitations/{number}' for number in range(len(gt['summary']['limitations']))}
    returned_limits = Counter()
    returned_facts = Counter()
    for context in contexts.values():
        returned = {hit['chunk']['source']['json_pointer'] for hit in context['retrieval']['hits']}
        returned.update(node['source']['json_pointer'] for node in context['traversal']['nodes'])
        returned_limits.update(returned & limits)
        returned_facts.update(returned & {'/facts/0', '/facts/1'})
    return {
        'json_readback_files': json_files, 'bundle_consumer_index_validators_passed': True,
        'actual_legacy_v1_rebuild_identical_to_existing_consumers': legacy_v1,
        'saved_context_signal_and_decision_replay_matches': True,
        'replay_is_saved_output_verification_not_an_independent_experiment': True,
        'development_cases': len(case_ids),
        'actual_context_return_counts_by_limitation': {pointer: returned_limits[pointer] for pointer in sorted(limits)},
        'actual_context_return_counts_by_fact': dict(sorted(returned_facts.items())),
        'no_gate_or_signal_algorithm_changed': True,
    }


def append_progress() -> None:
    tests = read(REVIEW / 'tests.json')
    full = next(run for run in tests['final_runs'] if run['scope'] == 'full suite')
    assert full['exit_code'] == 0 and full['failed'] == 0
    progress = ROOT / 'PROJECT_PROGRESS.md'
    original = (OUT / 'before/PROJECT_PROGRESS.md').read_bytes()
    assert progress.read_bytes() == original, 'Refusing duplicate or non-baseline progress appendix'
    appendix = f'''
## 11. Checkpoint GRAPHRAG-2D3-FIX1 — 16/10/2026

Theo yêu cầu FIX1, đã đồng bộ evidence consumers thử nghiệm với Ground Truth v2 được duyệt. Giữ nguyên toàn bộ bytes của checkpoint cũ phía trên. Branch vẫn `feature/mshta-evidence-extractor`, HEAD `af2243a3ee89c5e5721ec341eea0a8cb06814f41`, staging rỗng. Không sửa approved bundle, raw data hoặc consumer/review artifacts cũ.

Sáu compatibility source files được sửa: `retrieval/builder.py`, `retrieval/schema.py`, `graph/builder.py`, `graph/schema.py`, `graphrag/relevance.py`, `evaluation/calibration_schema.py`. Hỗ trợ đúng GT v1/v2, provenance ghi phiên bản thực tế, v1 golden outputs giữ nguyên; downstream schema v1 không đổi. Không đưa human approval hoặc benchmark questions/answers/labels/case IDs/rubric vào evidence embeddings hay runtime gate inputs.

Builders thực tế tạo `outputs/experiments/graphrag-2d3-fix1/`: 22 chunks, graph 20 nodes/21 edges, 22 vectors mới dimension 384. Nguồn là approved GT SHA-256 `8676d7a1df41058e7f4b1460a0d4bf909fca5d8f20992753e63be7d024268461`. Corpus mới `b57ffad3d1e3b797e1b5fae7360b605a67acbecede8fb98ce8faf6f993cc695c`; graph `04d6efd2ca47388689ad376766f96f9136a9a8f4ef22403b4bc1ed4ff30ae443`; index `2182baefb9598609c5e1e9a92ac370b366e0fcab79e8d672ac64adcb7717ae78`. Giữ E5 local revision `614241f622f53c4eeff9890bdc4f31cfecc418b3`, prefixes, L2/cosine và preprocessing cũ; 0 old-cache hits, 22 document và 32 query misses. Determinism replay chỉ dùng đúng inputs/vectors của cùng lần build.

Source observations giữ nguyên CommandLine, parent/child fields, IDs và raw references trong content/attributes được context trả về. Summary chỉ xác nhận PowerShell được khởi chạy với command line chứa Get-Service sysmon, không xác nhận cmdlet completion/output/service state. Đủ 7 limitations có trong consumers và mỗi limitation xuất hiện trong ít nhất một actual context của 32 queries; số contexts tương ứng là 2/3/3/2/3/1/13. Không thêm causal edges hoặc mở core sang probes ngoài phạm vi. Ba queries trọng tâm vẫn chưa nhận đủ context: scope-limitations và service-action có semantic support unassessed/null, final-review-limits thiếu structured analysis_status và các limits cần thiết. Không coi null là đã sửa xong.

Chạy lại đúng 32 development cases với policy `two-stage-dev-5a4b308b106699e0` và retrieval top-k=5, candidate-k=20, RRF k=60, traversal both/depth=2/nodes=100/edges=200 giữ nguyên. Không tune thresholds hoặc đổi rubric. TP/TN/FP/FN đổi 5/15/1/11 → 5/14/2/11; topical 7 passed/25 failed, answerability 7 passed/0 failed/25 not_evaluated; coverage 7/32, selective error 2/7. False proceed insufficient_evidence vẫn 1/8 (payload-download URL); unrelated tăng 0/8 → 1/8 (Linux cron). Chỉ có một transition abstain→proceed, không có true positive mới. False abstain với context đủ vẫn 8/13 theo conservative AI rubric ngoài runtime; hai positives chuyển false→null không được tính là đủ context.

Tests cuối: focused 85 passed; regression liên quan 2541 passed; full suite {full['passed']} passed + {full.get('subtests_passed', 0)} subtests passed, {full['failed']} failed/{full['skipped']} skipped. Exact commands, durations và các failed attempts trước khi sửa synthetic tests nằm trong `outputs/review/graphrag-ground-truth-v2-consumer-sync/tests.json`. Kiểm tra JSON/validators/bindings, replay context→signals→decisions và git diff --check đều pass. Inventory ghi hashes trước/sau của toàn bộ 5055 baseline files: chỉ sáu compatibility source files và phần append file tiến độ này thay đổi; raw inputs, approved bundle, consumer/review artifacts cùng ZIP cũ giữ nguyên hash.

Kết quả và per-case analysis tại `outputs/review/graphrag-ground-truth-v2-consumer-sync/`; gói review `outputs/review/graphrag_ground_truth_v2_consumer_sync_review.zip`. Source/build sync đạt; runtime context coverage và gate quality chưa đạt. Answerability hiện chỉ kiểm tra cấu trúc nên vẫn cho phép câu hỏi URL thiếu evidence và câu ngoài phạm vi. Bước tiếp theo duy nhất là review regression/context gaps này trước khi quyết định cơ chế answerability theo yêu cầu và retrieval hỗ trợ limitations. Không chạy 11 proposed probes hoặc held-out; không tích hợp production CLI/LLM/UI; không stage/commit/amend/push. Dừng chờ review kết quả.
'''
    progress.write_bytes(original + appendix.encode('utf-8'))
    assert progress.read_bytes().startswith(original)
    print('Appended checkpoint 11; original progress bytes preserved exactly')


def package() -> None:
    REVIEW.mkdir(parents=True, exist_ok=True)
    for required in ('report.md', 'per_case_report.md', 'tests.json'):
        assert (REVIEW / required).is_file(), required
    tests = read(REVIEW / 'tests.json')
    assert any(run['scope'] == 'full suite' for run in tests['final_runs'])
    assert all(run['exit_code'] == 0 and run['failed'] == 0 for run in tests['final_runs'])
    assert not ZIP.exists(), 'Refusing to overwrite an existing FIX1 ZIP'
    protected = protected_audit()
    validation = validate_new_outputs()
    write(OUT / 'protected_hashes_after.json', protected)
    write(OUT / 'validation_results.json', validation)
    diff_check = subprocess.run(['git', 'diff', '--check'], cwd=ROOT, capture_output=True, text=True)
    assert diff_check.returncode == 0, diff_check.stdout + diff_check.stderr
    source_patch = []
    for name in (*MODIFIED_SOURCE, 'PROJECT_PROGRESS.md'):
        source_patch.extend(difflib.unified_diff(
            (OUT / 'before' / name).read_text(encoding='utf-8').splitlines(keepends=True),
            (ROOT / name).read_text(encoding='utf-8').splitlines(keepends=True),
            fromfile='fix1-baseline/' + name, tofile='fix1-final/' + name,
        ))
    (REVIEW / 'new_changes.patch').write_bytes(''.join(source_patch).encode('utf-8'))
    distributions = ('sentence-transformers', 'transformers', 'torch', 'numpy', 'huggingface-hub', 'safetensors', 'PyYAML', 'pytest')
    dependencies = {'python': platform.python_version(), 'platform': platform.platform(),
                    'installed_versions': {name: version(name) for name in distributions},
                    'dependency_declarations_unchanged': digest(ROOT / 'pyproject.toml') == read(OUT / 'preflight.json')['protected_hashes']['pyproject.toml']}
    write(REVIEW / 'dependencies.json', dependencies)
    raw_names = {
        'purplesharp_ad_playbook_I_2020-10-22042947.json',
        'empire_launcher_sct_regsvr32_2020-07-21232741.json',
        'cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json',
        'enterprise-attack.json',
    }
    selected = [name for name in protected['entries'] if (
        name.startswith('data/') and (Path(name).name in raw_names or '/sigma/selected/' in name)
    )]
    selected.extend([
        'outputs/review/mshta-ground-truth/scenario_ground_truth.json',
        'outputs/review/mshta-ground-truth/reference_answers.json',
        'outputs/review/mshta-ground-truth/review_manifest.json',
        'outputs/retrieval/mshta-powershell/retrieval_corpus.json',
        'outputs/graph/mshta-powershell/knowledge_graph.json',
        'outputs/evaluation/mshta-powershell/vector_index_multilingual_e5_small.json',
        'outputs/review/graphrag_two_stage_gate_calibration_review.zip',
    ])
    lines = ['# Protected SHA-256 before/after', '',
             'All listed hashes match before/after. Full verification for every baseline file is in `protected_hashes_after.json` under the experiment directory.', '',
             '| Protected path | SHA-256 before = after |', '| --- | --- |']
    for name in selected:
        entry = protected['entries'][name]
        assert entry['unchanged']
        lines.append(f"| `{name}` | `{entry['before']}` |")
    (REVIEW / 'protected_hash_summary.md').write_bytes(('\n'.join(lines) + '\n').encode('utf-8'))
    files = {}
    def add(path: Path, name: str | None = None) -> None:
        relative = name if name is not None else path.relative_to(ROOT).as_posix()
        assert relative not in files
        files[relative] = path
    for folder in ('src', 'tests'):
        for path in sorted((ROOT / folder).rglob('*')):
            if path.is_file() and '__pycache__' not in path.parts and path.suffix in ('.py', '.json', '.yml', '.yaml'):
                add(path)
    for name in ('pyproject.toml', 'AGENTS.md', 'PROJECT_CONTEXT.md', 'PROJECT_PROGRESS.md', 'README.md', *[item for item in NEW_SOURCE if item.startswith('scripts/')]):
        add(ROOT / name)
    for name in (*MODIFIED_SOURCE, 'AGENTS.md', 'PROJECT_CONTEXT.md', 'PROJECT_PROGRESS.md', 'README.md'):
        add(OUT / 'before' / name, 'fix1_baseline/' + name)
    for path in sorted(OUT.iterdir()):
        if path.is_file() and path.suffix in ('.json', '.py'):
            add(path)
    old_dir = ROOT / 'outputs/review/graphrag-two-stage-gate-calibration'
    for name in ('selected_policy.json', 'frozen_retrieval_configuration.json', 'consumer_audit.json', 'external_context_adjudication.json', 'calibration_results.json', 'split_manifest.json'):
        add(old_dir / name)
    for name in ('scenario_ground_truth.json', 'reference_answers.json', 'review_manifest.json'):
        add(ROOT / 'outputs/review/mshta-ground-truth' / name)
    for path in sorted(REVIEW.iterdir()):
        if path.is_file() and path.name not in ('review_inventory.json', 'zip_verification.json'):
            add(path)
    baseline = read(OUT / 'preflight.json')
    inventory = {
        'schema_version': 'graphrag-v2-consumer-sync-review-inventory/v1',
        'baseline': {key: baseline[key] for key in ('branch', 'head', 'staging', 'working_tree')},
        'final_working_tree': git('status', '--short'),
        'new_change_scope': {'modified_existing_source': list(MODIFIED_SOURCE), 'new_source_and_tests': list(NEW_SOURCE),
                             'progress_update': 'append_only', 'isolated_outputs': OUT.relative_to(ROOT).as_posix()},
        'tests': read(REVIEW / 'tests.json'), 'dependencies': dependencies,
        'diff_check': {'command': 'git diff --check', 'exit_code': diff_check.returncode, 'output': diff_check.stdout + diff_check.stderr},
        'staging_empty': not git('diff', '--cached', '--name-only'),
        'build': read(OUT / 'build_manifest.json'), 'experiment_configuration': read(OUT / 'experiment_configuration.json'),
        'comparison': read(OUT / 'comparison.json'), 'validation': validation,
        'protected_summary': {key: value for key, value in protected.items() if key != 'entries'},
        'protected_hashes': 'outputs/experiments/graphrag-2d3-fix1/protected_hashes_after.json',
        'status': 'consumer_build_sync_complete_runtime_context_and_gate_gaps_remain_awaiting_review',
        'no_heldout_no_new_probes_no_production_cli_llm_ui': True,
        'package_payloads_excluding_inventory_itself': {name: {'sha256': digest(path), 'size': path.stat().st_size} for name, path in sorted(files.items())},
        'inventory_self_hash_and_archive_hash_recorded_in_external_zip_verification_sidecar': True,
    }
    write(REVIEW / 'review_inventory.json', inventory)
    add(REVIEW / 'review_inventory.json')
    verification = create_review_zip(ZIP, files)
    verify_review_zip(ZIP, {item['filename']: item['sha256'] for item in verification['entries']})
    with ZipFile(ZIP) as archive:
        assert archive.testzip() is None
        sizes = {info.filename: info.file_size for info in archive.infolist()}
        assert all(sizes[item['filename']] == item['size'] for item in verification['entries'])
    verification.update(
        archive=ZIP.relative_to(ROOT).as_posix(),
        archive_size=ZIP.stat().st_size,
        inventory_sha256=digest(REVIEW / 'review_inventory.json'),
        safe_unique_regular_entries=True, payload_sizes_and_hashes_match=True,
        testzip_result=None, staging_empty=not git('diff', '--cached', '--name-only'),
    )
    write(REVIEW / 'zip_verification.json', verification)
    print(json.dumps({key: value for key, value in verification.items() if key != 'entries'}, indent=2))
    print(f"Verified {len(verification['entries'])} ZIP entries and {protected['baseline_file_count']} baseline hashes")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', choices=('audit', 'progress', 'package'), required=True)
    arguments = parser.parse_args()
    if arguments.phase == 'audit':
        REVIEW.mkdir(parents=True, exist_ok=True)
        audit = protected_audit()
        write(OUT / 'protected_hashes_after.json', audit)
        write(OUT / 'validation_results.json', validate_new_outputs())
        print(json.dumps({key: value for key, value in audit.items() if key != 'entries'}, indent=2))
    elif arguments.phase == 'progress':
        append_progress()
    else:
        package()
