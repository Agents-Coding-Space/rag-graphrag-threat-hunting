"""Preserve baseline bytes, validate saved FIX2 results and build a safe ZIP."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import platform
import re
import subprocess
from zipfile import ZipFile

from threat_hunting.evaluation.review_package import create_review_zip, verify_review_zip
from threat_hunting.evaluation.two_stage_review import load_approved_evaluation_bundle
from threat_hunting.graphrag.query_context import validate_query_evidence_context
from threat_hunting.graphrag.query_gate import assess_query_aware_gate, extract_query_evidence_signals


ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
REVIEW = ROOT / 'outputs/review/graphrag-query-aware-answerability'
ZIP = ROOT / 'outputs/review/graphrag_query_aware_answerability_review.zip'
NEW_FILES = (
    'scripts/evaluate_query_aware_gate.py',
    'src/threat_hunting/graphrag/query_requirements.py',
    'src/threat_hunting/graphrag/query_context.py',
    'src/threat_hunting/graphrag/query_support.py',
    'src/threat_hunting/graphrag/query_gate.py',
    'tests/test_query_requirements.py', 'tests/test_query_context.py',
    'tests/test_query_support.py', 'tests/test_query_aware_gate.py',
    'tests/test_query_aware_ablation.py',
)
REGRESSION_FILES = (
    'test_retrieval_builder', 'test_retrieval_schema', 'test_vector_index_builder',
    'test_vector_index_schema', 'test_vector_retriever', 'test_hybrid_retriever',
    'test_knowledge_graph_builder', 'test_knowledge_graph_schema', 'test_knowledge_graph_traversal',
    'test_graphrag_seed_mapping', 'test_graphrag_orchestrator', 'test_graphrag_relevance',
    'test_graphrag_gate_signals', 'test_graphrag_two_stage_gate', 'test_relevance_calibration_schema',
    'test_ground_truth_schema', 'test_ground_truth_approval', 'test_two_stage_calibration', 'test_two_stage_review',
)


def digest(path: Path) -> str:
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def read(path: Path):
    return json.loads(path.read_text(encoding='utf-8'))


def write(path: Path, value: object) -> None:
    path.write_bytes((json.dumps(value, ensure_ascii=False, allow_nan=False, indent=2) + '\n').encode('utf-8'))
    assert read(path) == value


def git(*arguments: str) -> str:
    return subprocess.check_output(['git', *arguments], cwd=ROOT, text=True, encoding='utf-8')


def capture_test_results() -> None:
    """Parse actual final pytest logs, retaining exact shell commands."""
    focused = ' '.join(name for name in NEW_FILES if name.startswith('tests/'))
    regression = ' '.join('tests/' + name + '.py' for name in REGRESSION_FILES)
    results = []
    for scope, arguments, temporary, log in (
        ('focused', focused, 'rag-fix2-focused-resume-20261017', 'focused_final.log'),
        ('related regression', regression, 'rag-fix2-regression-resume-20261017', 'regression_final.log'),
        ('full suite', '', 'rag-fix2-full-final-20261017', 'full_final.log'),
    ):
        path = OUT / log
        payload = path.read_bytes()
        decoded = payload.decode('utf-16') if payload.startswith((b'\xff\xfe', b'\xfe\xff')) else payload.decode('utf-8-sig')
        lines = [line.strip() for line in decoded.splitlines() if re.search(r'\d+ passed.* in \d', line)]
        assert lines, f'No completed pytest summary in {log}'
        summary = lines[-1]
        passed = int(re.search(r'(\d+) passed', summary).group(1))
        subtests = re.search(r'(\d+) subtests passed', summary)
        failures = re.search(r'(\d+) failed', summary)
        skipped = re.search(r'(\d+) skipped', summary)
        errors = re.search(r'(\d+) errors?', summary)
        assert not failures and not errors, summary
        seconds = float(re.search(r' in ([0-9.]+)s', summary).group(1))
        # PowerShell's redirection used UTF-16. Normalize these derived logs to
        # UTF-8 for portable review; text and the pytest result remain exact.
        path.write_bytes(decoded.encode('utf-8'))
        command = '.\\.venv\\Scripts\\python.exe -m pytest ' + (arguments + ' ' if arguments else '')
        command += '-q -p no:cacheprovider --basetemp="$env:TEMP/' + temporary + '"'
        command += ' > outputs/experiments/graphrag-2d3-fix2/' + log + ' 2>&1'
        results.append({'scope': scope, 'command': command, 'passed': passed,
            'subtests_passed': int(subtests.group(1)) if subtests else 0,
            'failed': 0, 'skipped': int(skipped.group(1)) if skipped else 0,
            'errors': 0, 'seconds': seconds, 'exit_code': 0,
            'actual_pytest_summary': summary, 'log_sha256': digest(path)})
    write(REVIEW / 'tests.json', {
        'schema_version': 'query-aware-fix2-test-results/v1', 'final_runs': results,
        'logs_normalized_from_powershell_utf16_to_utf8_without_text_changes': True,
        'earlier_development_runs': [
            {'scope': 'initial parser', 'result': '96 passed / 2 failed; plural command-lines and child-process-of parsing were corrected; final parser 121 passed'},
            {'scope': 'context enrichment', 'result': '19 passed / 1 failed test assumption about smaller graph fallback; corrected assertion; final 20 passed'},
            {'scope': 'wrapper integration', 'result': '14 passed / 1 failed from pairing different legacy fixture inputs; corrected assertion; final 15 passed'},
            {'scope': 'initial ablation runner', 'result': 'KeyError before evaluation: corpus content hash was incorrectly assumed a chunk field; corrected to SHA-256 of actual UTF-8 content and added mismatch tests'},
            {'scope': 'earlier complete focused', 'result': '202 passed, 0 failed/skipped, 1.10s; superseded by generic invariant fixes and archive test'},
            {'scope': 'frozen focused before resume', 'result': '221 passed, 0 failed/skipped, 1.21s'},
            {'scope': 'earlier regression', 'result': '2541 passed, 0 failed/skipped, 12.06s; an additional running-cell result was unavailable after resume, so final regression was rerun and logged'},
        ],
        'experiment_commands': [
            '.\\.venv\\Scripts\\python.exe scripts/evaluate_query_aware_gate.py',
            '.\\.venv\\Scripts\\python.exe scripts/evaluate_query_aware_gate.py --archive-development-iteration',
        ],
        'no_test_or_experiment_is_claimed_as_independent_or_heldout': True,
    })


def protected_audit() -> dict:
    before = read(OUT / 'preflight.json')
    assert git('branch', '--show-current').strip() == before['branch']
    assert git('rev-parse', 'HEAD').strip() == before['head']
    assert not git('diff', '--cached', '--name-only')
    entries = {name: {'before': old, 'after': digest(ROOT / name)} for name, old in before['protected_hashes'].items()}
    for item in entries.values():
        item['unchanged'] = item['before'] == item['after']
    changed = [name for name, item in entries.items() if not item['unchanged']]
    assert set(changed) <= {'PROJECT_PROGRESS.md'}, changed
    original_progress = (OUT / 'before/PROJECT_PROGRESS.md').read_bytes()
    assert (ROOT / 'PROJECT_PROGRESS.md').read_bytes().startswith(original_progress)
    current = set(git('ls-files', '--cached', '--others', '--exclude-standard').splitlines())
    assert current - set(entries) == set(NEW_FILES), current - set(entries)
    result = {'schema_version': 'query-aware-fix2-protected-hashes/v1',
        'baseline_file_count': len(entries), 'unchanged_count': len(entries) - len(changed),
        'changed_existing_files': changed, 'original_progress_bytes_preserved_as_prefix': True,
        'all_existing_source_tests_fixtures_raw_approved_and_FIX1_artifacts_unchanged': all(
            item['unchanged'] for name, item in entries.items() if name != 'PROJECT_PROGRESS.md'),
        'entries': entries}
    write(OUT / 'protected_hashes_after.json', result)
    return result


def pointer_value(document, pointer):
    current = document
    for part in pointer.lstrip('/').split('/'):
        token = part.replace('~1', '/').replace('~0', '~')
        current = current[int(token)] if isinstance(current, list) else current[token]
    return current


def validate_results() -> dict:
    load_approved_evaluation_bundle(ROOT / 'outputs/review/mshta-ground-truth')
    config = read(OUT / 'experiment_configuration.json')
    for name, expected in config['runtime_code_sha256'].items():
        assert digest(ROOT / name) == expected
    assert digest(ROOT / 'scripts/evaluate_query_aware_gate.py') == config['runner_sha256']
    base, enriched = read(OUT / 'base_evidence_contexts.json'), read(OUT / 'enriched_contexts.json')
    queries, decisions, signals = read(OUT / 'query_requirements.json'), read(OUT / 'decisions.json'), read(OUT / 'signals.json')
    policy = read(OUT / 'fixed_policy.json')
    count = 0
    for arm in ('A', 'B', 'C', 'D'):
        for identifier, decision in decisions[arm].items():
            context = (base if arm in ('A', 'C') else enriched)[identifier]
            validate_query_evidence_context(context)
            assert extract_query_evidence_signals(context) == signals[arm][identifier]
            checked = assess_query_aware_gate(context, queries[identifier], policy=policy)
            assert checked == decision['trace']
            expected = checked['legacy_decision']['decision'] if arm in ('A', 'B') else checked['final_decision']
            assert decision['decision'] == expected
            assert not checked['security_conclusion_made']
            for requirement in checked['support_assessment']['requirements']:
                for trace in requirement['traces']:
                    actual = pointer_value(context, trace['context_pointer'])
                    quote = actual if isinstance(actual, str) else json.dumps(actual, ensure_ascii=False, sort_keys=True, allow_nan=False, separators=(',', ':'))
                    assert trace['quote'] == quote
                    payload_pointer = trace['context_pointer'].split('/payload', 1)[0]
                    item = pointer_value(context, payload_pointer)
                    assert item['item_id'] == trace['item_id'] and item['kind'] == trace['kind']
                    count += 1
    files = sorted(OUT.glob('*.json'))
    for path in files:
        read(path)
    result = {'json_readback_count': len(files), 'saved_output_replay_matches': True,
        'replay_is_consistency_verification_not_an_independent_experiment': True,
        'trace_field_quotes_and_item_ids_verified': count,
        'runtime_and_runner_hashes_match_final_ablation': True,
        'legacy_source_and_fixtures_unchanged': True}
    write(OUT / 'validation_results.json', result)
    return result


def append_progress() -> None:
    tests = read(REVIEW / 'tests.json')['final_runs']
    full = next(run for run in tests if run['scope'] == 'full suite')
    original = (OUT / 'before/PROJECT_PROGRESS.md').read_bytes()
    target = ROOT / 'PROJECT_PROGRESS.md'
    assert target.read_bytes() == original, 'Refusing duplicate/non-baseline progress appendix'
    appendix = f'''
## 12. Checkpoint GRAPHRAG-2D3-FIX2 — 17/10/2026

Đã triển khai luồng thử nghiệm query requirements → bounded context enrichment → evidence support → query-aware eligibility, với design note viết trước code. Thêm bốn modules `query_requirements.py`, `query_context.py`, `query_support.py`, `query_gate.py`, research runner `scripts/evaluate_query_aware_gate.py` và năm test files mới. Mọi source/tests/fixtures có sẵn giữ nguyên bytes; không đổi legacy APIs/schema/policy hoặc production defaults. Phần tiến độ cũ được giữ nguyên toàn bộ làm prefix.

Parser deterministic EN/VI có vocabulary công khai và biểu diễn supported/ambiguous/unsupported, scope/platform, process roles và mandatory requirements. Verifier chỉ kiểm tra items thực sự trả về, giữ supported/missing/unknown, trace tới field/ID/provenance, không dùng labels/answers/rubric. Process launch không chứng minh completion/output/service state; URL cần actor/action binding; candidate không thành confirmed. Với command invocation/service identity chưa bind được, verifier giữ unknown. Chỉ tách scope mismatch rõ ràng; phủ định/so sánh chưa phân giải là ambiguous.

Giữ nguyên FIX1 corpus/graph/index/model/revision cùng policy `two-stage-dev-5a4b308b106699e0`; không gọi embedding/LLM. Reuse ranked contexts đã đóng băng cho cùng 32 development queries; bổ sung evidence không có scores/paths giả. B/D tính lại legacy ranked signals và diagnostics final context riêng. Budget mặc định 12 supplements, 64 final items, 131072 canonical UTF-8 serialized bytes (không gọi là token count). Đã thêm tổng cộng 16 items cho 7 queries, max 6/query; không cut budget. External AI rubric giữ tiêu chí: context sufficient tăng 13→14, không đánh giá bằng checker mới rồi coi là ground truth.

A/B: TP/TN/FP/FN = 5/14/2/11, coverage 7/32, selective error 2/7. C/D: 2/16/0/14, coverage 2/32, selective error 0/2. D false abstain/context đủ = 12/14; parser 10 supported/10 ambiguous/12 unsupported; support 9 supported/1 missing/22 unknown. Linux cron bị scope mismatch; URL case bị chặn vì actor parsing ambiguous/support unknown, chưa phải xác minh trực tiếp missing download evidence. EN D2/8/0/6, VI D0/8/0/8; không có proceed tiếng Việt. Scope-limitations context đã đủ cả7 units theo rubric; final-review-limits vẫn thiếu context; service-action vẫn thiếu completion limitation theo rubric. False abstain và unsupported-query rate chưa chấp nhận được cho production.

Có hai vòng development; vòng đầu lưu riêng trong `iterations/initial/`. Review đã sửa invariant generic về named constraints/unanchored chain/ignored assertions/unresolved negated scope, dùng synthetic tests, không tune thresholds hoặc chạy proposed probes. Không coi các vòng này là held-out. Runtime/runner hashes vòng cuối được khóa và kiểm tra; source hashes vòng đầu chưa chụp tại thời điểm chạy được nêu rõ.

Tests cuối: focused {tests[0]['passed']} passed; regression {tests[1]['passed']} passed; full suite {full['passed']} passed + {full['subtests_passed']} subtests passed, 0 failed/skipped. Exact commands/logs tại `outputs/review/graphrag-query-aware-answerability/tests.json` và experiment logs. Inventory ghi hashes trước/sau của 5279 baseline files; raw data, approved bundle, FIX1 artifacts và các ZIP cũ không đổi. Git diff --check sạch, staging rỗng; branch/HEAD không đổi.

Kết quả tại `outputs/experiments/graphrag-2d3-fix2/` và `outputs/review/graphrag-query-aware-answerability/`; gói review `outputs/review/graphrag_query_aware_answerability_review.zip`. Bước tiếp theo duy nhất: review FIX2 và quyết định mở rộng clause/role binding, support completeness và cấu hình chất lượng EN/VI trước calibration/kiểm chứng độc lập. Chưa thực hiện các đề xuất đó. Không chạy 11 proposed probes hoặc held-out; không stage/commit/amend/push; không tích hợp production CLI/LLM/UI. Dừng chờ review kết quả.
'''
    target.write_bytes(original + appendix.encode('utf-8'))
    assert target.read_bytes().startswith(original)


def package() -> None:
    assert not ZIP.exists(), 'Refusing to overwrite an existing FIX2 review ZIP'
    for name in ('report.md', 'per_case_report.md', 'tests.json'):
        assert (REVIEW / name).is_file(), name
    tests = read(REVIEW / 'tests.json')
    assert len(tests['final_runs']) == 3 and all(run['exit_code'] == 0 for run in tests['final_runs'])
    protected, validation = protected_audit(), validate_results()
    check = subprocess.run(['git', 'diff', '--check'], cwd=ROOT, capture_output=True, text=True)
    assert check.returncode == 0, check.stdout + check.stderr
    dependencies = {'python': platform.python_version(), 'platform': platform.platform(),
        'installed_versions': {name: version(name) for name in ('PyYAML', 'pytest', 'sentence-transformers', 'transformers', 'torch', 'numpy')},
        'new_dependencies': [], 'model_calls': 0}
    write(REVIEW / 'dependencies.json', dependencies)
    raw_names = {
        'purplesharp_ad_playbook_I_2020-10-22042947.json',
        'empire_launcher_sct_regsvr32_2020-07-21232741.json',
        'cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json', 'enterprise-attack.json',
    }
    selected = [name for name in protected['entries'] if name.startswith('data/')
                and (Path(name).name in raw_names or '/sigma/selected/' in name)]
    selected += ['outputs/review/mshta-ground-truth/' + name for name in (
        'scenario_ground_truth.json', 'reference_answers.json', 'review_manifest.json')]
    selected += ['outputs/experiments/graphrag-2d3-fix1/' + name for name in (
        'retrieval_corpus.json', 'knowledge_graph.json', 'vector_index.json',
        'fixed_policy.json', 'experiment_configuration.json', 'contexts.json', 'signals.json', 'decisions.json')]
    selected += ['outputs/review/graphrag_two_stage_gate_calibration_review.zip',
                 'outputs/review/graphrag_ground_truth_v2_consumer_sync_review.zip']
    lines = ['# Protected SHA-256 before/after', '',
             'These protected hashes are identical before/after FIX2. Full verification for all baseline files is in `outputs/experiments/graphrag-2d3-fix2/protected_hashes_after.json`.', '',
             '| Protected path | SHA-256 before = after |', '| --- | --- |']
    for name in selected:
        item = protected['entries'][name]
        assert item['unchanged'], name
        lines.append(f"| `{name}` | `{item['before']}` |")
    (REVIEW / 'protected_hash_summary.md').write_bytes(('\n'.join(lines) + '\n').encode('utf-8'))
    files = {}
    def add(path: Path, name: str | None = None):
        key = name or path.relative_to(ROOT).as_posix()
        assert key not in files
        files[key] = path
    for folder in ('src', 'tests'):
        for path in sorted((ROOT / folder).rglob('*')):
            if path.is_file() and '__pycache__' not in path.parts and path.suffix in ('.py', '.json', '.yml', '.yaml'):
                add(path)
    for name in ('pyproject.toml', 'AGENTS.md', 'PROJECT_CONTEXT.md', 'PROJECT_PROGRESS.md', 'README.md', 'scripts/evaluate_query_aware_gate.py'):
        add(ROOT / name)
    add(OUT / 'before/PROJECT_PROGRESS.md', 'fix2_baseline/PROJECT_PROGRESS.md')
    for path in sorted(OUT.rglob('*')):
        if path.is_file() and 'before' not in path.relative_to(OUT).parts and '__pycache__' not in path.parts and path.suffix in ('.json', '.md', '.py', '.log'):
            add(path)
    # Exact FIX1 runtime dependencies, without modifying or copying raw logs.
    for name in ('retrieval_corpus.json', 'knowledge_graph.json', 'vector_index.json', 'fixed_policy.json', 'experiment_configuration.json'):
        add(ROOT / 'outputs/experiments/graphrag-2d3-fix1' / name)
    add(ROOT / 'outputs/review/graphrag-two-stage-gate-calibration/consumer_audit.json')
    for name in ('scenario_ground_truth.json', 'reference_answers.json', 'review_manifest.json'):
        add(ROOT / 'outputs/review/mshta-ground-truth' / name)
    for path in sorted(REVIEW.iterdir()):
        if path.is_file() and path.name not in ('review_inventory.json', 'zip_verification.json'):
            add(path)
    baseline = read(OUT / 'preflight.json')
    inventory = {
        'schema_version': 'query-aware-fix2-review-inventory/v1', 'review_date': '2026-10-17',
        'baseline': {key: baseline[key] for key in ('branch', 'head', 'working_tree', 'staging')},
        'new_change_scope': {'new_source_tests_runner': list(NEW_FILES), 'existing_source_modified': [], 'progress': 'append_only'},
        'final_working_tree': git('status', '--short'), 'staging_empty': not git('diff', '--cached', '--name-only'),
        'tests': tests, 'dependencies': dependencies,
        'diff_check': {'command': 'git diff --check', 'exit_code': check.returncode, 'output': check.stdout + check.stderr},
        'experiment_configuration': read(OUT / 'experiment_configuration.json'),
        'ablation_results': read(OUT / 'ablation_results.json'), 'validation': validation,
        'protected_summary': {key: value for key, value in protected.items() if key != 'entries'},
        'protected_hashes_before_after': 'outputs/experiments/graphrag-2d3-fix2/protected_hashes_after.json',
        'status': 'implementation_and_development_ablation_complete_quality_limits_remain_awaiting_review',
        'package_payloads_excluding_inventory_itself': {name: {'sha256': digest(path), 'size': path.stat().st_size} for name, path in sorted(files.items())},
        'inventory_self_hash_and_archive_hash_recorded_in_external_zip_verification_sidecar': True,
    }
    write(REVIEW / 'review_inventory.json', inventory)
    add(REVIEW / 'review_inventory.json')
    verification = create_review_zip(ZIP, files)
    verify_review_zip(ZIP, {entry['filename']: entry['sha256'] for entry in verification['entries']})
    with ZipFile(ZIP) as archive:
        assert archive.testzip() is None
        assert all(archive.getinfo(entry['filename']).file_size == entry['size'] for entry in verification['entries'])
    verification.update(archive=ZIP.relative_to(ROOT).as_posix(), archive_size=ZIP.stat().st_size,
        entry_count=len(verification['entries']), testzip_result=None,
        safe_unique_regular_entries=True, payload_sizes_and_hashes_match=True,
        inventory_sha256=digest(REVIEW / 'review_inventory.json'))
    write(REVIEW / 'zip_verification.json', verification)
    print(json.dumps({key: value for key, value in verification.items() if key != 'entries'}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', choices=('tests', 'audit', 'progress', 'package'), required=True)
    args = parser.parse_args()
    REVIEW.mkdir(parents=True, exist_ok=True)
    if args.phase == 'tests':
        capture_test_results()
    elif args.phase == 'audit':
        result = protected_audit()
        print(json.dumps({key: value for key, value in result.items() if key != 'entries'}, indent=2))
        print(json.dumps(validate_results(), indent=2))
    elif args.phase == 'progress':
        append_progress()
    else:
        package()
