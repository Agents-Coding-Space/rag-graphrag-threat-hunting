"""Produce Vietnamese development review from saved results and actual test logs."""
from collections import Counter
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
REVIEW = ROOT / 'outputs/review/graphrag-parser-policy-fix3'
ARMS = ('E0', 'E1', 'E2', 'E3', 'E4')


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def compact(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def ratio(value):
    return f"{value['numerator']}/{value['denominator']}" + (f" ({value['value']:.2%})" if value['value'] is not None else ' (undefined)')


def main():
    results = read(OUT / 'ablation_results.json')
    records = read(OUT / 'evaluation_records.json')
    decisions = read(OUT / 'decisions.json')
    requirements = read(OUT / 'requirements.json')
    contexts = read(OUT / 'contexts.json')
    changes = read(REVIEW / 'changed_cases.json')
    tests = read(REVIEW / 'tests.json')['final_runs']
    metrics = {}
    for arm in ARMS:
        values = records[arm]
        metrics[arm] = {
            'by_language_runtime_statuses': {lang: {
                'parser': dict(Counter(x['query_analysis_status'] for x in values if x['language'] == lang)),
                'support': dict(Counter(x['support_status'] for x in values if x['language'] == lang)),
            } for lang in ('en', 'vi')},
            'requirement_completeness': dict(Counter(req.get('completeness', {}).get('status', 'not_in_v1_contract')
                for d in decisions[arm].values() for req in d['trace'].get('verification_guards', d['trace']['support_assessment'])['requirements'])),
            'requirement_contradiction': dict(Counter(req.get('contradiction', {}).get('status', 'not_in_v1_contract')
                for d in decisions[arm].values() for req in d['trace'].get('verification_guards', d['trace']['support_assessment'])['requirements'])),
            'false_abstain_dataset_case_ids': [x['case_id'] for x in values if x['expected_decision'] == 'proceed' and x['actual_decision'] == 'abstain'],
            'permitted_with_external_context_unknown': [x['case_id'] for x in values if x['actual_decision'] == 'proceed' and x['context_sufficient'] is None],
            'permitted_with_external_context_false': [x['case_id'] for x in values if x['actual_decision'] == 'proceed' and x['context_sufficient'] is False],
            'source_inventory_coverage_unknown_contexts': sum(c['source_inventory'].get('process_relationship_inventory_complete') is False for c in contexts[arm].values()),
        }
    (OUT / 'analysis_metrics.json').write_bytes((json.dumps(metrics, ensure_ascii=False, indent=2) + '\n').encode('utf-8'))
    lines = ['# GRAPHRAG-2D3-FIX3 — Kết quả development', '',
        'Ngày review: 17/10/2026. Branch `feature/mshta-evidence-extractor`; HEAD `af2243a3ee89c5e5721ec341eea0a8cb06814f41`; staging rỗng. Đây là thí nghiệm development trên cùng 32 queries đã exposed, không phải independent validation.', '',
        'E4 đạt **9/16/0/7 TP/TN/FP/FN**, tăng 7 true positives so với E0 (4 câu VI), giữ cả 2 true positives E0. Coverage 9/32, recall 9/16; còn 7 false abstains và 21 support unknown. Không có false proceed theo approved labels trên tập này. Những con số này chưa đủ để chốt cấu hình production hay tuyên bố đã kiểm chứng riêng.', '',
        '## Bảo toàn và phạm vi thay đổi', '',
        'Đã đọc brief, tiến độ và FIX2; xác minh baseline thực tế rồi snapshot 5.528 hashes trước khi sửa. Human approval có sẵn trong approved bundle được giữ nguyên; các dòng pending review lịch sử trong AGENTS/PROJECT_CONTEXT không được hiểu là thu hồi approval. Chỉ thêm 4 modules phiên bản mới, 1 research runner và 5 test files; `PROJECT_PROGRESS.md` chỉ nối thêm. Không sửa bất kỳ source/tests/fixtures cũ, raw data, nhãn/câu hỏi/đáp án/provenance, FIX1 corpus/graph/index, FIX2 artifacts/policies hoặc ZIP cũ.', '',
        '| File mới | Trách nhiệm |', '| --- | --- |',
        '| `src/threat_hunting/graphrag/query_requirements_v2.py` | Clause/request/background, process roles, source spans EN/VI; schema query-requirements/v2 |',
        '| `src/threat_hunting/graphrag/query_context_v2.py` | Inventory exact source identities, coverage raw creation facts, supplementation bounded; context/v2 |',
        '| `src/threat_hunting/graphrag/query_support_v2.py` | Instance-bound chain, source-boundary completeness, exact limitation sets, contradiction guards; support/v2 |',
        '| `src/threat_hunting/graphrag/query_policy.py` | Policy/decision phiên bản riêng, legacy diagnostic-only, source authentication và mandatory guards |',
        '| `scripts/evaluate_parser_policy_fix3.py` | Research runner E0–E4; labels/rubric chỉ ở evaluator |',
        '| 5 `tests/test_*v2.py`, `test_query_policy.py`, `test_parser_policy_fix3_runner.py` | Synthetic development/compatibility/boundary tests; danh sách chính xác tại inventory |', '',
        'Không rebuild corpus/index, đổi model/revision, gọi embeddings/LLM, mở held-out hoặc chạy 11 proposed probes. Không sửa production CLI/UI; không stage/commit/amend/push.', '',
        '## Thiết kế khóa trước benchmark', '',
        '`design_note.md` và `combined_policy.json` được viết trước benchmark. `pre_evaluation_freeze.json` chụp SHA-256 parser/context/support/policy, runner và design trước vòng E0–E4; kiểm tra lại sau vòng. Chỉ một policy design, không sweep thresholds/rules và không sửa runtime sau khi xem kết quả. Mọi lỗi development trong tests được ghi ở `tests.json`.', '',
        'Hard requirements: >=1 ranked hit thật, finite existing scores và payload đúng runtime corpus/graph/provenance; parser supported và có mandatory requirements; không mismatch/ambiguous scope; tất cả mandatory requirements có evidence thật với field-resolved traces, identity/source anchors; không có completeness gap hoặc conflicting bound values liên quan. Scope unspecified chỉ pass nếu từng requirement có anchor đã authenticate. Missing/unknown/partial support đều block. Source inventory chỉ định boundary/completeness, không bổ sung positive proof ẩn.', '',
        'Legacy decision, cosine/token-coverage thresholds, graph traversal/counts là diagnostics trong policy mới. Không coi scores là xác suất, không ép traversal cho direct evidence, không chấm score cho supplements. Unrelated cuts chỉ diagnostic khi support/completeness đã đủ. Budget E4: 12 supplementary items, 64 final items, 131072 canonical serialized UTF-8 bytes, depth 8. Giữ nguyên toàn bộ initial evidence nếu vượt budget và báo incomplete.', '',
        '## Ablation và giới hạn tách nguyên nhân', '',
        '| Arm | Thay đổi |', '| --- | --- |',
        '| E0 | Parser/checker/FIX2 context/AND legacy nguyên bản; replay exact saved FIX2 D |',
        '| E1 | Parser v2 + final_items FIX2 cố định + compatibility checker v2 cho contract mới + AND legacy |',
        '| E2 | Parser/checker v1 + final_items FIX2 cố định + policy mới; independent completeness/contradiction guards ghi riêng |',
        '| E3 | Parser v2 + final_items FIX2 cố định + policy mới |',
        '| E4 | Parser v2 + tính lại unranked supplementation từ cùng nguồn runtime + policy mới |', '',
        'Mọi arm dùng cùng frozen ranked FIX1 initial_context. E1–E3 chỉ nâng inventory metadata, không đổi final_items. E1 không phải can thiệp parser thuần tuyệt đối: target-only chain/exact identities cần checker compatibility v2; tác động chung này được công bố. E2 giữ nguyên selected support v1, guard mới thuộc policy composition và xuất riêng. Layer metrics trong ablation_results vẫn là legacy-only diagnostics; không diễn giải thành performance các stage mới.', '',
        '| Arm | TP/TN/FP/FN | Coverage | Selective error | Recall | False abstain / context đủ | FP unrelated / insufficient |',
        '| --- | --- | --- | --- | --- | --- | --- |']
    for arm in ARMS:
        s = results['summaries'][arm]
        m = s['dataset_label_confusion_matrix']
        lines.append(f"| {arm} | {'/'.join(str(m[x]) for x in ('tp','tn','fp','fn'))} | {ratio(s['coverage'])} | {ratio(s['selective_error'])} | {ratio(s['dataset_label_metrics']['recall'])} | {ratio(s['false_abstain_context_sufficient'])} | {ratio(s['false_proceed_by_category']['unrelated'])} / {ratio(s['false_proceed_by_category']['insufficient_evidence'])} |")
    lines += ['', '## Parser, support và ngôn ngữ', '',
        '| Arm | Parser supported/ambiguous/unsupported | Support supported/missing/unknown | EN TP/TN/FP/FN | VI TP/TN/FP/FN |', '| --- | --- | --- | --- | --- |']
    for arm in ARMS:
        s = results['summaries'][arm]
        cells = [arm, '/'.join(str(s['query_analysis_counts'].get(x, 0)) for x in ('supported','ambiguous','unsupported')),
            '/'.join(str(s['evidence_support_counts'].get(x, 0)) for x in ('supported','missing','unknown'))]
        cells += ['/'.join(str(s['by_language'][lang]['dataset_label_confusion_matrix'][x]) for x in ('tp','tn','fp','fn')) for lang in ('en','vi')]
        lines.append('| ' + ' | '.join(cells) + ' |')
    lines += ['', 'Counts parser/support là query-level, không phải số requirements. Chi tiết EN/VI và per-requirement completeness/contradiction tại `analysis_metrics.json`:', '']
    for arm in ARMS:
        lines.append(f"- {arm}: `{compact(metrics[arm]['by_language_runtime_statuses'])}`; completeness `{compact(metrics[arm]['requirement_completeness'])}`; contradiction `{compact(metrics[arm]['requirement_contradiction'])}`.")
    lines += ['', 'Parser sửa được target-only ancestor chain, A-to-B process creation, launch command/passive roles, grounded evidence-limits/follow-up và URL actor/action tách background chain; tests đổi tên entities, phối hợp clauses, phủ định/so sánh và mandatory multi-intents. V1 APIs/fixtures/FIX2 replay giữ nguyên. Trên 32 cases, ba câu EN được cứu bởi parser/compatibility là process-chain và hai spawn-evidence queries. URL-download không còn bị chặn bằng parser unknown.', '',
        '## Context, supplementation và completeness', '',
        '| Arm | Min/max/mean UTF-8 bytes | Tổng/max supplements | Incomplete contexts |', '| --- | --- | --- | --- |']
    for arm in ARMS:
        c = results['summaries'][arm]['context']
        lines.append(f"| {arm} | {c['min_bytes']}/{c['max_bytes']}/{c['mean_bytes']:.4f} | {c['supplementary_items_total']}/{c['max_supplementary_items']} | {c['incomplete_context_count']} |")
    lines += ['', 'Không cut budget trên 32 contexts. Không đồng nhất incomplete_context=false với mọi requirement đủ: chain thiếu target/source boundary vẫn unknown, limitations phải đủ exact requested identity set. Chuỗi không nối bằng basename/PID xuyên lifetime; cycle/depth/unresolved source coverage không được coi là complete. Right-count/wrong-identity limitations bị chặn trong synthetic tests.', '',
        'E3→E4 cứu thêm `rd-vi-proxy-technique-assessment`: parser v2 sinh thêm review_status requirement; fixed context thiếu scenario analysis_status, E4 lấy source-associated scenario item. E2 đã cho proceed vì parser v1 không sinh requirement này; vì vậy có 1 TP của E2 bị mất tạm ở E3 rồi phục hồi ở E4. Đây là khác biệt contract cần review: review_status facet hiện mô tả scenario.analysis_status; technique review_status thực tế được verifier technique_assessment kiểm riêng. Clause continuation chưa bind chắc nghĩa review-status về đúng đối tượng nên không được khẳng định parser đã hiểu hoàn hảo câu đó.', '',
        '## Các quyết định thay đổi và đối chiếu ngoài runtime', '',
        '`changed_cases.md`/`.json` ghi đầy đủ 7 cases có thay đổi trong bất kỳ arm: requirements và exact query spans, quotation tới final context field/item/source identities/raw references, guards, lý do evidence hỗ trợ, phần chưa chứng minh và approved label ngoài runtime. Không tạo span giả cho v1. Tất cả quotes được đối chiếu lại, không lấy checker output làm nhãn chính nó.', '']
    for arm, counts in changes['per_arm_change_counts'].items():
        lines.append(f"- {arm} so E0: cứu {counts['rescued_dataset_positive']} dataset positives, gồm {counts['rescued_dataset_positive_vi']} VI; mất {counts['baseline_true_positive_lost']} baseline TP; FP {counts['false_proceed']}.")
    lines += ['', 'E4 cứu EN: `rd-en-process-chain`, `rd-en-initial-spawn-evidence`, `rd-en-final-spawn-evidence`; VI: `rd-vi-proxy-technique-assessment`, `rd-vi-reviewed-scope-limitations`, `rd-vi-initial-relation-provenance`, `rp-vi-service-action`. Không mất TP E0; FP unrelated và insufficient-evidence đều 0/8 trên tập exposed này.', '',
        '**Bất đồng rubric cần giữ nguyên:** `rp-vi-service-action` có launch-command evidence (`-noexit -command Get-Service sysmon`) và expected proceed, nhưng external context_sufficient vẫn **null** vì thiếu exact limitation_4 về completion/output/service state. Không đổi rubric/label và không cộng trường hợp này vào 14 contexts được rubric xác nhận đủ. Trace chỉ chứng minh command line khi launch, không chứng minh cmdlet hoàn tất hoặc Sysmon service state. E4 giữ 8 context-sufficient positives và thêm 1 dataset-positive/context-unknown; false abstain/context đủ còn 6/14. Đây là giới hạn guard/scope của checker, không dùng FP=0 che khuất.', '',
        '**URL-download:** requirement duy nhất actor=`powershell.exe`, action=`download`, field=`url`; phần MSHTA chain là background. Parser supported, verifier **missing** (`bound_actor_action_endpoint_not_returned`), quyết định abstain trực tiếp trong E1/E3/E4. Không suy ra download không xảy ra ở toàn hệ thống. C2-address cũng missing bound network evidence. URL trong command/reference không đủ chứng minh download.', '',
        '## False abstains còn lại và bước review', '',
        '7 dataset positives E4 vẫn abstain:', '']
    for identifier in metrics['E4']['false_abstain_dataset_case_ids']:
        req = requirements['E4'][identifier]
        support = decisions['E4'][identifier]['trace']['support_assessment']
        reasons = req['reason_codes'] + [reason for item in support['requirements'] if item['status'] != 'supported' for reason in item['reason_codes']]
        lines.append(f"- `{identifier}`: parser {req['analysis_status']}; support {support['status']}; `{', '.join(dict.fromkeys(reasons))}`.")
    lines += ['', 'Các nhóm còn yếu: anaphora/implicit process roles (final shell/intermediate utility), continuation câu kỹ thuật tiếng Việt và negation punctuation, chain không nêu target, provenance cho toàn bộ hai groups (verifier cũ chỉ trả observation đại diện), follow-up diễn đạt mở không có evidence/review anchor rõ. Parser còn có thể tạo requirement thừa từ từ khóa background như command-line trong câu technique assessment. Các trường hợp này được giữ ambiguous/unsupported/unknown, chưa thêm rules sau khi xem benchmark.', '',
        'Deterministic subset đã cải thiện nhưng chưa đủ để khóa cấu hình cho kiểm chứng riêng: recall 56.25%, parser unresolved 19/32 và support unknown 21/32, còn bất đồng rubric và review-status object binding. Đề xuất review contract/coverage theo nhóm ngôn ngữ và annotated semantic requirements độc lập; chỉ sau một quyết định riêng mới triển khai hướng parser có grammar chặt hơn hoặc semantic parser với strict validation. Không mở thêm tầng heuristic/tune trên 32 cases trong FIX3; chưa thực hiện đề xuất tiếp theo.', '',
        '## Tests, hashes và package', '',
        '| Scope | Passed | Subtests | Failed | Skipped |', '| --- | --- | --- | --- | --- |']
    for run in tests:
        lines.append(f"| {run['scope']} | {run['passed']} | {run['subtests_passed']} | {run['failed']} | {run['skipped']} |")
    lines += ['', 'Exact commands đã chạy (Windows TEMP dùng vì workspace ACL, không phải dependency/model download):', '']
    for run in tests:
        lines += ['```powershell', run['command'], '```', '']
    lines += ['Experiment command: `.\\.venv\\Scripts\\python.exe -B scripts/evaluate_parser_policy_fix3.py`. Replay audit là consistency check của saved outputs, không thêm experiment/independent sample. `validation_results.json` ghi số contexts/decisions/field quotes được kiểm tra và frozen hashes. `protected_hashes_after.json` ghi SHA-256 trước/sau toàn bộ 5.528 baseline paths; `protected_hash_summary.md` ghi raw inputs, approved bundle, FIX1, FIX2 và ZIPs cũ. Chỉ PROJECT_PROGRESS thay đổi theo append-only prefix.', '',
        'Package `outputs/review/graphrag_parser_policy_fix3_review.zip` chứa source/tests/dependency closure, frozen configs/design, requirements/contexts/support traces/decisions, E0–E4 metrics, per-case analysis, actual test logs, hashes và `review_inventory.json`. `zip_verification.json` bên ngoài ghi archive/inventory SHA-256, unique safe regular entries, CRC/testzip và payload sizes/hashes. Dừng chờ review FIX3.']
    (REVIEW / 'report.md').write_bytes(('\n'.join(lines) + '\n').encode('utf-8'))
    per_case = ['# FIX3 — Toàn bộ 32 development cases', '', 'Các labels/rubric sau đây chỉ được evaluator đọc ngoài runtime. A=abstain, P=proceed. Quotes chi tiết cho mọi case thay đổi ở `changed_cases.md`.', '',
        '| Case | Label | E0 | E1 | E2 | E3 | E4 | Parser E4 | Support E4 | External context E4 |', '| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |']
    for record in records['E4']:
        identifier = record['case_id']
        per_case.append('| ' + ' | '.join([identifier, record['expected_decision']] + [decisions[arm][identifier]['decision'] for arm in ARMS] + [record['query_analysis_status'], record['support_status'], str(record['context_sufficient'])]) + ' |')
    for record in records['E4']:
        identifier = record['case_id']
        per_case += ['', '## ' + identifier, '', requirements['E4'][identifier]['query'], '',
            'Expected: `' + record['expected_decision'] + '`; category `' + record['category'] + '`; language `' + record['language'] + '`.', '',
            '| Arm | Scope | Parser/support | Decision | Reason codes |', '| --- | --- | --- | --- | --- |']
        for arm in ARMS:
            trace = decisions[arm][identifier]['trace']
            per_case.append(f"| {arm} | {trace['scope_assessment']['status']} | {requirements[arm][identifier]['analysis_status']}/{trace['support_assessment']['status']} | {trace['final_decision']} | {', '.join(trace['reason_codes']) or '—'} |")
        per_case += ['', 'E4 requirements: `' + compact([{key: req[key] for key in ('requirement_id', 'kind', 'parameters', 'analysis_status')} for req in requirements['E4'][identifier]['requirements']]) + '`.', '',
            'E4 support detail: `' + compact([{key: req[key] for key in ('requirement_id','status','reason_codes','completeness','contradiction')} for req in decisions['E4'][identifier]['trace']['verification_guards']['requirements']]) + '`.', '',
            'External context: `' + str(record['context_sufficient']) + '`; basis `' + record['context_sufficiency_basis'] + '`.']
    (REVIEW / 'per_case_report.md').write_bytes(('\n'.join(per_case) + '\n').encode('utf-8'))
    full = next(item for item in tests if item['scope'] == 'full suite')
    appendix = f'''
## 13. Checkpoint GRAPHRAG-2D3-FIX3 — 17/10/2026

Đã thêm parser/context/support v2, policy composition riêng, research runner E0–E4 và 5 test files; giữ nguyên mọi source/tests/fixtures cũ và replay exact FIX2 D. Policy/design cùng hashes source được khóa trước benchmark, một design duy nhất, không sweep hoặc sửa runtime theo kết quả. E1 có checker compatibility cho requirement contract mới; E2 giữ old checker assessment và independent guards riêng. Labels/reference answers/rubric ngoài runtime. Không rebuild corpus/graph/index, đổi model hay gọi embedding/LLM.

E0 TP/TN/FP/FN=2/16/0/14; E1=5/16/0/11; E2=6/16/0/10; E3=8/16/0/8; E4=9/16/0/7. E4 cứu thêm 7 dataset positives so E0, gồm 4 VI, không mất baseline TP hoặc thêm dataset FP; EN=5/8/0/3, VI=4/8/0/4. Coverage9/32, selective error0/9, recall9/16; false abstain/context đủ6/14. Parser13supported/8ambiguous/11unsupported; support9supported/2missing/21unknown. URL-download đã bind PowerShell/download/url và kiểm tra trực tiếp missing, không còn parserunknown. Limits/chain completeness so exact source identities, host/GUID/sourceentity instances; không nối basename/PID khác lifetime, giữ unknown cho cycle/depth/unresolved source boundaries.

E4 tổng18supplements, max6/query; context26582–60995 canonical UTF-8 bytes, mean51389.1875; không cut budget. External AI rubric giữ nguyên: rp-vi-service-action proceed theo approved label nhưng context_sufficient=null vì thiếu exact completion limitation_4; chỉ launch command được chứng minh. E2→E3 mất tạm proxy-technique query do review_status requirement mới, E4 phục hồi bằng scenario metadata; object binding review-status còn cần review, không đồng nhất scenario analysis_status với technique/human approval. 7 false abstains còn lại và 21 supportunknown ngăn tuyên bố khóa production/independent-validation config.

Tests cuối: focused {tests[0]['passed']} passed; regression {tests[1]['passed']} passed; full suite {full['passed']} passed + {full['subtests_passed']} subtests, 0 failed/skipped. Exact commands/logs ở outputs/review/graphrag-parser-policy-fix3/tests.json. Audit5.528 baseline hashes giữ nguyên ngoại trừ append này; toàn bộ tiến độ cũ giữ nguyên bytes làm prefix. Raw inputs, approved bundle, FIX1/FIX2 artifacts và ZIP cũ không đổi; staging rỗng, branch/HEAD không đổi, git diff --check sạch.

Artifacts: outputs/experiments/graphrag-2d3-fix3/; báo cáo/changed cases/inventory tại outputs/review/graphrag-parser-policy-fix3/; ZIP outputs/review/graphrag_parser_policy_fix3_review.zip. Không chạy11proposedprobes/held-out, không production CLI/LLM/UI, không stage/commit/amend/push. Dừng chờ review FIX3; chưa thực hiện đề xuất sửa semantic coverage hoặc kiểm chứng tiếp theo.
'''
    (OUT / 'progress_appendix.md').write_bytes(appendix.encode('utf-8'))
    print('Wrote report, per-case report, analysis metrics and append-only progress text.')


if __name__ == '__main__':
    main()
