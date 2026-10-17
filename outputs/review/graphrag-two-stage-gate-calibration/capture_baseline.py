"""Capture the protected baseline before calibration implementation or execution."""
from pathlib import Path
import hashlib
import json
import os
import subprocess

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent

def digest(path: Path) -> str:
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()

def main() -> None:
    target = OUT / 'preflight.json'
    if target.exists():
        raise ValueError('Refusing to replace existing calibration baseline snapshot')
    paths = set(subprocess.check_output(['git', 'ls-files'], cwd=ROOT, text=True).splitlines())
    paths.update(('docs/human_approval.md', 'tests/test_ground_truth_approval.py'))
    paths.update('src/threat_hunting/ground_truth/' + name for name in ('approval.py', 'approval_update.py', 'review_artifacts.py'))
    for folder in ('data', 'outputs'):
        for directory, children, names in os.walk(ROOT / folder):
            children[:] = [name for name in children if not name.startswith('test-tmp') and name != '__pycache__' and (Path(directory) / name).resolve() != OUT.resolve()]
            for name in names:
                paths.add((Path(directory) / name).relative_to(ROOT).as_posix())
    hashes = {name: digest(ROOT / name) for name in sorted(paths) if (ROOT / name).is_file()}
    # Approval verification only; no rerun of the prerequisite test suite.
    approved = json.loads((ROOT / 'outputs/review/mshta-human-approval/postflight.json').read_text(encoding='utf-8'))
    for name, pair in approved['artifact_hashes'].items():
        assert hashes['outputs/review/mshta-ground-truth/' + name] == pair['after'], name
    record = {
        'schema_version': 'two-stage-calibration-preflight/v1',
        'client_date': '2026-10-16',
        'branch': subprocess.check_output(['git', 'branch', '--show-current'], cwd=ROOT, text=True).strip(),
        'head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        'working_tree': subprocess.check_output(['git', 'status', '--short'], cwd=ROOT, text=True),
        'staging': subprocess.check_output(['git', 'diff', '--cached', '--name-only'], cwd=ROOT, text=True),
        'protected_hashes': hashes,
        'exclusions': ['new calibration review directory/zip', 'generated test-tmp directories', '__pycache__'],
    }
    assert not record['staging']
    target.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(f'Captured {len(hashes)} protected file hashes; approved artifact hashes match')

if __name__ == '__main__':
    main()
