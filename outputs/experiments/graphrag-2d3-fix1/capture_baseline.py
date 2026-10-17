"""Capture FIX1 baseline, preserving all existing user/prerequisite changes."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
NEW_REVIEW = ROOT / 'outputs/review/graphrag-ground-truth-v2-consumer-sync'
NEW_ZIP = ROOT / 'outputs/review/graphrag_ground_truth_v2_consumer_sync_review.zip'

def digest(path: Path) -> str:
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()

def main() -> None:
    if (OUT / 'preflight.json').exists():
        raise ValueError('Refusing to overwrite FIX1 baseline')
    files = set(subprocess.check_output(['git', 'ls-files', '--cached', '--others', '--exclude-standard'], cwd=ROOT, text=True).splitlines())
    for folder in ('data', 'outputs'):
        for directory, children, names in os.walk(ROOT / folder):
            children[:] = [name for name in children if name != '__pycache__' and not name.startswith('test-tmp') and (Path(directory) / name).resolve() not in (OUT.resolve(), NEW_REVIEW.resolve())]
            for name in names:
                path = Path(directory) / name
                if path.resolve() != NEW_ZIP.resolve():
                    files.add(path.relative_to(ROOT).as_posix())
    hashes = {name: digest(ROOT / name) for name in sorted(files) if (ROOT / name).is_file()}
    expected = '8676d7a1df41058e7f4b1460a0d4bf909fca5d8f20992753e63be7d024268461'
    assert hashes['outputs/review/mshta-ground-truth/scenario_ground_truth.json'] == expected
    record = {'schema_version': 'graphrag-2d3-fix1-preflight/v1', 'client_date': '2026-10-16',
              'branch': subprocess.check_output(['git', 'branch', '--show-current'], cwd=ROOT, text=True).strip(),
              'head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              'staging': subprocess.check_output(['git', 'diff', '--cached', '--name-only'], cwd=ROOT, text=True),
              'working_tree': subprocess.check_output(['git', 'status', '--short'], cwd=ROOT, text=True),
              'protected_hashes': hashes}
    assert not record['staging']
    before = OUT / 'before'
    for name in hashes:
        if name.startswith(('src/', 'scripts/', 'tests/', 'docs/')) or name in ('AGENTS.md', 'PROJECT_CONTEXT.md', 'PROJECT_PROGRESS.md', 'README.md', 'pyproject.toml'):
            target = before / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
    (OUT / 'preflight.json').write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(f'Captured {len(hashes)} baseline hashes and source backups; approved GT hash verified')

if __name__ == '__main__':
    main()
