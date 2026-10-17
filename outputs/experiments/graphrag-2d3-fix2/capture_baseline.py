"""Capture read-only FIX2 inputs and the existing dirty worktree before edits."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
REVIEW = ROOT / 'outputs/review/graphrag-query-aware-answerability'
ZIP = ROOT / 'outputs/review/graphrag_query_aware_answerability_review.zip'


def digest(path: Path) -> str:
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def git(*args: str) -> str:
    return subprocess.check_output(['git', *args], cwd=ROOT, text=True, encoding='utf-8')


if __name__ == '__main__':
    assert not (OUT / 'preflight.json').exists(), 'Refusing to overwrite baseline'
    names = set(git('ls-files', '--cached', '--others', '--exclude-standard').splitlines())
    for folder in ('data', 'outputs'):
        for directory, children, files in os.walk(ROOT / folder):
            parent = Path(directory)
            children[:] = [child for child in children if child != '__pycache__'
                           and not child.startswith('test-tmp') and parent / child not in (OUT, REVIEW)]
            for name in files:
                path = parent / name
                if path != ZIP:
                    names.add(path.relative_to(ROOT).as_posix())
    hashes = {name: digest(ROOT / name) for name in sorted(names) if (ROOT / name).is_file()}
    for name in hashes:
        if name.startswith(('src/', 'scripts/', 'tests/', 'docs/')) or name in ('AGENTS.md', 'PROJECT_CONTEXT.md', 'PROJECT_PROGRESS.md', 'README.md', 'pyproject.toml'):
            target = OUT / 'before' / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
    result = {'schema_version': 'graphrag-fix2-preflight/v1',
              'branch': git('branch', '--show-current').strip(), 'head': git('rev-parse', 'HEAD').strip(),
              'working_tree': git('status', '--short'), 'staging': git('diff', '--cached', '--name-only'),
              'protected_hashes': hashes}
    assert not result['staging']
    (OUT / 'preflight.json').write_bytes((json.dumps(result, ensure_ascii=False, indent=2) + '\n').encode('utf-8'))
    print(f'Captured {len(hashes)} hashes and current source/Markdown backups')
