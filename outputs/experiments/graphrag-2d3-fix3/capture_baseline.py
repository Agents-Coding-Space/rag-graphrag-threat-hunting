"""Capture existing FIX3 inputs before any runtime implementation edits."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
REVIEW = ROOT / 'outputs/review/graphrag-parser-policy-fix3'
ZIP = ROOT / 'outputs/review/graphrag_parser_policy_fix3_review.zip'


def digest(path):
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT, text=True, encoding='utf-8')


if __name__ == '__main__':
    assert not (OUT / 'preflight.json').exists(), 'Refusing to overwrite baseline'
    names = set(git('ls-files', '--cached', '--others', '--exclude-standard').splitlines())
    for folder in ('data', 'outputs'):
        for directory, children, files in os.walk(ROOT / folder):
            parent = Path(directory)
            children[:] = [name for name in children if name != '__pycache__'
                           and not name.startswith('test-tmp') and parent / name not in (OUT, REVIEW)]
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
    record = {'schema_version': 'graphrag-fix3-preflight/v1',
        'branch': git('branch', '--show-current').strip(), 'head': git('rev-parse', 'HEAD').strip(),
        'working_tree': git('status', '--short'), 'staging': git('diff', '--cached', '--name-only'),
        'protected_hashes': hashes}
    assert not record['staging']
    (OUT / 'preflight.json').write_bytes((json.dumps(record, ensure_ascii=False, indent=2) + '\n').encode('utf-8'))
    print(f'Captured {len(hashes)} hashes and original source/Markdown bytes')
