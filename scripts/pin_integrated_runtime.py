"""Freeze an offline-verified integrated configuration before live use."""
from pathlib import Path
import argparse
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'src')]
from threat_hunting.evaluation import experimental_comparison as pipeline
from threat_hunting.llm.config import LLMConfig


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--preflight',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    config=pipeline._read(args.config)
    results=pipeline._read(args.preflight/'results.json')
    manifest=pipeline._read(args.preflight/'manifest.json')
    if results['llm_http_attempts'] or results['planned_branch_count']!=24 or any(r['outcome']=='runtime_error' for r in results['rows']):
        raise ValueError('Require all 24 branches serialized without runtime errors and zero LLM attempts')
    if pipeline.sha256(args.config)!=manifest['config_sha256']:
        raise ValueError('Config changed since preflight')
    case_path=ROOT/config['benchmark']
    if pipeline.sha256(case_path)!=manifest['cases_sha256']:
        raise ValueError('Locked questions/rubric changed')
    paths=pipeline._runtime_sources(ROOT/config['runtime_artifacts'])
    if pipeline._source_manifest(paths)!=manifest['artifacts']:
        raise ValueError('Consumers changed after preflight')
    pin={**manifest,'schema_version':'integrated-runtime-pin/v1','offline_preflight_path':args.preflight.resolve().relative_to(ROOT).as_posix(),
         'model':pipeline._safe_config(LLMConfig.from_env()),'code_sha256':pipeline._code_manifest(),
         'profile_id':config['profile_id'],'approval_status':'pending_human_review','research_draft_runnable':True}
    pipeline._write(args.output,pin)
    print({'pin':str(args.output),'planned':24,'eligible':results['eligible_branch_count'],'actual_llm_requests':0,'live_ceiling':24})


if __name__=='__main__':main()
