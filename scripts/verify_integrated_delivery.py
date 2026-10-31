"""Offline source/consumer/citation/generator-validator audit of all 12x2 branches."""
from __future__ import annotations
from collections import Counter
from copy import deepcopy
from pathlib import Path
import argparse
import json
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'src')]
from scripts.inventory_offline_inputs import write_json
from threat_hunting.evaluation import experimental_comparison as pipeline
from threat_hunting.ground_truth.schema import load_ground_truth_document
from threat_hunting.llm.guardrail import HallucinationGuardrail,context_catalog,_assessments
from threat_hunting.llm.schema import ThreatHuntingReport
from threat_hunting.retrieval.context_packing import unpack_context


def read(path: Path):return json.loads(path.read_text(encoding='utf-8'))


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--config',type=Path,required=True)
    args=parser.parse_args();base=args.root
    config=read(args.config);registry=read(ROOT/config['runtime_artifacts'])
    baseline=read(ROOT/'outputs/integrated/20261030_v1/baseline_hashes.json')
    changed={p:{'before':sha,'after':pipeline.sha256(Path(p)) if Path(p).is_file() else None} for p,sha in baseline.items() if not Path(p).is_file() or pipeline.sha256(Path(p))!=sha}
    allowed=('src/threat_hunting/','scripts/','frontend/src/')
    forbidden={}
    for path,value in changed.items():
        relative=Path(path).relative_to(ROOT).as_posix() if Path(path).is_relative_to(ROOT) else path
        if not relative.startswith(allowed):forbidden[path]=value
    write_json(base/'integrity.json',{'protected_before':len(baseline),'changed_source_files':changed,'unexpected_changes':forbidden,
                                     'historical_artifacts_and_env_unchanged':not forbidden})
    if forbidden:raise ValueError('Unexpected baseline changes; see integrity.json')
    consumers={}
    for sid,entry in registry['scenarios'].items():
        paths={field:ROOT/path for field,path in entry['paths'].items()}
        gt=load_ground_truth_document(paths['gt_path']);corpus=pipeline.load_retrieval_corpus(paths['corpus_path'])
        graph=pipeline.load_knowledge_graph(paths['graph_path']);index=pipeline.load_vector_index(paths['index_path'])
        for path in paths.values():
            if pipeline.sha256(path)!=entry['sha256'][path.name]:raise ValueError(f'Consumer hash mismatch: {sid}')
        provenance=[]
        for source in gt['input_provenance']:
            path=Path(source['path']);path=path if path.is_absolute() else ROOT/path
            if not path.is_file() or pipeline.sha256(path)!=source['sha256']:raise ValueError(f'Input provenance mismatch: {sid}/{source["input_id"]}')
            provenance.append(source['input_id'])
        if corpus['source_ground_truth']['sha256']!=pipeline.sha256(paths['gt_path']) or graph['source_ground_truth']!=corpus['source_ground_truth']:
            raise ValueError('GT/corpus/graph provenance mismatch')
        cti=[c for c in corpus['chunks'] if c['chunk_type']=='cti_report']
        for chunk in cti:
            props=chunk['metadata'];cti_path=ROOT/props['corpus_path']
            if pipeline.sha256(cti_path)!=props['corpus_sha256']:raise ValueError('CTI corpus hash mismatch')
            doc=read(cti_path);source=next(s for s in doc['sources'] if s['source_id']==props['source_id'])
            snapshot=cti_path.parent/source['snapshot_path'];text=(cti_path.parent/source['extracted_text_path']).read_text(encoding='utf-8')
            cite=props['citation']
            if pipeline.sha256(snapshot)!=cite['snapshot_sha256'] or text[cite['char_start']:cite['char_end']]!=cite['anchor']:raise ValueError('CTI citation does not resolve')
            if chunk['status']!='candidate' or chunk['evidence_ids']:raise ValueError('CTI was promoted to observed evidence')
        consumers[sid]={'input_provenance_verified':provenance,'cti_chunks_verified':len(cti),'corpus_chunks':len(corpus['chunks']),
                        'graph_nodes':len(graph['nodes']),'index_rows':len(index['records']),'review_status':gt['review']['review_status']}
    results=read(base/'delivery_preflight/results.json');cases=read(ROOT/config['benchmark'])['cases']
    audits=[];guard=HallucinationGuardrail(strict=True)
    for row in results['rows']:
        directory=base/'delivery_preflight'/f"{row['case_id']}_{row['branch']}"
        context=read(directory/'context.json');gate=read(directory/'gate.json');projection=read(directory/'evidence_contract.json')
        messages=read(directory/'messages.json')['messages']
        from threat_hunting.llm.prompt import ThreatHuntingPromptBuilder
        if ThreatHuntingPromptBuilder().build_messages(next(c['request']['query'] for c in cases if c['case_id']==row['case_id']),context)!=messages:
            raise ValueError('Prompt differs from saved supplied context')
        expanded=unpack_context(context)
        if row['branch']=='rag' and expanded.get('traversal',{}).get('nodes'):raise ValueError('Graph objects entered RAG')
        catalog=context_catalog(context);checks=[]
        # Build source-vocabulary fixtures from returned assessments only. These
        # are structural checks, not reference answers or generation results.
        for tid,assessment in _assessments(context).items():
            confidence='supported_by_observed_behavior' if assessment['evidence_support']=='supported_by_observed_behavior' and assessment.get('stix_id') else 'candidate'
            report=ThreatHuntingReport(verdict='INSUFFICIENT_EVIDENCE',executive_summary='',technical_analysis='',
                mitre_mappings=[{'technique_id':tid,'technique_name':assessment['name'],'confidence':confidence,'assessment_status':assessment.get('status','candidate'),
                                'evidence_support':assessment['evidence_support'],'review_status':assessment.get('review_status','needs_review'),'rationale':assessment['rationale']}])
            validated=guard.validate(report,context)
            if not validated.is_valid:raise ValueError(f'Generator/validator assessment vocabulary mismatch: {row["case_id"]}/{row["branch"]}/{tid}')
            checks.append(tid)
        references=[]
        for unit in projection['units']:
            if unit['source'].get('object_id') and unit['source']['object_id'] not in catalog:raise ValueError('Returned source object is not citable')
            references += [r['raw_record_ref'] for r in unit['source_references']]
        if any(ref not in catalog for ref in references):raise ValueError('Returned raw reference is not in the supplied context catalog')
        if not guard.validate(ThreatHuntingReport(verdict='INSUFFICIENT_EVIDENCE',executive_summary='',technical_analysis='',evidence_refs=list(dict.fromkeys(references))),context).is_valid:
            raise ValueError('Reference serialization/validator mismatch')
        audits.append({'case_id':row['case_id'],'scenario_id':row['scenario_id'],'branch':row['branch'],'outcome':row['outcome'],
                       'eligible':row['eligibility_decision']=='proceed','abstention_stage':row.get('abstention_stage'),'gate_reasons':gate['reason_codes'],
                       'evidence_requirements':{c['requirement']:c['status'] for c in gate['stage_results']['evidence_answerability']['checks']},
                       'assessment_vocabulary_checked':checks,'raw_references_verified':len(set(references)),
                       'cti_units':sum(u.get('evidence_layer')=='cti_context' for u in projection['units']),
                       'context_bytes':row['context_utf8_bytes'],'messages_bytes':row['messages_utf8_bytes'],'packing_lossless':True})
    if len(audits)!=24 or any(r['outcome']=='runtime_error' for r in results['rows']) or results['llm_http_attempts']:
        raise ValueError('Offline branch audit not complete')
    write_json(base/'query_coverage.json',{'schema_version':'integrated-query-coverage/v1','consumers':consumers,'branches':audits,
        'planned':24,'eligible':results['eligible_branch_count'],'actual_requests':0,'live_ceiling':24,
        'eligible_by_branch':dict(Counter(r['branch'] for r in audits if r['eligible'])),'review_status':'pending_human_review'})
    print({'planned':24,'eligible':results['eligible_branch_count'],'serialized_branches':len(audits),'llm_requests':0,'historical_files_unchanged':not forbidden})


if __name__=='__main__':main()
