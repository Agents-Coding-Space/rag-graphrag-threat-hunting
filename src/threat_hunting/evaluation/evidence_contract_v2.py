"""Generic authentication, process-correlation and CTI source witnesses.

No case IDs, expected decisions, rubric, corpus lookup or IO enter this gate.
Topical thresholds remain exactly the supplied existing policy.
"""
from copy import deepcopy
import re

from .evidence_contract import project_evidence, observations, evidence_support, fold, walk, trace

VERSION = "source-evidence-contract/v2"


def safe_fields(fields: dict) -> dict:
    """Gate witnesses retain relevant scalar bindings, not executable payloads."""
    return {k:v for k,v in fields.items() if k not in {'command_line','CommandLine','parent_command_line','ParentCommandLine'}}


def layer(unit: dict) -> str:
    if any(obj.get("evidence_layer") == "cti_context" for obj, _ in walk(unit["properties"])):
        return "cti_context"
    return "observed_telemetry" if unit["status"] == "observed" else "inferred_correlation" if unit["status"] == "inferred" else "candidate_assessment"


def assess_integrated_evidence_gate(query: str, context: dict, legacy: dict) -> tuple[dict, dict]:
    from threat_hunting.retrieval.context_packing import unpack_context
    packed = 'source_observation_catalog' in context
    context = unpack_context(context)
    projection = project_evidence(context)
    projection["schema_version"] = VERSION
    if packed:
        projection['source_observation_resolution'] = 'source-observation-interning/v1: field pointers address the losslessly expanded supplied context; raw refs retain their original source identity'
    for unit in projection["units"]: unit["evidence_layer"] = layer(unit)
    units = projection["units"]
    telemetry = [u for u in units if u["evidence_layer"] != "cti_context"]
    query_tasks = re.split(r"[;,.]\s*(?:không|do not)\b",query,flags=re.I)[0]
    request = fold(query_tasks)
    auth = any(word in request for word in ("4625", "4776", "password spray", "dang nhap", "authentication"))
    cti = bool(re.search(r"\b(cti|red canary|redcanary|uptycs|microsoft)\b", request))
    correlation = any(word in request for word in ("tuong quan", "correlation", "parent/child")) or "→" in query
    limits = any(word in request for word in ("chung minh", "completion", "hoan tat", "exfiltration", "output", "service state", "trang thai dich vu"))
    checks = []
    def add(kind, witnesses, reason):
        checks.append({"requirement":kind,"status":"supported" if witnesses else "missing","witnesses":witnesses,
                       "reason_code":"source_witness_present" if witnesses else reason})
    obs = observations(telemetry)
    scope_limits=[]
    for unit in telemetry:
        if not unit['source_bound']:continue
        if unit['object_type']=='limitation':scope_limits.append((unit,unit['text']))
        for value,path in walk(unit['properties']):
            if isinstance(value.get('scope_limitations'),list):
                scope_limits.extend((unit,text) for text in value['scope_limitations'] if isinstance(text,str))
    # Auth fields are additional canonical/raw aliases, never guessed from prose.
    auth_rows = []
    for unit in telemetry:
        if not unit["source_bound"] or unit["status"] != "observed": continue
        refs = {(r["source_file"],r["raw_record_ref"]) for r in unit["source_references"]}
        for obj,path in walk(unit["properties"]):
            raw = obj.get("original_fields")
            if not isinstance(raw,dict) or (obj.get("source_file"),obj.get("raw_record_ref")) not in refs: continue
            if str(raw.get("EventID")) not in {"4624","4625","4776","4769"}: continue
            auth_rows.append((unit,path,raw,obj))
    if auth:
        wants_success = "dang nhap thanh cong" in request or "successful logon" in request
        valid = [(u,p,r,o) for u,p,r,o in auth_rows if str(r.get("EventID")) in ({"4624"} if wants_success else {"4625","4776"})
                 and r.get("TargetUserName") and (str(r.get("EventID")) == "4624" or r.get("Status"))]
        add("authentication_fields",[trace(u,p+"/original_fields",r) for u,p,r,_ in valid],"authentication_account_outcome_fields_missing")
        if correlation and not wants_success:
            candidates=[]
            for unit in telemetry:
                if not unit["source_bound"] or unit["status"] not in {"observed","inferred"} or not unit["source_references"]: continue
                for obj,path in walk(unit["properties"]):
                    summary=obj.get("authentication_correlation")
                    if isinstance(summary,dict) and summary.get("paired_attempts") is not None and summary.get("countable_attempts") is not None:
                        candidates.append(trace(unit,path+"/authentication_correlation",summary))
            add("deduplicated_authentication",candidates,"authentication_correlation_summary_missing")
        if wants_success:
            candidates=[trace(u,p+"/logon_investigation",v["logon_investigation"]) for u in telemetry if u["source_bound"] for v,p in walk(u["properties"]) if isinstance(v.get("logon_investigation"),dict)]
            add("success_failure_context",candidates,"logon_temporal_context_missing")
    elif correlation and ("parent/child" in request or "→" in query):
        creation=[o for o in obs if str(o['fields'].get('event_id')) in {'1','4688'} and o['fields'].get('parent_process_name') and o['fields'].get('process_name')]
        process_pairs={(str(o['fields']['parent_process_name']).casefold(),str(o['fields']['process_name']).casefold()) for o in creation}
        add("process_chain",[trace(o['unit'],'properties',safe_fields(o['fields'])) for o in creation] if len(process_pairs)>=2 else [],"two_process_relationships_missing")
        if "connections" in request or "network" in request:
            networks=[o for o in obs if str(o['fields'].get('event_id'))=='3' and o['fields'].get('destination_ip') and o['fields'].get('destination_port')]
            add("process_bound_network",[trace(o['unit'],'properties',safe_fields(o['fields'])) for o in networks],"process_network_observations_missing")
            summaries=[trace(u,p,v) for u in telemetry if u['source_bound'] for v,p in walk(u['properties']) if isinstance(v.get('connection_summary'),dict) or isinstance(v.get('correlation_policy'),dict)]
            add("network_correlation_policy",summaries,"network_identity_lifetime_summary_missing")
        if "core" in request:
            limits_core=[trace(u,'properties' if u['object_type']!='limitation' else 'text',text) for u,text in scope_limits if 'core' in fold(text)]
            add("core_boundary",limits_core,"core_boundary_missing")
    elif limits and not cti:
        named=[o for o in obs if (str(o['fields'].get('process_name') or '').replace('\\','/').rsplit('/',1)[-1].casefold().removesuffix('.exe') in request
                                  and o['fields'].get('process_name')) or ('get-service' in request and 'get-service' in str(o['fields'].get('command_line','')).casefold())]
        add('observed_outcome_anchor',[trace(o['unit'],'properties',safe_fields(o['fields'])) for o in named],'relevant_observed_anchor_not_returned')
        facets={'completion':('completion','hoan tat'), 'output':('output','dau ra'), 'service_state':('service state','trang thai dich vu'),
                'exfiltration':('exfiltration','danh cap'), 'bytes':('bytes','dung luong'), 'c2_purpose':('c2 da xac nhan','confirmed c2')}
        for facet,words in facets.items():
            if not any(w in request for w in words):continue
            candidates=[trace(u,'properties' if u['object_type']!='limitation' else 'text',text) for u,text in scope_limits
                        if any(w in fold(text) for w in words) and any(negative in fold(text) for negative in ('not','unverified','khong','chua','does not','do not'))]
            add('limit_'+facet,candidates,'explicit_requested_limit_not_returned')
    elif not cti or any(w in request for w in ("command line","dong lenh","ip va cong")):
        # A negative instruction is a constraint on the answer, not an additional
        # request to establish the result of an unobserved action.
        previous = evidence_support(query_tasks,{**projection,"units":telemetry})
        checks.extend(previous["checks"])
    if cti:
        witnesses=[]
        named=[name for name in ("microsoft","red canary","redcanary","uptycs") if name in request]
        for unit in units:
            if not unit["source_bound"] or unit['evidence_layer']!='cti_context': continue
            for obj,path in walk(unit['properties']):
                citation=obj.get('citation')
                if (isinstance(citation,dict) and re.fullmatch(r'[0-9a-f]{64}',str(citation.get('snapshot_sha256','')))
                        and citation.get('url') and citation.get('char_start') is not None and obj.get('publisher')
                        and (not named or any(name.replace(' ','') in fold(str(obj['publisher'])).replace(' ','') for name in named))):
                    witnesses.append(trace(unit,path+"/citation",citation))
        add("external_cti_context",witnesses,"publisher_bound_cti_citation_missing")
        add("separate_observed_anchor",[trace(o['unit'],'properties',safe_fields(o['fields'])) for o in obs] + [trace(u,p+'/original_fields',r) for u,p,r,_ in auth_rows],"local_telemetry_anchor_missing")
    if auth and limits:
        witnesses=[trace(u,'text',u['text']) for u in telemetry if u['source_bound'] and u['object_type'] in {'limitation','evidence'} and
                   any(w in fold(u['text']) for w in ('does not prove','does not establish','not establish','unobserved','khong','chua'))]
        add("authentication_outcome_limits",witnesses,"explicit_authentication_outcome_limit_missing")
    if not checks:
        add("recognized_query",[],"unsupported_query_contract")
    bound=[u for u in units if u['origin']['kind']=='chunk' and u['source_bound'] and u['source_references']]
    add("bound_retrieved_source",[trace(u,'source',u['source']) for u in bound],"bound_source_missing")
    topical=legacy['stage_results']['topical_relevance']
    missing=[c['reason_code'] for c in checks if c['status']!='supported']
    reasons=topical['reason_codes'] if topical['status']!='passed' else list(dict.fromkeys(missing))
    support={"schema_version":VERSION,"requirements":{"authentication":auth,"cti":cti,"correlation":correlation,"limits":limits},"checks":checks,
             "status":"missing" if missing else "supported","reason_codes":list(dict.fromkeys(missing))}
    decision={"schema_version":"source-evidence-gate-decision/v2","contract":VERSION,"decision":"abstain" if reasons else "proceed",
              "abstention_stage":"topical_relevance" if topical['status']!='passed' else "evidence_answerability" if reasons else None,
              "reason_codes":reasons,"stage_results":{"topical_relevance":deepcopy(topical),"evidence_answerability":support},
              "legacy_policy_id":legacy['policy_id'],"human_review_required":True,"interpretation":"Research context eligibility, not claim truth or human approval."}
    return decision,projection
