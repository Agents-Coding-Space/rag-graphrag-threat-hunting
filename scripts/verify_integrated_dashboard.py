"""Verify the existing dashboard API with the integrated profile, offline only."""
from pathlib import Path
import argparse
import json
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'src')]
from fastapi.testclient import TestClient
from scripts.inventory_offline_inputs import write_json
from threat_hunting.server.experimental import ExperimentalSession,create_app


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--pin',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--report',type=Path,required=True)
    args=parser.parse_args()
    def forbidden(**kwargs):raise AssertionError('No real LLM client is permitted by dashboard QA')
    session=ExperimentalSession(args.output,config_path=args.config,pin_path=args.pin,client_factory=forbidden)
    checks=[]
    with TestClient(create_app(session)) as client:
        assert client.get('/').status_code==200
        config=client.get('/experimental-api/config').json()
        assert config['profile_id']=='integrated-three-scenarios-cti-v5'
        assert len(config['presets'])==12 and config['maximum_llm_requests']==0
        assert client.get('/experimental-api/config?profile=unknown').status_code==422
        for preset in config['presets']:
            assert set(preset)=={'case_id','scenario_id','query'}
            for branch in ('rag','graphrag'):
                response=client.get('/experimental-api/saved',params={'case_id':preset['case_id'],'branch':branch}).json()
                assert response['request']['query']==preset['query'] and response['request']['branch']==branch
                assert response['result']['llm_http_attempts']==0 and response['report'] is None
                assert response['provenance']['mode']=='saved_offline_preflight'
                assert response['evidence_contract']['schema_version']=='source-evidence-contract/v2'
                checks.append({'case_id':preset['case_id'],'branch':branch,'outcome':response['outcome'],
                               'cti_units':sum(u.get('evidence_layer')=='cti_context' for u in response['evidence_contract']['units'])})
        historical=client.get('/experimental-api/config?profile=historical-replay').json()
        assert historical['mode']=='historical_replay_only' and historical['generation_disabled']
        old=client.get('/experimental-api/saved',params={'case_id':'PS02','branch':'rag','profile':'historical-replay'}).json()
        assert old['provenance']['mode']=='saved_experimental_replay'
        assert client.post('/experimental-api/hunt?profile=historical-replay',json={'query':'Synthetic request','scenario_id':'purplesharp-ad','branch':'rag'}).status_code==409
        assert client.post('/api/hunt',json={}).status_code in {404,405}
        assert client.get('/.env').status_code==404
        # One real shared offline query, no saved-answer shortcut or provider.
        preset=config['presets'][0]
        response=client.post('/experimental-api/hunt',json={'query':preset['query'],'scenario_id':preset['scenario_id'],'branch':'rag'}).json()
        assert response['outcome'] in {'dry_run_no_generation','abstain'}
        assert response['result']['llm_http_attempts']==session.attempts==0
        checks.append({'shared_pipeline_offline_query':True,'outcome':response['outcome'],'provider_constructed':False})
    write_json(args.report,{'schema_version':'integrated-dashboard-qa/v1','checks':checks,'http_static_dashboard':True,
                            'profiles_separate':True,'preset_rubric_excluded':True,'llm_attempts':0,
                            'scope':'HTTP adapter, saved contexts/source labels, existing built dashboard; browser visual layout not asserted'})
    print({'saved_branches_verified':24,'shared_offline_query':True,'llm_attempts':0})


if __name__=='__main__':main()
