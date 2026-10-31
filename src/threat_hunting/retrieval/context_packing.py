"""Lossless interning of repeated observation objects in supplied context.

This changes serialization only: no fields, sources or returned objects are
removed. Hash-keyed references resolve to the same complete source observation.
"""
from copy import deepcopy
import hashlib
import json

CONTRACT = "source-observation-interning/v1"


def observation_key(value: dict) -> str:
    return "observation--"+hashlib.sha256(json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode('utf-8')).hexdigest()


def reference_key(value: dict) -> str:
    # Compact content address, checked for collision at insertion and resolution.
    return 'r-'+observation_key(value).removeprefix('observation--')[:20]


def pack_context(context: dict) -> dict:
    if 'source_observation_catalog' in context:
        raise ValueError('Context already contains an observation catalog')
    catalog={}
    references={}
    def visit(value, field=None):
        if field=='source_observations' and isinstance(value,list):
            result=[]
            for item in value:
                if isinstance(item,dict) and item.get('source_file') and item.get('raw_record_ref') and (isinstance(item.get('canonical_fields'),dict) or isinstance(item.get('original_fields'),dict)):
                    key=observation_key(item);catalog[key]=deepcopy(item);result.append({'source_observation_key':key})
                else: result.append(visit(item))
            return result
        if isinstance(value,dict):
            if set(value)=={'source_file','raw_record_ref'} and all(isinstance(v,str) and v for v in value.values()):
                key=reference_key(value)
                if key in references and references[key]!=value: raise ValueError('Raw reference content-address collision')
                references[key]=deepcopy(value)
                return {'raw_reference_key':key}
            return {k:visit(v,k) for k,v in value.items()}
        if isinstance(value,list): return [visit(v) for v in value]
        return deepcopy(value)
    result=visit(context)
    result['source_observation_contract']=CONTRACT
    result['source_observation_catalog']={k:catalog[k] for k in sorted(catalog)}
    result['raw_reference_catalog']={k:references[k] for k in sorted(references)}
    if unpack_context(result)!=context:
        raise ValueError('Observation packing was not lossless')
    return result


def expand_item(value, context: dict):
    catalog=context.get('source_observation_catalog',{})
    if isinstance(value,dict):
        if set(value)=={'raw_reference_key'}:
            key=value['raw_reference_key'];reference=context.get('raw_reference_catalog',{}).get(key)
            if not isinstance(reference,dict) or reference_key(reference)!=key:
                raise ValueError('Missing or tampered raw source reference')
            return deepcopy(reference)
        if set(value)=={'source_observation_key'}:
            key=value['source_observation_key']
            item=catalog.get(key)
            if not isinstance(item,dict) or observation_key(item)!=key:
                raise ValueError('Missing or tampered source observation reference')
            return deepcopy(item)
        return {k:expand_item(v,context) for k,v in value.items()}
    if isinstance(value,list): return [expand_item(v,context) for v in value]
    return deepcopy(value)


def unpack_context(context: dict) -> dict:
    if 'source_observation_catalog' not in context: return deepcopy(context)
    if context.get('source_observation_contract')!=CONTRACT: raise ValueError('Unknown source observation packing contract')
    return expand_item({k:v for k,v in context.items() if k not in {'source_observation_catalog','source_observation_contract','raw_reference_catalog'}},context)
