"""Strict local parsing and declaration comparison; never resolve AWS expressions."""
import hashlib
import json
import re

import yaml

from .cfn_template import _TemplateLoader
from .document_model import Document, DocumentInput, Item, Observation, Setting
from .document_services import CATALOG

SENSITIVE = re.compile(r'password|secret(?:accesskey|string|value)?|privatekey|accesskeyid|sessiontoken|credential',re.I)


class InputError(ValueError):
    pass


class DocumentLoader(_TemplateLoader):
    def construct_mapping(self,node,deep=False):
        result={}
        for key_node,value_node in node.value:
            key=self.construct_object(key_node,deep=True)
            if not isinstance(key,str) or key in result:
                raise InputError('duplicate or non-string mapping key')
            result[key]=self.construct_object(value_node,deep=True)
        return result


def parse(raw):
    if len(raw)>2_000_000:raise InputError('input exceeds v1 size limit')
    try:
        text=raw.decode('utf-8-sig')
        if any(isinstance(t,yaml.AliasToken) for t in yaml.scan(text)):
            raise InputError('YAML aliases are not supported; use environment overrides')
        result=yaml.load(text,Loader=DocumentLoader)
        # Also rejects non-JSON YAML types and non-finite numbers.
        json.dumps(result,allow_nan=False)
        return result
    except InputError:
        raise
    except (ValueError,TypeError,UnicodeError,yaml.YAMLError,RecursionError) as exc:
        raise InputError('invalid JSON/YAML input') from None


def secret_literal(value):
    if isinstance(value,dict):
        if any(SENSITIVE.search(k) for k in value):return True
        if isinstance(value.get('Key'),str) and SENSITIVE.search(value['Key']):return True
        return any(secret_literal(v) for v in value.values())
    if isinstance(value,list):return any(secret_literal(v) for v in value)
    return isinstance(value,str) and ('-----BEGIN ' in value and 'PRIVATE KEY-----' in value or
                                     bool(re.search(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b',value)))


def expression(value):
    if isinstance(value,dict):
        return any(k=='Ref' or k.startswith('Fn::') or expression(v) for k,v in value.items())
    if isinstance(value,list):return any(expression(v) for v in value)
    return isinstance(value,str) and '{{resolve:' in value


def sanitize(value):
    if isinstance(value,dict):
        return {k:({'redacted':True} if SENSITIVE.search(k) else sanitize(v)) for k,v in value.items()}
    if isinstance(value,list):return [sanitize(v) for v in value]
    return {'redacted':True} if secret_literal(value) else value


def observe(template,resource,name):
    if template is None:return Observation(state='NO_CFN')
    if not resource.cfn_logical_id:return Observation(state='NO_BINDING')
    pointer=f'/Resources/{resource.cfn_logical_id}'
    body=template['Resources'].get(resource.cfn_logical_id)
    if body is None:return Observation(state='RESOURCE_MISSING',pointer=pointer)
    if body['Type']!=resource.type:return Observation(state='TYPE_MISMATCH',pointer=pointer+'/Type',value=body['Type'])
    properties=body.get('Properties',{})
    pointer+='/Properties/'+name
    if name not in properties:return Observation(state='ABSENT',pointer=pointer)
    value=properties[name]
    if SENSITIVE.search(name):
        safe_ref=value if isinstance(value,dict) and set(value)=={'Ref'} and isinstance(value['Ref'],str) else None
        return Observation(state='REDACTED',pointer=pointer,value=safe_ref)
    if secret_literal(value):return Observation(state='REDACTED',pointer=pointer)
    if 'Condition' in body or 'Transform' in template or 'Transform' in body:
        return Observation(state='CONDITIONAL',pointer=pointer,value=sanitize(value))
    return Observation(state='EXPRESSION' if expression(value) else 'LITERAL',value=sanitize(value),pointer=pointer)


def expected_ref(setting,resources):
    refs=[setting.ref] if isinstance(setting.ref,str) else setting.ref
    if any(not resources[r].cfn_logical_id for r in refs):return None
    values=[{'Ref':resources[r].cfn_logical_id} for r in refs]
    return values if isinstance(setting.ref,list) else values[0]


def compare(setting,observed,resources):
    if observed.state in ('NO_CFN','NO_BINDING'):return 'NOT_COMPARED'
    if observed.state in ('RESOURCE_MISSING','TYPE_MISMATCH'):return 'DIFFERENT'
    if setting.status!='DECIDED':return 'NOT_COMPARED'
    if setting.mode=='OMITTED':
        return 'MATCH' if observed.state=='ABSENT' else 'UNRESOLVED' if observed.state=='CONDITIONAL' else 'DIFFERENT'
    if setting.mode in ('DEFAULT','EXTERNAL_REF','SECRET_REF'):return 'UNRESOLVED'
    if observed.state in ('CONDITIONAL','REDACTED'):return 'UNRESOLVED'
    if observed.state=='ABSENT':return 'DIFFERENT'
    wanted=setting.value
    if setting.mode=='RESOURCE_REF':
        wanted=expected_ref(setting,resources)
        if wanted is None:return 'UNRESOLVED'
        if wanted==observed.value:return 'MATCH'
        # Only direct resource Refs establish a differing identity.
        vals=observed.value if isinstance(observed.value,list) else [observed.value]
        if not all(isinstance(v,dict) and set(v)=={'Ref'} and v['Ref'] in {r.cfn_logical_id for r in resources.values()} for v in vals):
            return 'UNRESOLVED'
    elif setting.mode=='EXPRESSION':
        return 'MATCH' if setting.expression==observed.value else 'UNRESOLVED'
    elif observed.state=='EXPRESSION':return 'UNRESOLVED'
    # JSON scalar equality must not equate true and 1.
    return 'MATCH' if json.dumps(wanted,sort_keys=True)==json.dumps(observed.value,sort_keys=True) else 'DIFFERENT'


def normalize(raw,environment,cfn_raw=None):
    parsed=parse(raw)
    if isinstance(parsed,dict) and parsed.get('schema_version')=='1.1':
        from .document_v11 import normalize_schema
        return normalize_schema(raw,environment,cfn_raw)
    spec=DocumentInput.model_validate(parsed)
    # Secret payloads are rejected, including nested values. No original text is retained.
    for resource in spec.resources:
        for item in resource.settings.values():
            if secret_literal(item.value) or secret_literal(item.expression):raise InputError('secret-like literal is prohibited')
    for env in spec.environments:
        for override in env.overrides:
            for item in override.settings.values():
                if secret_literal(item.value) or secret_literal(item.expression):raise InputError('secret-like literal is prohibited')
    env=next((e for e in spec.environments if e.id==environment),None)
    if env is None:raise InputError('unknown environment')
    template=None;notices=[]
    if cfn_raw is not None:
        template=parse(cfn_raw)
        if not isinstance(template,dict) or not isinstance(template.get('Resources'),dict):raise InputError('CFN Resources mapping required')
        for logical,body in template['Resources'].items():
            if not isinstance(body,dict) or not isinstance(body.get('Type'),str) or not isinstance(body.get('Properties',{}),dict):raise InputError('invalid CFN resource shape')
            if logical not in {r.cfn_logical_id for r in spec.resources}:notices.append('Unbound CFN resource: '+logical+' ('+body['Type']+')')
            if body['Type'] in CATALOG:
                unknown=set(body.get('Properties',{}))-CATALOG[body['Type']][1].keys()
                if unknown:notices.append('CFN properties outside v1 catalog: '+logical+' / '+', '.join(sorted(unknown)))
    overrides={o.resource_id:o.settings for o in env.overrides};resources={r.id:r for r in spec.resources};items=[]
    resource_comparisons={}
    for resource_index,resource in enumerate(spec.resources):
        body=template['Resources'].get(resource.cfn_logical_id) if template else None
        resource_comparisons[resource.id]=('NO_CFN' if template is None else 'NO_BINDING' if not resource.cfn_logical_id
            else 'MISSING' if body is None else 'TYPE_MISMATCH' if body['Type']!=resource.type
            else 'CONDITIONAL' if 'Condition' in body or 'Transform' in body or 'Transform' in template else 'PRESENT')
        effective={**resource.settings,**overrides.get(resource.id,{})}
        names=set(effective)
        if template and resource.cfn_logical_id in template['Resources']:
            names|=set(template['Resources'][resource.cfn_logical_id].get('Properties',{})) & CATALOG[resource.type][1].keys()
        for name in sorted(names):
            common=resource.settings.get(name)
            setting=effective.get(name,Setting(status='UNDECIDED',rationale='Design setting not supplied'))
            origin='environment' if name in overrides.get(resource.id,{}) else 'common' if common else 'cfn_only'
            input_pointer=(f'/environments/{spec.environments.index(env)}/overrides/{next(i for i,o in enumerate(env.overrides) if o.resource_id==resource.id)}/settings/{name}'
                           if origin=='environment' else f'/resources/{resource_index}/settings/{name}' if common else '')
            observed=observe(template,resource,name)
            items.append(Item(item_id=resource.id+'.'+name,row_id=env.id+'/'+resource.id+'.'+name,
                resource_id=resource.id,name=name,input_pointer=input_pointer,service=CATALOG[resource.type][0],expected=setting,
                common=common if origin=='environment' else None,origin=origin,defined=observed,
                comparison=compare(setting,observed,resources)))
    connection_comparisons={}
    for conn in spec.connections:
        result='NOT_COMPARED'
        if conn.kind=='REFERENCE' and conn.status=='DECIDED':
            current=next((x.expected for x in items if x.resource_id==conn.source and x.name==conn.property),None)
            if current and current.mode=='RESOURCE_REF':
                targets=[current.ref] if isinstance(current.ref,str) else current.ref
                if conn.target not in targets:raise InputError('connection contradicts effective resource reference')
            observed=observe(template,resources[conn.source],conn.property)
            if isinstance(observed.value,list) and observed.state in ('LITERAL','EXPRESSION'):
                values=[Observation(state=observed.state,value=v,pointer=observed.pointer) for v in observed.value]
                comparisons=[compare(Setting(mode='RESOURCE_REF',ref=conn.target),v,resources) for v in values]
                result='MATCH' if 'MATCH' in comparisons else 'UNRESOLVED' if 'UNRESOLVED' in comparisons else 'DIFFERENT'
            else:result=compare(Setting(mode='RESOURCE_REF',ref=conn.target),observed,resources)
        connection_comparisons[conn.id]=result
    notices+=['Generation validates the document structure, not AWS deployability or design correctness.',
              'Traffic, routes, security permissions, availability and recovery feasibility are not evaluated.']
    from .document_checklist import attach
    return attach(Document(environment_id=env.id,input_sha256=hashlib.sha256(raw).hexdigest(),
        cfn_sha256=hashlib.sha256(cfn_raw).hexdigest() if cfn_raw is not None else None,
        design=spec,items=items,resource_comparisons=resource_comparisons,connection_comparisons=connection_comparisons,notices=notices))
