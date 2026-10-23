"""Schema-driven document contract 1.1, with recursive design decisions."""
import hashlib
import json
import re
from typing import Literal

from pydantic import ConfigDict, Field, model_validator

from .document_catalog import catalog, matches, pointer, input_type_inventory
from .document_decisions import Decision, Section, validate_decisions
from .document_changes import ChangeRecord
from .document_model import (ID, Connection, Document, DocumentInput, Environment, Item, Observation,
                             Override, Resource, Setting)
from .document_normalize import InputError, compare, expression, parse, secret_literal
from .document_requirements import validate_requirements

# Policy data complements names; write-only is metadata, not synonymous with secret.
SECRET_PATHS={
 'AWS::ApiGateway::ApiKey':['/properties/Value'],
 'AWS::IAM::User':['/properties/LoginProfile/Password'],
 'AWS::SSM::Parameter':['/properties/Value'],  # conservatively reference-only
 'AWS::MSK::Configuration':['/properties/ServerProperties'],
}
SECRET_NAME=re.compile(r'(?:password|secretstring|secretbinary|secretaccesskey|privatekey|token|clientsecret|accesskeyid|accesskey|apikey|secret|credentials?)$',re.I)


def sensitive(kind,parts):
    if any(matches(p,parts) for p in SECRET_PATHS.get(kind,[])):return True
    return any(SECRET_NAME.search(str(p).replace('_','').replace('-','')) for p in parts if p not in ('GenerateSecretString','ClientRequestToken','ClientToken'))


class SchemaSetting(Setting):
    model_config=ConfigDict(json_schema_extra={'allOf':[
        r for r in Setting.model_config['json_schema_extra']['allOf']
        if r.get('if',{}).get('properties',{}).get('mode',{}).get('const')!='LITERAL']+[
        {'if':{'properties':{'mode':{'const':'LITERAL'}},'required':['mode']},
         'then':{'required':['value'],'properties':{'ref':{'type':'null'},'expression':{'type':'null'}}}},
        {'if':{'properties':{'mode':{'const':'COMPOSITE'}},'required':['mode']},
         'then':{'required':['value'],'properties':{'value':{'type':['object','array']}}}}
    ]})
    mode: Literal['LITERAL','DEFAULT','OMITTED','RESOURCE_REF','EXTERNAL_REF','EXPRESSION','SECRET_REF','COMPOSITE'] | None = None
    # Basic-design decisions this value realizes; explicit links only.
    decision_ids: list[ID]=Field(default_factory=list)

    @model_validator(mode='after')
    def shape(self):
        if self.status=='DECIDED' and self.mode=='LITERAL' and self.value is None and 'value' in self.model_fields_set:
            if self.ref is not None or self.expression is not None or self.classification=='SECRET':raise ValueError('invalid literal null setting')
            return self
        if self.mode!='COMPOSITE':return super().shape()
        if self.status!='DECIDED' or not isinstance(self.value,(dict,list)) or self.ref is not None or self.expression is not None or self.classification=='SECRET':
            raise ValueError('composite requires a non-secret decided object/array; secret leaves use references')
        return self


class SchemaResource(Resource):
    model_config=ConfigDict(json_schema_extra={})
    type: str = Field(json_schema_extra={'enum':input_type_inventory()})
    settings: dict[str,SchemaSetting]=Field(default_factory=dict)
    region: str | None = Field(default=None, pattern=r'^[a-z]{2}(?:-gov)?-[a-z]+-\d+$')


class SchemaOverride(Override):
    settings: dict[str,SchemaSetting]


class SchemaEnvironment(Environment):
    overrides: list[SchemaOverride]=Field(default_factory=list)


class SchemaInput(DocumentInput):
    schema_version: Literal['1.1']
    resources: list[SchemaResource]=Field(min_length=1)
    environments: list[SchemaEnvironment]=Field(min_length=1)
    design_outline: list[Section] | None = None
    decisions: list[Decision]=Field(default_factory=list)
    # Approved workbook changes, appended by aws-design-changes apply.
    change_log: list[ChangeRecord]=Field(default_factory=list)

    @model_validator(mode='after')
    def integrity(self):
        validate_requirements(self)
        validate_decisions(self)
        if len({c.change_id for c in self.change_log})!=len(self.change_log):raise ValueError('duplicate change ID')
        objects=[self.system,*self.environments,*self.sources,*self.resources,*self.requirements,*self.connections,*self.operations,*self.issues,*self.decisions]
        ids=[x.id for x in objects]
        if len(ids)!=len(set(ids)):raise ValueError('duplicate stable ID')
        resources={r.id:r for r in self.resources};sources={s.id for s in self.sources}
        bindings=[r.cfn_logical_id for r in self.resources if r.cfn_logical_id]
        if len(bindings)!=len(set(bindings)):raise ValueError('duplicate CFN binding')
        decisions={d.id for d in self.decisions}
        def provenance(obj):
            if any(s not in sources for s in obj.sources):raise ValueError('invalid source reference')
            links=getattr(obj,'decision_ids',[])
            if len(links)!=len(set(links)) or set(links)-decisions:raise ValueError('invalid decision reference')
        def validate(resource,values,cat):
            if resource.type not in cat.schemas:raise ValueError('resource is outside the regional service catalog')
            for name,setting in values.items():
                if name not in cat.writable(resource.type):raise ValueError('unknown or read-only top-level property')
                visit_setting(setting,resource.type,[name],resources,provenance,cat=cat)
        for resource in self.resources:provenance(resource)
        for env in self.environments:
            for resource in self.resources:validate(resource,resource.settings,catalog(resource.region or env.region))
            if len({o.resource_id for o in env.overrides})!=len(env.overrides):raise ValueError('duplicate environment override')
            for o in env.overrides:
                if o.resource_id not in resources:raise ValueError('invalid override resource')
                resource=resources[o.resource_id]
                validate(resource,o.settings,catalog(resource.region or env.region))
        for note in [*self.requirements,*self.operations,*self.issues]:
            provenance(note)
            if any(r not in resources for r in note.resources):raise ValueError('invalid note resource')
        for conn in self.connections:
            provenance(conn)
            if conn.source not in resources or conn.target not in resources:raise ValueError('invalid connection endpoint')
            if conn.kind=='REFERENCE':
                source=resources[conn.source]
                if any(conn.property not in catalog(source.region or e.region).writable(source.type) for e in self.environments):raise ValueError('unknown connection property')
            elif conn.property is not None:raise ValueError('only reference connections have a property')
        from .document_decisions import expanded_setting, expansion_targets
        for d in self.decisions:
            for e in d.expansions:
                for env in self.environments:
                    for rid in expansion_targets(self,d,e,env.id):
                        resource=resources[rid];validate(resource,{e.property:expanded_setting(d,e)},catalog(resource.region or env.region))
        from .document_policy_model import validate_policies
        validate_policies(self)
        return self


def visit_setting(setting,kind,parts,resources,provenance,trace=None,*,cat=None):
    """Validate typed decision nodes and preserve their original representation."""
    cat=cat or catalog();provenance(setting)
    if cat.readonly(kind,parts) or not cat.at(kind,parts):raise ValueError('unknown or read-only nested property')
    if trace is not None:trace.append({'path':pointer(parts),'status':setting.status,'mode':setting.mode})
    if setting.status!='DECIDED':return
    if setting.mode=='OMITTED':return
    if sensitive(kind,parts) and setting.mode!='SECRET_REF':raise ValueError('sensitive input requires SECRET_REF')
    if setting.mode=='RESOURCE_REF':
        refs=setting.ref if isinstance(setting.ref,list) else [setting.ref]
        if any(r not in resources for r in refs) or len(refs)!=len(set(refs)):raise ValueError('invalid internal reference')
        for i,r in enumerate(refs):
            targets=cat.reference_targets(kind,[*parts,i] if isinstance(setting.ref,list) else parts)
            if targets and resources[r].type not in targets:raise ValueError('reference target type disagrees with registered reference metadata')
        return
    if setting.mode in ('SECRET_REF','EXTERNAL_REF','DEFAULT','OMITTED'):return
    if setting.mode=='EXPRESSION':
        if secret_literal(setting.expression):raise ValueError('secret-like expression literal')
        return
    def walk(value,path,composite):
        if composite and isinstance(value,dict) and set(value)=={'$design'}:
            visit_setting(SchemaSetting.model_validate(value['$design']),kind,path,resources,provenance,trace,cat=cat);return
        if sensitive(kind,path):raise ValueError('sensitive input requires a typed secret reference')
        if secret_literal(value) and not isinstance(value,(dict,list)):raise ValueError('secret-like literal')
        cat.shape(kind,path,value)
        if isinstance(value,dict):
            # Tag key/value pairs can carry secrets despite an innocuous Value field.
            if isinstance(value.get('Key'),str) and SECRET_NAME.search(value['Key']):
                val=value.get('Value')
                if not (composite and isinstance(val,dict) and set(val)=={'$design'} and val['$design'].get('mode')=='SECRET_REF'):
                    raise ValueError('secret tag value must use a secret reference')
            for k,v in value.items():walk(v,[*path,k],composite)
        elif isinstance(value,list):
            for i,v in enumerate(value):walk(v,[*path,i],composite)
    walk(setting.value,parts,setting.mode=='COMPOSITE')


def materialize(setting,resources):
    """Comparison view only. No default, external or secret values are fetched."""
    if setting.status!='DECIDED' or setting.mode in ('DEFAULT','OMITTED','EXTERNAL_REF','SECRET_REF'):
        return {'$unresolved':setting.mode or setting.status}
    if setting.mode=='RESOURCE_REF':
        refs=setting.ref if isinstance(setting.ref,list) else [setting.ref]
        vals=[{'Ref':resources[r].cfn_logical_id} if resources[r].cfn_logical_id else {'$unresolved':r} for r in refs]
        return vals if isinstance(setting.ref,list) else vals[0]
    if setting.mode=='EXPRESSION':return setting.expression
    if setting.mode=='LITERAL':return setting.value
    def walk(value):
        if isinstance(value,dict):
            if set(value)=={'$design'}:return materialize(SchemaSetting.model_validate(value['$design']),resources)
            return {k:walk(v) for k,v in value.items()}
        if isinstance(value,list):return [walk(v) for v in value]
        return value
    return walk(setting.value)


def redact_cfn(kind,value,path,omissions):
    cat=catalog()
    if cat.readonly(kind,path):omissions.append(pointer(path));return {'$read_only':True}
    if sensitive(kind,path):
        safe=value if isinstance(value,dict) and set(value)=={'Ref'} and isinstance(value['Ref'],str) else None
        return {'$secret_reference':safe} if safe else {'$redacted':True}
    if isinstance(value,dict):
        tag_secret=isinstance(value.get('Key'),str) and bool(SECRET_NAME.search(value['Key']))
        return {k:({'$redacted':True} if tag_secret and k=='Value' else redact_cfn(kind,v,[*path,k],omissions)) for k,v in value.items()}
    if isinstance(value,list):return [redact_cfn(kind,v,[*path,i],omissions) for i,v in enumerate(value)]
    return {'$redacted':True} if secret_literal(value) else value


def unresolved(value):
    if isinstance(value,dict):return any(k.startswith(('$unresolved','$redacted','$secret_reference','$read_only')) or unresolved(v) for k,v in value.items())
    return isinstance(value,list) and any(unresolved(v) for v in value)


def compare_tree(wanted,actual,path=''):
    """Preserve known differences even when a sibling value remains unresolved."""
    def opaque(value):
        return isinstance(value,dict) and any(k.startswith(('$unresolved','$redacted','$secret_reference','$read_only')) for k in value)
    def intrinsic(value):return isinstance(value,dict) and any(k=='Ref' or k.startswith('Fn::') for k in value)
    if opaque(wanted) or opaque(actual):return [{'path':path,'result':'UNRESOLVED'}]
    if intrinsic(wanted) or intrinsic(actual):
        return [{'path':path,'result':'EXPRESSION_MATCH' if json.dumps(wanted,sort_keys=True)==json.dumps(actual,sort_keys=True) else 'UNRESOLVED'}]
    if isinstance(wanted,dict) and isinstance(actual,dict):
        rows=[]
        for key in sorted(set(wanted)|set(actual)):
            child=path+'/'+key.replace('~','~0').replace('/','~1')
            if key not in wanted or key not in actual:
                rows.append({'path':child,'result':'UNRESOLVED' if opaque(wanted.get(key)) or opaque(actual.get(key)) else 'DIFFERENT'})
            else:rows+=compare_tree(wanted[key],actual[key],child)
        return rows or [{'path':path,'result':'MATCH'}]
    if isinstance(wanted,list) and isinstance(actual,list):
        if len(wanted)!=len(actual):return [{'path':path,'result':'UNRESOLVED' if expression(wanted) or expression(actual) else 'DIFFERENT'}]
        return [row for i,(a,b) in enumerate(zip(wanted,actual)) for row in compare_tree(a,b,path+'/'+str(i))] or [{'path':path,'result':'MATCH'}]
    return [{'path':path,'result':'MATCH' if json.dumps(wanted,sort_keys=True)==json.dumps(actual,sort_keys=True) else 'DIFFERENT'}]


def value_resolution(setting):
    """Decision status is independent of whether a declared value is concrete."""
    if setting.status=='NOT_APPLICABLE':return 'NOT_APPLICABLE'
    if setting.status!='DECIDED':return 'UNRESOLVED'
    if setting.mode=='LITERAL':return 'RESOLVED'
    if setting.mode!='COMPOSITE':return 'UNRESOLVED'
    def walk(value):
        if isinstance(value,dict):
            if set(value)=={'$design'}:return {value_resolution(SchemaSetting.model_validate(value['$design']))}
            return set().union(*(walk(v) for v in value.values())) or {'RESOLVED'}
        if isinstance(value,list):return set().union(*(walk(v) for v in value)) or {'RESOLVED'}
        return {'RESOLVED'}
    states=walk(setting.value)
    if states=={'RESOLVED'}:return 'RESOLVED'
    if 'RESOLVED' in states or 'PARTIAL' in states:return 'PARTIAL'
    return 'UNRESOLVED'


class SchemaItem(Item):
    expected: SchemaSetting
    common: SchemaSetting | None = None
    schema_pointer: str
    origin: Literal['common','environment','decision','cfn_only']
    decision_paths: list[dict]=Field(default_factory=list)
    comparison_details: list[dict]=Field(default_factory=list)
    comparison: Literal['MATCH','EXPRESSION_MATCH','DIFFERENT','UNRESOLVED','NOT_COMPARED']
    expected_resolution: Literal['RESOLVED','PARTIAL','UNRESOLVED','NOT_APPLICABLE']
    defined_resolution: Literal['RESOLVED','UNRESOLVED','UNAVAILABLE']
    comparison_basis: str


class SchemaDocument(Document):
    model_version: Literal['1.1']='1.1'
    design: SchemaInput
    items: list[SchemaItem]
    catalog_provenance: dict
    resource_services: dict[str,str]
    read_only_omissions: list[str]
    resource_regions: dict[str,str]=Field(default_factory=dict)
    regional_catalog_provenance: dict[str,dict]=Field(default_factory=dict)
    review_report: dict=Field(default_factory=dict)
    # Local, non-secret values for EXTERNAL_REF settings; evaluation input only.
    external_bindings: dict=Field(default_factory=dict)
    decision_trace: dict=Field(default_factory=dict)
    decision_expansions: list[dict]=Field(default_factory=list)


def normalize_schema(raw,environment,cfn_raw=None):
    parsed=parse(raw)
    # Setup errors must retain their category outside Pydantic's value-error wrapper.
    if isinstance(parsed,dict):
        regions=set()
        for key in ('environments','resources'):
            if isinstance(parsed.get(key),list):
                for entry in parsed[key]:
                    region=entry.get('region') if isinstance(entry,dict) else None
                    if isinstance(region,str) and re.fullmatch(r'[a-z]{2}(?:-gov)?-[a-z]+-\d+',region):regions.add(region)
        for region in sorted(regions):catalog(region)
    spec=SchemaInput.model_validate(parsed)
    env=next((e for e in spec.environments if e.id==environment),None)
    if env is None:raise InputError('unknown environment')
    cats={region:catalog(region) for region in {env.region,*[r.region or env.region for r in spec.resources]}}
    if cfn_raw and len({r.region or env.region for r in spec.resources})>1:
        raise InputError('a single comparison CFN cannot assert multi-region deployment scope')
    template=parse(cfn_raw) if cfn_raw else None;notices=[];omissions=[]
    if template is not None:
        if not isinstance(template,dict) or not isinstance(template.get('Resources'),dict):raise InputError('CFN Resources mapping required')
        for logical,body in template['Resources'].items():
            if not isinstance(body,dict) or not isinstance(body.get('Type'),str) or not isinstance(body.get('Properties',{}),dict):raise InputError('invalid CFN resource shape')
            if logical not in {r.cfn_logical_id for r in spec.resources}:notices.append('Unbound CFN resource: '+logical+' / '+body['Type'])
    resources={r.id:r for r in spec.resources};overrides={o.resource_id:o.settings for o in env.overrides}
    from .document_decisions import expansions
    expanded,expansion_records=expansions(spec,env.id)
    items=[];resource_comparisons={}
    for ri,r in enumerate(spec.resources):
        cat=cats[r.region or env.region]
        body=template['Resources'].get(r.cfn_logical_id) if template else None
        state=('NO_CFN' if template is None else 'NO_BINDING' if not r.cfn_logical_id else 'MISSING' if body is None
               else 'TYPE_MISMATCH' if body['Type']!=r.type else 'CONDITIONAL' if 'Condition' in body or 'Transform' in body or 'Transform' in template else 'PRESENT')
        # Explicit common/environment settings always win over decision expansions.
        derived={name:value for name,(value,_) in expanded.get(r.id,{}).items()}
        resource_comparisons[r.id]=state;effective={**derived,**r.settings,**overrides.get(r.id,{})};names=set(effective)
        props=body.get('Properties',{}) if body and body['Type']==r.type else {}
        for name in props:
            if cat.readonly(r.type,[name]):omissions.append(r.id+pointer([name]));continue
            if name not in cat.writable(r.type):notices.append('CFN property outside fixed schema: '+r.id+'/'+name);continue
            names.add(name)
        for name in sorted(names):
            wanted=effective.get(name,SchemaSetting(status='UNDECIDED',rationale='Design setting not supplied'))
            origin=('environment' if name in overrides.get(r.id,{}) else 'common' if name in r.settings
                    else 'decision' if name in derived else 'cfn_only')
            source=(f'/environments/{spec.environments.index(env)}/overrides/{next(i for i,o in enumerate(env.overrides) if o.resource_id==r.id)}/settings/{name}'
                    if origin=='environment' else f'/resources/{ri}/settings/{name}' if origin=='common'
                    else expanded[r.id][name][1] if origin=='decision' else '')
            obs_state={'MISSING':'RESOURCE_MISSING','PRESENT':'ABSENT'}.get(state,state)
            obs_value=None
            if state in ('PRESENT','CONDITIONAL') and name in props:
                obs_value=redact_cfn(r.type,props[name],[name],omissions)
                obs_state=('CONDITIONAL' if state=='CONDITIONAL' else 'REDACTED' if unresolved(obs_value)
                           else 'EXPRESSION' if expression(obs_value) else 'LITERAL')
            observed=Observation(state=obs_state,value=obs_value,pointer=f'/Resources/{r.cfn_logical_id}/Properties/{name}' if body else '')
            details=[]
            if wanted.mode=='COMPOSITE':
                actual=materialize(wanted,resources)
                if state in ('NO_CFN','NO_BINDING'):result='NOT_COMPARED'
                elif state in ('MISSING','TYPE_MISMATCH') or obs_state=='ABSENT':result='DIFFERENT'
                elif obs_state=='CONDITIONAL':result='UNRESOLVED'
                else:
                    details=compare_tree(actual,obs_value)
                    result=next((label for label in ('DIFFERENT','UNRESOLVED','EXPRESSION_MATCH') if any(d['result']==label for d in details)),'MATCH')
            else:
                result=compare(wanted,observed,resources)
                if wanted.mode=='EXPRESSION' and result=='MATCH' and json.dumps(wanted.expression,sort_keys=True)!=json.dumps(obs_value,sort_keys=True):result='UNRESOLVED'
                if result=='MATCH' and (wanted.mode in ('EXPRESSION','RESOURCE_REF') or expression(obs_value)):result='EXPRESSION_MATCH'
            basis={'MATCH':'LITERAL_VALUE_EQUALITY_ONLY; NOT_DESIGN_APPROVAL',
                'EXPRESSION_MATCH':'DECLARATION_AST_EQUALITY; VALUES_NOT_RESOLVED; NOT_DESIGN_APPROVAL',
                'DIFFERENT':'KNOWN_DECLARATION_DIFFERENCE; SEE_LEAF_DETAILS_OR_OBSERVATION_STATE',
                'UNRESOLVED':'VALUE_OR_CONDITION_NOT_RESOLVED; NOT_DESIGN_APPROVAL',
                'NOT_COMPARED':'NO_COMPARISON; NOT_DESIGN_APPROVAL'}[result]
            if wanted.mode=='OMITTED' and result=='MATCH':basis='DECLARED_OMISSION_MATCH; NOT_INPUT_COMPLETENESS_OR_DESIGN_APPROVAL'
            trace=[];visit_setting(wanted,r.type,[name],resources,lambda x:None,trace,cat=cat)
            items.append(SchemaItem(item_id=r.id+'.'+name,row_id=env.id+'/'+r.id+'.'+name,resource_id=r.id,
                name=name,input_pointer=source,service=cat.services[r.type],expected=wanted,
                common=r.settings.get(name) if origin=='environment' else None,origin=origin,defined=observed,
                comparison=result,schema_pointer=pointer([name]),decision_paths=trace,comparison_details=details,
                expected_resolution=value_resolution(wanted),
                defined_resolution='RESOLVED' if obs_state=='LITERAL' else 'UNRESOLVED' if obs_state in ('EXPRESSION','REDACTED','CONDITIONAL') else 'UNAVAILABLE',
                comparison_basis=basis))
    connections={}
    for conn in spec.connections:
        result='NOT_COMPARED'
        if conn.kind=='REFERENCE' and conn.status=='DECIDED':
            row=next((i for i in items if i.resource_id==conn.source and i.name==conn.property),None)
            if row:
                if row.expected.mode=='RESOURCE_REF' and conn.target not in (row.expected.ref if isinstance(row.expected.ref,list) else [row.expected.ref]):raise InputError('connection contradicts design reference')
                result=compare(SchemaSetting(mode='RESOURCE_REF',ref=conn.target),row.defined,resources)
                if isinstance(row.defined.value,list) and row.defined.state in ('LITERAL','EXPRESSION'):
                    target=resources[conn.target].cfn_logical_id
                    values=row.defined.value
                    if target and {'Ref':target} in values:result='MATCH'
                    elif all(isinstance(v,dict) and set(v)=={'Ref'} and v['Ref'] in {r.cfn_logical_id for r in resources.values()} for v in values):result='DIFFERENT'
                    else:result='UNRESOLVED'
        connections[conn.id]='REFERENCE_MATCH' if result=='MATCH' else result
    notices+=['Required-input checklist evaluates bounded schema obligations separately. General enum/range semantics and deployment validity remain unevaluated.',
              'Array item IDs are JSON pointers: reordering arrays changes index-based leaf paths.',
              'Write-only metadata does not by itself classify an input as secret. Secret values require references.']
    from .document_checklist import attach
    provenance={region:{**{k:c.manifest[k] for k in ('region','source','retrieved_at','zip_sha256')},'reference_catalog_sha256':c.reference_sha256,
                        **{k:c.manifest[k] for k in ('review_status','reviewed_zip_sha256','review_drift') if k in c.manifest}}
                for region,c in cats.items()}
    for region,origin in sorted(provenance.items()):
        if origin.get('review_status')=='DRIFTED_FROM_REVIEWED':
            drift=origin['review_drift']
            notices.append(f"Schema {region} was acquired after the reviewed release and differs from it "
                           f"(added {drift['added']}, changed {drift['changed']}, removed {drift['removed']} types). "
                           'Rules for changed types are reconciled as review-required; drifted types are not treated as reviewed.')
    document=attach(SchemaDocument(environment_id=env.id,input_sha256=hashlib.sha256(raw).hexdigest(),
        cfn_sha256=hashlib.sha256(cfn_raw).hexdigest() if cfn_raw else None,design=spec,items=items,
        resource_comparisons=resource_comparisons,connection_comparisons=connections,notices=notices,
        catalog_provenance=provenance[env.region],regional_catalog_provenance=provenance,
        resource_regions={r.id:r.region or env.region for r in spec.resources},
        resource_services={r.id:cats[r.region or env.region].services[r.type] for r in spec.resources},read_only_omissions=omissions,
        decision_expansions=expansion_records))
    from .document_decisions import trace
    document.decision_trace=trace(document)
    return document
