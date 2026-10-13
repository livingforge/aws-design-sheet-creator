"""Explicit ID namespace rule-source restrictions in consuming workflows."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT, read
from ..common.literals import literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={rule:[CF+'aws-properties-entityresolution-idmappingworkflow-idmappingrulebasedproperties.html',CF+'aws-properties-entityresolution-idmappingworkflow-idmappingworkflowinputsource.html',CF+'aws-properties-entityresolution-idnamespace-namespacerulebasedproperties.html','https://docs.aws.amazon.com/entityresolution/latest/apireference/API_NamespaceRuleBasedProperties.html'] for rule in ('ENTITY_MAPPING_RULE_DEFINITION_ALLOWED','ENTITY_NAMESPACE_RULE_DEFINITION_COMPATIBILITY')}
INPUT='/properties/InputSourceConfig'


def namespace(ctx,r,path):
    if not resolved(r):return None
    refs=[ref for ref in ctx.design.relations if ref.source_resource_id==r.id and ref.source_path==path]
    if len(refs)!=1 or refs[0].condition:return None
    other=ctx.by_id.get(refs[0].target_resource_id)
    if not resolved(other) or other.type!='AWS::EntityResolution::IdNamespace':return None
    if (other.scope.environment,other.scope.region)!=(r.scope.environment,r.scope.region):return None
    raw=read(ctx,r,path)
    if raw is not ABSENT:
        m=re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:entityresolution:([a-z0-9-]+):([0-9]{12}):idnamespace/([a-zA-Z_0-9-]{1,255})',raw) if literal(raw) else None
        if not m or (m[1],m[2],m[3])!=(other.scope.region,other.scope.account,value(ctx,other,'/properties/IdNamespaceName')):return None
    ctx.evidence.extend(refs[0].evidence_ids)
    return other


def restrictions(ctx,r):
    base='/properties/IdMappingWorkflowProperties';rows=value(ctx,r,base)
    if not isinstance(rows,list) or len(rows)!=1:return None
    if value(ctx,r,base+'/0/IdMappingType')!='RULE_BASED':return None
    raw=value(ctx,r,base+'/0/RuleBasedProperties/RuleDefinitionTypes')
    if not isinstance(raw,list) or not 1<=len(raw)<=2 or any(x not in ('SOURCE','TARGET') for x in raw):return None
    return set(raw)


def compatible(ctx,r,selected_required=True):
    if not resolved(r):return 'NEEDS_REVIEW'
    mode=value(ctx,r,'/properties/IdMappingTechniques/IdMappingType')
    if mode=='PROVIDER':return 'NOT_APPLICABLE'
    if mode!='RULE_BASED':return 'NEEDS_REVIEW'
    rows=value(ctx,r,INPUT)
    if not isinstance(rows,list) or not 1<=len(rows)<=20:return 'NEEDS_REVIEW'
    selected=value(ctx,r,'/properties/IdMappingTechniques/RuleBasedProperties/RuleDefinitionType')
    pending=False;roles=set();intersection={'SOURCE','TARGET'}
    for i in range(len(rows)):
        path=INPUT+'/'+str(i);other=namespace(ctx,r,path+'/InputSourceARN')
        if other is None:pending=True;continue
        role=value(ctx,other,'/properties/Type');input_role=value(ctx,r,path+'/Type')
        if role not in ('SOURCE','TARGET') or (input_role is not ABSENT and input_role!=role):pending=True;continue
        allowed=restrictions(ctx,other)
        if allowed is None:pending=True;continue
        roles.add(role);intersection&=allowed
        if not intersection or (selected_required and selected in ('SOURCE','TARGET') and selected not in allowed):return 'FAIL'
    if pending or roles!={'SOURCE','TARGET'}:return 'NEEDS_REVIEW'
    if selected_required and selected not in ('SOURCE','TARGET'):return 'NEEDS_REVIEW'
    return 'PASS'


@resource_check('AWS::EntityResolution::IdMappingWorkflow', 'AWS::EntityResolution::IdNamespace')
def evaluate_entityresolution_rule_compatibility(design,resource):
    if resource.type not in ('AWS::EntityResolution::IdMappingWorkflow','AWS::EntityResolution::IdNamespace'):return []
    ctx=_Context(design,resource)
    if resource.type=='AWS::EntityResolution::IdMappingWorkflow':
        rule='ENTITY_MAPPING_RULE_DEFINITION_ALLOWED';path='/properties/IdMappingTechniques/RuleBasedProperties/RuleDefinitionType';verdict=compatible(ctx,resource)
    else:
        rule='ENTITY_NAMESPACE_RULE_DEFINITION_COMPATIBILITY';path='/properties/IdMappingWorkflowProperties';verdict='NEEDS_REVIEW';seen=False;pending=False
        if resolved(resource):
            for workflow in design.resources:
                if workflow.type!='AWS::EntityResolution::IdMappingWorkflow':continue
                refs=[ref for ref in design.relations if ref.source_resource_id==workflow.id and ref.target_resource_id==resource.id and re.fullmatch(re.escape(INPUT)+r'/[0-9]+/InputSourceARN',ref.source_path)]
                if not refs:continue
                if not any(namespace(ctx,workflow,ref.source_path) is resource for ref in refs):pending=True;continue
                answer=compatible(ctx,workflow,False)
                if answer=='FAIL':verdict='FAIL';break
                if answer=='PASS':seen=True
                elif answer!='NOT_APPLICABLE':pending=True
            else:
                if seen and not pending:verdict='PASS'
    f=ctx.finding(rule,path,verdict,'Explicit SOURCE/TARGET namespace rule-definition allowances must have a common value; a selected workflow rule source must be allowed by every resolved namespace. Cross-account references are permitted with same-Region/environment and matching ARN/name evidence. Missing or empty restriction lists are not assumed unrestricted. PASS covers declared consumers only; external consumers, dynamic values, mismatched input roles and conditional references remain reviewable.')
    f['source_checked_at']='2026-10-04';return [f]
