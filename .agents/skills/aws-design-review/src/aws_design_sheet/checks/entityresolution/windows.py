"""Checks for AWS::EntityResolution::IdMappingWorkflow, AWS::EntityResolution::IdNamespace."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, known_scope, literal
from ..common.string_lists import strings

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'ENTITY_WORKFLOW_SCHEMA_KEYS': [CF+'aws-properties-entityresolution-idmappingworkflow-rule.html',CF+'aws-properties-entityresolution-schemamapping-schemainputattribute.html'],
    'ENTITY_NAMESPACE_SCHEMA_KEYS': [CF+'aws-properties-entityresolution-idnamespace-rule.html',CF+'aws-properties-entityresolution-schemamapping-schemainputattribute.html'],
}


def common_schema(ctx,resource,key):
    inputs=value(ctx,resource,'/properties/InputSourceConfig')
    if not known_scope(resource) or not isinstance(inputs,list) or not inputs:return None
    schemas=[]
    for i in range(len(inputs)):
        schema=linked(ctx,resource,'/properties/InputSourceConfig/'+str(i)+'/'+key,'AWS::EntityResolution::SchemaMapping')
        if not schema:return None
        schemas.append(schema)
    return schemas[0] if len({s.id for s in schemas})==1 else None


@resource_check('AWS::EntityResolution::IdMappingWorkflow','AWS::EntityResolution::IdNamespace')
def evaluate_entityresolution_windows(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    entity={
        'AWS::EntityResolution::IdMappingWorkflow':('ENTITY_WORKFLOW_SCHEMA_KEYS','SchemaArn','/properties/IdMappingTechniques/RuleBasedProperties/Rules/*/MatchingKeys'),
        'AWS::EntityResolution::IdNamespace':('ENTITY_NAMESPACE_SCHEMA_KEYS','SchemaName','/properties/IdMappingWorkflowProperties/*/RuleBasedProperties/Rules/*/MatchingKeys'),
    }
    if resource.type in entity:
        rule,key,pattern=entity[resource.type];schema=common_schema(ctx,resource,key);known=set();complete=False
        if schema:
            fields=value(ctx,schema,'/properties/MappedInputFields');complete=isinstance(fields,list)
            for i in range(len(fields)) if isinstance(fields,list) else ():
                match=value(ctx,schema,'/properties/MappedInputFields/'+str(i)+'/MatchKey')
                if match is ABSENT:continue
                if literal(match):known.add(match)
                else:complete=False
        for path in expand(ctx,resource,pattern):
            names,pending=strings(ctx,resource,path);missing=set(names)-known
            verdict='FAIL' if schema and complete and missing else 'PASS' if schema and not pending and not missing else 'NEEDS_REVIEW'
            emit(rule,path,verdict,'MatchingKeys must be explicit MatchKey values in the single shared linked schema; omitted MatchKey does not fall back to FieldName; mixed schemas, unresolved/conditional links and namespace inheritance remain under review')
    return results
