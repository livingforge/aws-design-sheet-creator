"""Checks for AWS::EntityResolution::MatchingWorkflow."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'ENTITYRESOLUTION_OUTPUT_FIELD': [CF+'aws-properties-entityresolution-matchingworkflow-outputattribute.html',CF+'aws-properties-entityresolution-schemamapping-schemainputattribute.html'],
}


def output_fields(ctx,resource):
    inputs = value(ctx,resource,'/properties/InputSourceConfig')
    if not isinstance(inputs,list) or len(inputs)!=1:
        return None
    schema = linked(ctx,resource,'/properties/InputSourceConfig/0/SchemaArn','AWS::EntityResolution::SchemaMapping')
    fields = value(ctx,schema,'/properties/MappedInputFields') if schema else None
    if not isinstance(fields,list) or not fields or len(fields)>1000:
        return None
    names = [value(ctx,schema,'/properties/MappedInputFields/'+str(i)+'/FieldName') for i in range(len(fields))]
    if not all(literal(n) for n in names) or len(set(names))!=len(names):
        return None
    return set(names)


@resource_check('AWS::EntityResolution::MatchingWorkflow')
def evaluate_entityresolution_output_field(design,resource):
    ctx = _Context(design,resource)
    results = []
    def emit(rule,path,verdict,reason):
        finding = ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at'] = '2026-10-04'
        results.append(finding)
    if resource.type == 'AWS::EntityResolution::MatchingWorkflow':
        names = output_fields(ctx,resource)
        for path in expand(ctx,resource,'/properties/OutputSourceConfig/*/Output/*/Name'):
            raw = value(ctx,resource,path)
            if raw is not ABSENT:
                emit('ENTITYRESOLUTION_OUTPUT_FIELD',path,'NEEDS_REVIEW' if names is None or not literal(raw) else 'PASS' if raw in names else 'FAIL','output name must match FieldName in a single uniquely linked complete explicit input schema; multi-source semantics, duplicate/unknown field names, MatchingKeys and external schema state remain held')
    return results
