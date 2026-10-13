"""Checks for AWS::EventSchemas::Schema."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'EVENTSCHEMAS_TYPE_VALUES': [CF+'aws-resource-eventschemas-schema.html','https://docs.aws.amazon.com/eventbridge/latest/schema-reference/v1-registries-name-registryname-schemas-name-schemaname.html'],
}


@resource_check('AWS::EventSchemas::Schema')
def evaluate_eventschemas_type_values(design,resource):
    ctx = _Context(design,resource)
    results = []
    def emit(rule,path,verdict,reason):
        finding = ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at'] = '2026-10-04'
        results.append(finding)
    if resource.type == 'AWS::EventSchemas::Schema':
        path = '/properties/Type'
        raw = value(ctx,resource,path)
        if raw is not ABSENT:
            emit('EVENTSCHEMAS_TYPE_VALUES',path,'NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in ('OpenApi3','JSONSchemaDraft4') else 'FAIL','explicit values from the CreateSchema/UpdateSchema request Type enum; schema content validity and external registry state remain separate')
    return results
