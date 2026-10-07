"""Checks for AWS::AppSync::GraphQLApi."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'APPSYNC_API_NAME_PUBLIC_PATTERN': [CF+'aws-resource-appsync-graphqlapi.html'],
}


@resource_check('AWS::AppSync::GraphQLApi')
def evaluate_appsync_api_name_public_pattern(design, resource):
    ctx = _Context(design, resource)
    results = []
    def get(path): return value(ctx, resource, path)
    def emit(rule, path, verdict, reason):
        results.append(ctx.finding(rule, path, verdict, reason))
    def enum(rule, path, choices):
        raw = get(path)
        if raw is not ABSENT:
            emit(rule, path, 'NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in choices else 'FAIL',
                 'explicit value compared with current documented allowed values; omitted and unresolved values are not inferred')
    def maximum(rule, path, limit):
        raw = get(path)
        if raw is not ABSENT:
            emit(rule, path, 'NEEDS_REVIEW' if not isinstance(raw, list) else 'PASS' if len(raw) <= limit else 'FAIL',
                 'explicit array length compared with documented maximum; member validity is separate')
    def required(rule, path, active):
        raw = get(path)
        verdict = 'NEEDS_REVIEW'
        if active:
            verdict = 'FAIL' if raw is ABSENT else 'PASS' if literal(raw) else 'NEEDS_REVIEW'
        emit(rule, path, verdict, 'checks presence only for an explicitly established triggering condition; credentials and resource existence remain external')

    if resource.type == 'AWS::AppSync::GraphQLApi':
        path = '/properties/Name'
        raw = get(path)
        if raw is not ABSENT:
            emit('APPSYNC_API_NAME_PUBLIC_PATTERN',path,'NEEDS_REVIEW' if not literal(raw) else
                 'PASS' if len(raw) <= 65536 and re.fullmatch(r'[_A-Za-z][_0-9A-Za-z]*',raw) else 'FAIL',
                 'checks current CloudFormation Name pattern and maximum; does not infer schema name semantics')
    return results
