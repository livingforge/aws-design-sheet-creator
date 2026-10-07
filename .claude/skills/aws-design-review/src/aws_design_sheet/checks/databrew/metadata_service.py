"""Checks for AWS::DataBrew::Dataset."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'DATABREW_METADATA_SERVICE': [CF+'aws-properties-databrew-dataset-metadata.html'],
}


@resource_check('AWS::DataBrew::Dataset')
def evaluate_databrew_metadata_service(design, resource):
    ctx = _Context(design, resource)
    results = []
    def get(p):
        return value(ctx, resource, p)
    def emit(rule, p, verdict, reason):
        f = ctx.finding(rule, p, verdict, reason)
        f['source_checked_at'] = '2026-10-04'
        results.append(f)
    if resource.type == 'AWS::DataBrew::Dataset':
        p = '/properties/Input/Metadata/SourceArn'
        arn = get(p)
        if arn is not ABSENT:
            match = re.fullmatch(r'arn:[a-z0-9-]+:([a-z0-9-]+):[^:]*:[0-9]{12}:.+', arn) if literal(arn) else None
            emit('DATABREW_METADATA_SERVICE', p, 'NEEDS_REVIEW' if not match else 'PASS' if match[1] == 'appflow' else 'FAIL', 'only explicit ARN service component is checked; exact resource format, existence and AppFlow permissions remain separate')
    return results
