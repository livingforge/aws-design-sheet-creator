"""Checks for AWS::Batch::ServiceEnvironment."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'BATCH_SERVICE_ENVIRONMENT_VALUES': [CF+'aws-resource-batch-serviceenvironment.html', CF+'aws-properties-batch-serviceenvironment-capacitylimit.html'],
}


@resource_check('AWS::Batch::ServiceEnvironment')
def evaluate_batch_service_environment_values(design, resource):
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

    if resource.type == 'AWS::Batch::ServiceEnvironment':
        rule = 'BATCH_SERVICE_ENVIRONMENT_VALUES'
        enum(rule,'/properties/ServiceEnvironmentType',('SAGEMAKER_TRAINING',))
        if get('/properties/ServiceEnvironmentType') == 'SAGEMAKER_TRAINING':
            for path in expand(ctx,resource,'/properties/CapacityLimits/*/CapacityUnit'): enum(rule,path,('NUM_INSTANCES',))
    return results
