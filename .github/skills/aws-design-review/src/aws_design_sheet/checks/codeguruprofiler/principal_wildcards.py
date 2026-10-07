"""Checks for AWS::CodeGuruProfiler::ProfilingGroup."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CODEGURU_PRINCIPAL_WILDCARDS': [CF+'aws-properties-codeguruprofiler-profilinggroup-agentpermissions.html'],
}


@resource_check('AWS::CodeGuruProfiler::ProfilingGroup')
def evaluate_codeguruprofiler_principal_wildcards(design, resource):
    ctx = _Context(design, resource)
    results = []

    def get(path):
        return value(ctx, resource, path)

    def emit(rule, path, verdict, reason):
        f = ctx.finding(rule, path, verdict, reason)
        f['source_checked_at'] = '2026-10-04'
        results.append(f)

    def enum(rule, path, allowed):
        raw = get(path)
        if raw is not ABSENT:
            emit(rule, path, 'NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in allowed else 'FAIL', 'checks documented literal values; external availability and applicability remain separate')

    if resource.type == 'AWS::CodeGuruProfiler::ProfilingGroup':
        for p in expand(ctx, resource, '/properties/AgentPermissions/Principals/*'):
            raw = get(p)
            verdict = 'NEEDS_REVIEW' if not literal(raw) else 'FAIL' if '*' in raw or '?' in raw else 'PASS'
            emit('CODEGURU_PRINCIPAL_WILDCARDS', p, verdict, 'principal ARN wildcard prohibition only; ARN identity, count and effective access remain separate')
    return results
