"""Checks for AWS::DirectConnect::Lag."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'DIRECTCONNECT_LAG_BANDWIDTH': [CF+'aws-resource-directconnect-lag.html'],
}


def _emitter(ctx, results):
    def emit(rule, path, verdict, reason):
        finding = ctx.finding(rule, path, verdict, reason)
        finding['source_checked_at'] = '2026-10-04'
        results.append(finding)
    return emit


def _enum(ctx, resource, emit, rule, field, allowed):
    path = '/properties/'+field
    raw = value(ctx,resource,path)
    if raw is not ABSENT:
        emit(rule,path,'NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in allowed else 'FAIL','explicit published allowed values only; omitted defaults and other property constraints remain separate')


@resource_check('AWS::DirectConnect::Lag')
def evaluate_directconnect_lag_bandwidth(design, resource):
    ctx = _Context(design, resource)
    results = []
    emit = _emitter(ctx, results)
    _enum(ctx, resource, emit, 'DIRECTCONNECT_LAG_BANDWIDTH', 'ConnectionsBandwidth', ('1Gbps','10Gbps','100Gbps','400Gbps'))
    return results
