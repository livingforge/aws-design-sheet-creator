"""Checks for AWS::DLM::LifecyclePolicy."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'DLM_DEFAULT_PUBLIC_VALUES': [CF+'aws-resource-dlm-lifecyclepolicy.html'],
}


@resource_check('AWS::DLM::LifecyclePolicy')
def evaluate_dlm_default_public_values(design, resource):
    ctx = _Context(design, resource)
    results = []
    def get(p):
        return value(ctx, resource, p)
    def emit(rule, p, verdict, reason):
        f = ctx.finding(rule, p, verdict, reason)
        f['source_checked_at'] = '2026-10-04'
        results.append(f)
    def enum(rule, p, allowed):
        raw = get(p)
        if raw is not ABSENT:
            emit(rule, p, 'NEEDS_REVIEW' if not (literal(raw) or (resource.type=='AWS::CodePipeline::CustomActionType' and raw=='')) else 'PASS' if raw in allowed else 'FAIL', 'documented explicit value only; applicability and service state remain separate')
    if resource.type == 'AWS::DLM::LifecyclePolicy':
        rule = 'DLM_DEFAULT_PUBLIC_VALUES'
        enum(rule, '/properties/State', ('ENABLED','DISABLED','ERROR'))
        for field, low, high in (('CreateInterval',1,7), ('RetainInterval',2,14)):
            p = '/properties/'+field
            raw = get(p)
            if raw is ABSENT:
                continue
            supported = get('/properties/DefaultPolicy') in ('VOLUME','INSTANCE') and get('/properties/PolicyDetails') is ABSENT
            verdict = 'NEEDS_REVIEW' if not supported or type(raw) is not int else 'PASS' if low <= raw <= high else 'FAIL'
            emit(rule, p, verdict, 'top-level explicit default policy day range only; mixed request structures, other policy kinds, defaults and retention/creation relationship remain separate')
    return results
