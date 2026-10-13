"""Checks for AWS::ARCZonalShift::ZonalAutoshiftConfiguration."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'ARC_AUTOSHIFT_RESOURCE_TYPE': [CF+'aws-resource-arczonalshift-zonalautoshiftconfiguration.html'],
}


@resource_check('AWS::ARCZonalShift::ZonalAutoshiftConfiguration')
def evaluate_arczonalshift_autoshift_resource_type(design, resource):
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
    if resource.type == 'AWS::ARCZonalShift::ZonalAutoshiftConfiguration':
        p = '/properties/ResourceIdentifier'
        raw = get(p)
        if raw is not ABSENT:
            lb = linked(ctx, resource, p, 'AWS::ElasticLoadBalancingV2::LoadBalancer')
            kind = value(ctx,lb,'/properties/Type') if lb else None
            verdict = 'NEEDS_REVIEW'
            if kind in ('application','network','gateway'):
                verdict = 'PASS' if kind in ('application','network') else 'FAIL'
            elif literal(raw):
                match = re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:elasticloadbalancing:[a-z0-9-]+:[0-9]{12}:loadbalancer/(app|net|gwy)/[^/]+/[a-zA-Z0-9]+',raw)
                if match:
                    verdict = 'FAIL' if match[1]=='gwy' else 'PASS'
            emit('ARC_AUTOSHIFT_RESOURCE_TYPE',p,verdict,'ALB/NLB identity from explicit linked type or recognized ARN; omitted type, other ARN shapes, actual zonal support and availability remain held')
    return results
