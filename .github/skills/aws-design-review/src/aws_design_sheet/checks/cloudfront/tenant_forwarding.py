"""Checks for AWS::CloudFront::Distribution."""
from ..registry import resource_check
from .policies_keys_and_tenants import cloudfront_distribution
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CLOUDFRONT_TENANT_FORWARDED_VALUES': [CF + 'aws-properties-cloudfront-distribution-forwardedvalues.html'],
}


@resource_check('AWS::CloudFront::Distribution')
def tenant_forwarding(design, resource):
    ctx = _Context(design, resource)
    base = '/properties/DistributionConfig'
    mode = value(ctx, resource, base + '/ConnectionMode')
    if mode in (ABSENT, 'direct'):
        return cloudfront_distribution(design, resource)
    paths = [base + '/DefaultCacheBehavior/ForwardedValues']
    behaviors = value(ctx, resource, base + '/CacheBehaviors')
    if isinstance(behaviors, list):
        paths.extend(base + f'/CacheBehaviors/{i}/ForwardedValues' for i in range(len(behaviors)))
    elif behaviors is not ABSENT:
        paths.append(base + '/CacheBehaviors')
    results = cloudfront_distribution(design, resource)
    for path in paths:
        forwarded = value(ctx, resource, path)
        if forwarded is ABSENT:
            continue
        verdict = 'FAIL' if mode == 'tenant-only' and isinstance(forwarded, dict) else 'NEEDS_REVIEW'
        results.append(ctx.finding('CLOUDFRONT_TENANT_FORWARDED_VALUES', path, verdict,
            'ForwardedValues is not supported for multi-tenant distributions'))
    return results
