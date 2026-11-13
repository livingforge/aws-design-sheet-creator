"""TTL order of a CloudFront cache policy.

CloudFront refuses a cache policy whose MinTTL is above its DefaultTTL (InvalidArgument);
cfn-lint 1.57.2 does not compare the two. AWS refused it in aws-emulator-evaluation-suite.
"""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CLOUDFRONT_CACHE_POLICY_MIN_TTL_ORDER': [CF + 'aws-properties-cloudfront-cachepolicy-cachepolicyconfig.html'],
}
BASE = '/properties/CachePolicyConfig/'


def _seconds(raw):
    if isinstance(raw, bool):
        return None
    if isinstance(raw, (int, float)):
        return raw
    try:
        return float(raw) if isinstance(raw, str) else None
    except ValueError:
        return None


@resource_check('AWS::CloudFront::CachePolicy')
def evaluate_cache_policy_min_ttl_order(design, resource):
    ctx = _Context(design, resource)
    low, default = value(ctx, resource, BASE + 'MinTTL'), value(ctx, resource, BASE + 'DefaultTTL')
    if low is ABSENT or default is ABSENT:
        return []
    low, default = _seconds(low), _seconds(default)
    verdict = 'NEEDS_REVIEW' if low is None or default is None else 'PASS' if low <= default else 'FAIL'
    return [ctx.finding('CLOUDFRONT_CACHE_POLICY_MIN_TTL_ORDER', BASE + 'MinTTL', verdict,
                        'MinTTL does not exceed DefaultTTL')]
