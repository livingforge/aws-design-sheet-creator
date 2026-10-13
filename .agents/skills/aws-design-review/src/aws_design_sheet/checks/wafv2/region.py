"""Explicit CloudFront WAF control-plane deployment Region."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SPECS={
 'AWS::WAFv2::IPSet':('WAFV2_IPSET_CLOUDFRONT_REGION','ipset'),
 'AWS::WAFv2::RegexPatternSet':('WAFV2_REGEX_CLOUDFRONT_REGION','regexpatternset'),
 'AWS::WAFv2::RuleGroup':('WAFV2_RULEGROUP_CLOUDFRONT_REGION','rulegroup'),
 'AWS::WAFv2::WebACL':('WAFV2_WEBACL_CLOUDFRONT_REGION','webacl'),
}
SOURCES={rule:[CF+'aws-resource-wafv2-'+page+'.html'] for rule,page in SPECS.values()}


@resource_check(
    'AWS::WAFv2::IPSet',
    'AWS::WAFv2::RegexPatternSet',
    'AWS::WAFv2::RuleGroup',
    'AWS::WAFv2::WebACL',
)
def evaluate_wafv2_region(design,resource):
    if resource.type not in SPECS:return []
    ctx=_Context(design,resource);scope=value(ctx,resource,'/properties/Scope')
    if scope is ABSENT:return []
    verdict='NEEDS_REVIEW'
    if resolved(resource):
        if scope=='REGIONAL':verdict='NOT_APPLICABLE'
        elif scope=='CLOUDFRONT':verdict='PASS' if resource.scope.region=='us-east-1' else 'FAIL'
    f=ctx.finding(SPECS[resource.type][0],'/properties/Scope',verdict,'explicit CLOUDFRONT scope requires us-east-1; unknown scope/deployment context, unavailable regional schema coverage, tag update restrictions and resource validity remain held')
    f['source_checked_at']='2026-10-04'
    return [f]
