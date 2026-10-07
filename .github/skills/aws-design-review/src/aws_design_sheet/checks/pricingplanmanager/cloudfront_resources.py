"""Checks for AWS::PricingPlanManager::Subscription."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'PRICINGPLAN_CLOUDFRONT_RESOURCES': [CF+'aws-resource-pricingplanmanager-subscription.html'],
}


@resource_check('AWS::PricingPlanManager::Subscription')
def evaluate_pricingplanmanager_cloudfront_resources(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(p):return value(ctx,resource,p)
    def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
    if resource.type=='AWS::PricingPlanManager::Subscription':
        p='/properties/ResourceArns';raw=get(p);families=set();pending=not isinstance(raw,list)
        for i in range(len(raw)) if isinstance(raw,list) else ():
            arn=get(p+'/'+str(i))
            if not literal(arn):pending=True;continue
            if re.fullmatch(r'arn:(?:aws|aws-cn|aws-us-gov):cloudfront::[0-9]{12}:distribution/[^/]+',arn):families.add('cloudfront')
            elif re.fullmatch(r'arn:(?:aws|aws-cn|aws-us-gov):wafv2:[a-z0-9-]+:[0-9]{12}:(?:global|regional)/webacl/[^/]+/[^/]+',arn):families.add('waf')
            elif not re.fullmatch(r'arn:[^:]+:[^:]+:[^:]*:[0-9]{12}:.+',arn):pending=True
        family=get('/properties/PlanFamily');v='NEEDS_REVIEW'
        if family=='CloudFront':v='PASS' if families=={'cloudfront','waf'} else 'NEEDS_REVIEW' if pending else 'FAIL'
        emit('PRICINGPLAN_CLOUDFRONT_RESOURCES',p,v,'explicit CloudFront plan contains distribution and WAF web ACL ARNs; unresolved references, absent/future plan family and actual association/scope compatibility held')
    return results
