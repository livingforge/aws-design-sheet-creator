"""Legacy regional WAF protects ALBs and REST API stages only."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.literals import literal
from ..common.scoped_resolution import resolved

SOURCES={'WAFREGIONAL_ASSOCIATION_TARGET_KIND':['https://docs.aws.amazon.com/waf/latest/APIReference/API_wafRegional_AssociateWebACL.html','https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-wafregional-webacl.html']}


def target_kind(ctx,r):
    if not resolved(r):return 'NEEDS_REVIEW'
    path='/properties/ResourceArn';raw=read(ctx,r,path)
    refs=[ref for ref in ctx.design.relations if ref.source_resource_id==r.id and ref.source_path==path]
    if refs:
        if len(refs)!=1 or refs[0].condition or raw is not ABSENT:return 'NEEDS_REVIEW'
        targets=[other for other in ctx.design.resources if other.id==refs[0].target_resource_id]
        if len(targets)!=1 or not resolved(targets[0]):return 'NEEDS_REVIEW'
        other=targets[0]
        if linked(ctx,r,path,other.type) is not other:return 'NEEDS_REVIEW'
        if other.type=='AWS::ApiGateway::Stage':return 'PASS'
        if other.type=='AWS::ElasticLoadBalancingV2::LoadBalancer':
            kind=value(ctx,other,'/properties/Type')
            return 'PASS' if kind=='application' else 'FAIL' if kind in ('network','gateway') else 'NEEDS_REVIEW'
        return 'FAIL'
    raw=value(ctx,r,path)
    if not literal(raw):return 'NEEDS_REVIEW'
    arn=re.fullmatch(r'arn:([a-z0-9-]+):([a-z0-9-]+):([a-z0-9-]+):([0-9]*):(.+)',raw)
    if not arn:return 'NEEDS_REVIEW'
    _,service,region,account,name=arn.groups()
    if service=='elasticloadbalancing':
        if re.fullmatch(r'loadbalancer/app/[^/\s]+/[^/\s]+',name) and len(account)==12:return 'PASS'
        return 'FAIL'
    if service=='apigateway':return 'PASS' if account=='' and re.fullmatch(r'/restapis/[^/\s]+/stages/[^/\s]+',name) else 'FAIL'
    return 'FAIL'


@resource_check('AWS::WAFRegional::WebACLAssociation')
def evaluate_waf_wafregional_target(design,resource):
    if resource.type!='AWS::WAFRegional::WebACLAssociation':return []
    ctx=_Context(design,resource)
    f=ctx.finding('WAFREGIONAL_ASSOCIATION_TARGET_KIND','/properties/ResourceArn',target_kind(ctx,resource),'WAF Classic Regional supports an Application Load Balancer or API Gateway REST stage. Explicit linked type or documented literal ARN shape is checked. API Gateway v2 stages and non-application load balancers do not qualify. PASS covers resource kind only; ARN existence, regional equality, permissions and service availability remain separate.')
    f['source_checked_at']='2026-10-04';return [f]
