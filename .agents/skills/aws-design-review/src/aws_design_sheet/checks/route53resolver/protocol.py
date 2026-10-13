"""Resolver rule target protocol support on its declared outbound endpoint."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'RESOLVER_RULE_ENDPOINT_PROTOCOL':[CF+'aws-properties-route53resolver-resolverrule-targetaddress.html',CF+'aws-resource-route53resolver-resolverendpoint.html']}


def protocols(ctx,r):
    rows=value(ctx,r,'/properties/TargetIps')
    if rows is ABSENT:return 'NOT_APPLICABLE'
    if not resolved(r) or not isinstance(rows,list) or not 1<=len(rows)<=100:return 'NEEDS_REVIEW'
    if read(ctx,r,'/properties/ResolverEndpointId') is not ABSENT:return 'NEEDS_REVIEW'
    endpoint=linked(ctx,r,'/properties/ResolverEndpointId','AWS::Route53Resolver::ResolverEndpoint')
    if not resolved(endpoint):return 'NEEDS_REVIEW'
    direction=value(ctx,endpoint,'/properties/Direction')
    if direction in ('INBOUND','INBOUND_DELEGATION'):return 'FAIL'
    if direction!='OUTBOUND':return 'NEEDS_REVIEW'
    supported=value(ctx,endpoint,'/properties/Protocols')
    if supported is ABSENT:supported=['Do53']
    if not isinstance(supported,list) or not 1<=len(supported)<=2 or any(p not in ('Do53','DoH') for p in supported):return 'NEEDS_REVIEW'
    pending=False
    for i in range(len(rows)):
        protocol=value(ctx,r,f'/properties/TargetIps/{i}/Protocol')
        # Target omission has no default documented by the property reference.
        if protocol not in ('Do53','DoH'):pending=True
        elif protocol not in supported:return 'FAIL'
    return 'NEEDS_REVIEW' if pending else 'PASS'


@resource_check('AWS::Route53Resolver::ResolverRule')
def evaluate_route53resolver_protocol(design,resource):
    if resource.type!='AWS::Route53Resolver::ResolverRule':return []
    ctx=_Context(design,resource)
    f=ctx.finding('RESOLVER_RULE_ENDPOINT_PROTOCOL','/properties/TargetIps',protocols(ctx,resource),'Each explicit target protocol must be supported by the linked OUTBOUND endpoint. Omitted endpoint Protocols defaults to Do53 as documented. Omitted target protocols, literal endpoint IDs, conditional references and unknown values remain reviewable. PASS does not establish target reachability or DNS responses.')
    f['source_checked_at']='2026-10-04';return [f]
