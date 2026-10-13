"""Checks for AWS::Route53Resolver::ResolverEndpoint."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'RESOLVER_ENDPOINT_ENUM_VALUES': [CF+'aws-resource-route53resolver-resolverendpoint.html'],
}


@resource_check('AWS::Route53Resolver::ResolverEndpoint')
def evaluate_route53resolver_endpoint_enums(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    def enum(raw,allowed):return 'NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in allowed else 'FAIL'
    if resource.type=='AWS::Route53Resolver::ResolverEndpoint':
        seen=set()
        for pattern,allowed in (('/properties/Direction',('INBOUND','OUTBOUND','INBOUND_DELEGATION')),('/properties/Protocols/*',('Do53','DoH','DoH-FIPS'))):
            for path in expand(ctx,resource,pattern):
                if path in seen:continue
                seen.add(path)
                emit('RESOLVER_ENDPOINT_ENUM_VALUES',path,enum(value(ctx,resource,path),allowed),'explicit Direction/protocol values only; existing per-direction combination checks retained, unknown/default values and network reachability remain held')
    return results
