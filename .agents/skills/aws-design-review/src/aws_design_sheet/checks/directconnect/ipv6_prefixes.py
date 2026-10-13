"""Checks for these resource types:

- AWS::DirectConnect::DirectConnectGatewayAssociation
- AWS::DirectConnect::PublicVirtualInterface
"""
import ipaddress
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'DIRECTCONNECT_GATEWAY_IPV6_PREFIX': [CF+'aws-resource-directconnect-directconnectgatewayassociation.html'],
    'DIRECTCONNECT_PUBLIC_IPV6_PREFIX': [CF+'aws-resource-directconnect-publicvirtualinterface.html'],
}


@resource_check('AWS::DirectConnect::DirectConnectGatewayAssociation','AWS::DirectConnect::PublicVirtualInterface')
def evaluate_directconnect_ipv6_prefixes(design,resource):
 ctx=_Context(design,resource);results=[]
 def get(p):return value(ctx,resource,p)
 def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
 specs={'AWS::DirectConnect::DirectConnectGatewayAssociation':('DIRECTCONNECT_GATEWAY_IPV6_PREFIX','AllowedPrefixesToDirectConnectGateway'),'AWS::DirectConnect::PublicVirtualInterface':('DIRECTCONNECT_PUBLIC_IPV6_PREFIX','RouteFilterPrefixes')}
 if resource.type in specs:
  rule,key=specs[resource.type]
  for p in expand(ctx,resource,'/properties/'+key+'/*'):
   raw=get(p);v='NEEDS_REVIEW'
   if literal(raw) and '/' in raw and '%' not in raw:
    try:
     net=ipaddress.ip_network(raw,strict=True)
     v='NOT_APPLICABLE' if net.version==4 else 'PASS' if net.prefixlen<=64 else 'FAIL'
    except ValueError:pass
   emit(rule,p,v,'pinned schema item description requires IPv6 /64 or shorter; IPv4 is outside this check; noncanonical/invalid/unresolved CIDRs held')
 return results
