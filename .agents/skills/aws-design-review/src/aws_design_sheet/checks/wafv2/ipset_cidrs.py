"""Checks for AWS::WAFv2::IPSet."""
import ipaddress
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'WAFV2_IPSET_CIDRS': [CF+'aws-resource-wafv2-ipset.html'],
}


def waf_cidr(raw,version):
    if raw=='':return 'FAIL'
    if not literal(raw):return 'NEEDS_REVIEW'
    if '%' in raw:return 'NEEDS_REVIEW'
    if '/' not in raw:return 'FAIL'
    address,prefix=raw.rsplit('/',1)
    if not re.fullmatch(r'[0-9]{1,3}',prefix):return 'NEEDS_REVIEW'
    try:network=ipaddress.ip_network(raw,strict=False);ip=ipaddress.ip_address(address)
    except ValueError:return 'FAIL'
    if network.prefixlen==0:return 'FAIL'
    if version in ('IPV4','IPV6') and network.version!=int(version[-1]):return 'FAIL'
    if version not in ('IPV4','IPV6') or ip!=network.network_address:return 'NEEDS_REVIEW'
    return 'PASS'


@resource_check('AWS::WAFv2::IPSet')
def evaluate_wafv2_ipset_cidrs(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::WAFv2::IPSet':
        version=get('/properties/IPAddressVersion')
        for path in expand(ctx,resource,'/properties/Addresses/*'):
            emit('WAFV2_IPSET_CIDRS',path,waf_cidr(get(path),version),'addresses require numeric CIDR notation, matching IP family and nonzero prefix; host bits, scoped IPv6, dotted masks and unresolved values remain under review')
    return results
