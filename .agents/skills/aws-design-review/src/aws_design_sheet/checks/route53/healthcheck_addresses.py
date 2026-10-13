"""Stable non-public endpoint ranges explicitly referenced by Route 53."""
import ipaddress
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

URL='https://docs.aws.amazon.com/Route53/latest/APIReference/API_HealthCheckConfig.html'
SOURCES={'ROUTE53_HEALTHCHECK_NONPUBLIC_ADDRESS':[URL]+[
    f'https://www.rfc-editor.org/rfc/rfc{number}.html' for number in (1918,5735,6598,5156)]}
BLOCKED=tuple(ipaddress.ip_network(cidr) for cidr in (
    '0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8',
    '169.254.0.0/16','172.16.0.0/12','192.168.0.0/16','224.0.0.0/4',
    '::/128','::1/128','fc00::/7','fe80::/10','fec0::/10','ff00::/8','2001:db8::/32'))


@resource_check('AWS::Route53::HealthCheck')
def healthcheck_address(design,resource):
    ctx=_Context(design,resource)
    path='/properties/HealthCheckConfig/IPAddress'
    raw=value(ctx,resource,path)
    if raw is ABSENT:return []
    verdict='NEEDS_REVIEW'
    if isinstance(raw,str) and '{{' not in raw and '${' not in raw:
        try:
            address=ipaddress.ip_address(raw)
        except ValueError:
            verdict='FAIL'
        else:
            candidate=address.ipv4_mapped if address.version==6 and address.ipv4_mapped else address
            if any(candidate.version==net.version and candidate in net for net in BLOCKED):
                verdict='FAIL'
    return [ctx.finding('ROUTE53_HEALTHCHECK_NONPUBLIC_ADDRESS',path,verdict,
        'rejects malformed IPs and enumerated private, loopback, link-local, shared, multicast and IPv6 documentation ranges; other special-use ranges, AWS acceptance and reachability remain unverified')]
