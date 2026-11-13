"""Security group rule values that EC2 refuses although cfn-lint 1.57.2 accepts them.

Each was refused by AWS in aws-emulator-evaluation-suite, for embedded and standalone rules:

- a TCP or UDP rule whose FromPort is above its ToPort ("Invalid TCP/UDP port range(100:50)").
  For ICMP the two fields are a type and a code, and other protocols do not use ports, so only
  TCP and UDP rules are compared;
- an IpProtocol name other than tcp, udp, icmp, icmpv6 and all, or a number outside 0-255
  ("Invalid value 'esp' for IP protocol. Unknown protocol.");
- an ICMPv6 rule with an IPv4 range and ports other than -1/-1 ("When protocol is 58 and
  remote-ip-range is specified, port range must either not be specified or must be specified
  as from=-1 and to=-1.");
- a CidrIp or CidrIpv6 without prefix notation ("CIDR block 203.0.113.5 is malformed").
"""
import ipaddress

from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT, UNKNOWN
from ..common.literals import expand

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
API = 'https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_IpPermission.html'
SOURCES = {
    'EC2_SECURITY_GROUP_PORT_RANGE_ORDER': [
        API, CF + 'aws-resource-ec2-securitygroupingress.html', CF + 'aws-resource-ec2-securitygroupegress.html',
        CF + 'aws-properties-ec2-securitygroup-ingress.html', CF + 'aws-properties-ec2-securitygroup-egress.html'],
}
for _rule in ('EC2_SECURITY_GROUP_PROTOCOL_NAME', 'EC2_SECURITY_GROUP_ICMPV6_IPV4_PORTS', 'EC2_SECURITY_GROUP_CIDR_PREFIX'):
    SOURCES[_rule] = SOURCES['EC2_SECURITY_GROUP_PORT_RANGE_ORDER']
RULE = 'EC2_SECURITY_GROUP_PORT_RANGE_ORDER'
PORTED = {'tcp': 'tcp', '6': 'tcp', 'udp': 'udp', '17': 'udp'}


def _port(raw):
    """The port as an int, None when it is not a usable literal port."""
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str) and raw.strip().lstrip('-').isdigit():
        return int(raw.strip())
    return None


def _rule_finding(ctx, resource, base):
    """One finding for the rule at base, or None when the rule has no port range to compare."""
    low_raw = value(ctx, resource, base + '/FromPort')
    high_raw = value(ctx, resource, base + '/ToPort')
    if low_raw is ABSENT or high_raw is ABSENT:
        return None
    protocol = value(ctx, resource, base + '/IpProtocol')
    if protocol is UNKNOWN:
        return ctx.finding(RULE, base + '/FromPort', 'NEEDS_REVIEW',
                           'IpProtocol is unresolved, so whether FromPort and ToPort form a TCP/UDP port range is unknown')
    if not isinstance(protocol, (str, int)) or str(protocol).strip().lower() not in PORTED:
        return None  # ICMP type/code, all protocols or a protocol without ports.
    low, high = _port(low_raw), _port(high_raw)
    if low is None or high is None or not (0 <= low <= 65535 and 0 <= high <= 65535):
        return ctx.finding(RULE, base + '/FromPort', 'NEEDS_REVIEW',
                           'TCP/UDP FromPort or ToPort is unresolved or not a port number from 0 to 65535')
    if low > high:
        return ctx.finding(RULE, base + '/FromPort', 'FAIL',
                           f'TCP/UDP FromPort {low} is above ToPort {high}; EC2 rejects the port range')
    return ctx.finding(RULE, base + '/FromPort', 'PASS', 'TCP/UDP FromPort does not exceed ToPort')


@resource_check('AWS::EC2::SecurityGroup')
def evaluate_embedded_security_group_port_ranges(design, resource):
    results = []
    for name in ('SecurityGroupIngress', 'SecurityGroupEgress'):
        for base in expand(_Context(design, resource), resource, f'/properties/{name}/*'):
            if base == f'/properties/{name}':
                continue  # the whole list is unresolved; schema review reports it
            finding = _rule_finding(_Context(design, resource), resource, base)
            if finding is not None:
                results.append(finding)
    return results


@resource_check('AWS::EC2::SecurityGroupIngress', 'AWS::EC2::SecurityGroupEgress')
def evaluate_standalone_security_group_port_range(design, resource):
    finding = _rule_finding(_Context(design, resource), resource, '/properties')
    return [] if finding is None else [finding]


NAMED = ('tcp', 'udp', 'icmp', 'icmpv6', 'all', '-1')


def _value_findings(design, resource, base):
    """Protocol name, ICMPv6 ports with an IPv4 range and CIDR notation of one rule."""
    results = []
    ctx = _Context(design, resource)
    protocol = value(ctx, resource, base + '/IpProtocol')
    text = str(protocol).strip().lower() if isinstance(protocol, (str, int)) and not isinstance(protocol, bool) else None
    if text is not None:
        number = text.isdigit()
        verdict = 'PASS' if text in NAMED or number and int(text) <= 255 else 'FAIL'
        results.append(ctx.finding('EC2_SECURITY_GROUP_PROTOCOL_NAME', base + '/IpProtocol', verdict,
                                   'IpProtocol is tcp, udp, icmp, icmpv6, all (-1) or a protocol number from 0 to 255'))
    for key, family in (('CidrIp', 4), ('CidrIpv6', 6)):
        local = _Context(design, resource)
        cidr = value(local, resource, f'{base}/{key}')
        if not isinstance(cidr, str) or '{{' in cidr or '${' in cidr:
            continue
        try:
            valid = '/' in cidr and ipaddress.ip_network(cidr, strict=False).version == family
        except ValueError:
            valid = False
        results.append(local.finding('EC2_SECURITY_GROUP_CIDR_PREFIX', f'{base}/{key}', 'PASS' if valid else 'FAIL',
                                     f'{key} must be an IPv{family} CIDR block with a prefix length, such as '
                                     + ('10.0.0.0/16' if family == 4 else '2001:db8::/32')))
    if text in ('icmpv6', '58'):
        local = _Context(design, resource)
        if value(local, resource, base + '/CidrIp') is not ABSENT:
            low, high = value(local, resource, base + '/FromPort'), value(local, resource, base + '/ToPort')
            ports = [p for p in (low, high) if p is not ABSENT]
            if any(p is UNKNOWN for p in ports):
                verdict = 'NEEDS_REVIEW'
            else:
                verdict = 'PASS' if all(_port(p) == -1 for p in ports) else 'FAIL'
            results.append(local.finding('EC2_SECURITY_GROUP_ICMPV6_IPV4_PORTS', base + '/FromPort', verdict,
                                         'an ICMPv6 rule with an IPv4 range takes no ports or FromPort and ToPort -1'))
    return results


@resource_check('AWS::EC2::SecurityGroup')
def evaluate_embedded_security_group_rule_values(design, resource):
    results = []
    for name in ('SecurityGroupIngress', 'SecurityGroupEgress'):
        for base in expand(_Context(design, resource), resource, f'/properties/{name}/*'):
            if base != f'/properties/{name}':
                results.extend(_value_findings(design, resource, base))
    return results


@resource_check('AWS::EC2::SecurityGroupIngress', 'AWS::EC2::SecurityGroupEgress')
def evaluate_standalone_security_group_rule_values(design, resource):
    return _value_findings(design, resource, '/properties')
