"""A private IPv4 address used twice in one subnet.

EC2 refuses an instance or network interface whose PrivateIpAddress another one in the same
subnet already holds (InvalidIPAddress.InUse, "Address ... is in use."); cfn-lint 1.57.2 does not
compare resources. Only literal addresses and subnets the design resolves are compared.
"""
import re

from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.literals import literal

SOURCES = {
    'EC2_PRIVATE_IP_UNIQUE_IN_SUBNET': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-instance.html',
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-networkinterface.html',
        'https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_RunInstances.html'],
}
TYPES = ('AWS::EC2::Instance', 'AWS::EC2::NetworkInterface')


def _key(ctx, resource):
    address = value(ctx, resource, '/properties/PrivateIpAddress')
    if not literal(address):
        return None
    subnet = linked(ctx, resource, '/properties/SubnetId', 'AWS::EC2::Subnet')
    if subnet is not None:
        return ('resource', subnet.id), address
    raw = value(ctx, resource, '/properties/SubnetId')
    if isinstance(raw, str) and re.fullmatch(r'subnet-[0-9a-f]+', raw):
        return ('literal', raw), address
    return None


@resource_check(*TYPES)
def evaluate_private_ip_uniqueness(design, resource):
    ctx = _Context(design, resource)
    key = _key(ctx, resource)
    if key is None:
        return []
    others = sorted(other.name for other in design.resources
                    if other.id != resource.id and other.type in TYPES and other.scope == resource.scope
                    and _key(_Context(design, other), other) == key)
    if others:
        return [ctx.finding('EC2_PRIVATE_IP_UNIQUE_IN_SUBNET', '/properties/PrivateIpAddress', 'FAIL',
                            f'{key[1]} is also the private address of ' + ', '.join(others) + ' in the same subnet')]
    return [ctx.finding('EC2_PRIVATE_IP_UNIQUE_IN_SUBNET', '/properties/PrivateIpAddress', 'PASS',
                        'no other instance or network interface in the design uses this address in the subnet')]
