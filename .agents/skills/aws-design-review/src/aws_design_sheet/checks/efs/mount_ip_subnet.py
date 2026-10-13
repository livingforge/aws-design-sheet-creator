"""Checks for AWS::EFS::MountTarget."""
import ipaddress
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

SOURCES = {
    'EFS_MOUNT_IP_SUBNET': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-efs-mounttarget.html',
    ],
}


@resource_check('AWS::EFS::MountTarget')
def evaluate_efs_mount_ip_subnet(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(p):return value(ctx,resource,p)
    def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
    if resource.type=='AWS::EFS::MountTarget':
        subnet=linked(ctx,resource,'/properties/SubnetId','AWS::EC2::Subnet')
        for key,cidrkey,version in [('IpAddress','CidrBlock',4),('Ipv6Address','Ipv6CidrBlock',6)]:
            p='/properties/'+key;raw=get(p)
            if raw is ABSENT:continue
            cidr=value(ctx,subnet,'/properties/'+cidrkey) if subnet else None;v='NEEDS_REVIEW'
            if literal(raw) and literal(cidr) and '%' not in raw+cidr:
                try:
                    address=ipaddress.ip_address(raw);network=ipaddress.ip_network(cidr,strict=True)
                    if address.version==network.version==version:v='PASS' if address in network else 'FAIL'
                except ValueError:pass
            emit('EFS_MOUNT_IP_SUBNET',p,v,'explicit assigned IP must belong to canonical linked subnet CIDR of matching address family; malformed/unknown CIDRs, IP type/native flags and available-address state held')
    return results
