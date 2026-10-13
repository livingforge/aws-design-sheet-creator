"""Checks for AWS::SageMaker::Domain."""
import ipaddress
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'SAGEMAKER_DOMAIN_SUBNET_IPV6': [CF+'aws-properties-sagemaker-domain-domainsettings.html'],
}


def subnet_ipv6(ctx,r,path):
    if not resolved(r) or value(ctx,r,'/properties/DomainSettings/IpAddressType')!='DUALSTACK':return 'NEEDS_REVIEW'
    subnet=linked(ctx,r,path,'AWS::EC2::Subnet')
    if not resolved(subnet):return 'NEEDS_REVIEW'
    cidr=value(ctx,subnet,'/properties/Ipv6CidrBlock')
    if not literal(cidr):return 'NEEDS_REVIEW'
    try:network=ipaddress.ip_network(cidr,strict=True)
    except ValueError:return 'NEEDS_REVIEW'
    return 'PASS' if network.version==6 else 'NEEDS_REVIEW'


@resource_check('AWS::SageMaker::Domain')
def evaluate_sagemaker_domain_subnet_ipv6(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::SageMaker::Domain' and value(ctx,resource,'/properties/DomainSettings/IpAddressType') is not ABSENT:
        for path in expand(ctx,resource,'/properties/SubnetIds/*'):
            emit('SAGEMAKER_DOMAIN_SUBNET_IPV6',path,subnet_ipv6(ctx,resource,path),'explicit DUALSTACK with linked explicit valid IPv6 subnet CIDR establishes IPv6 configuration intent; omitted/dynamic CIDRs, separate associations/IPAM, lowercase prose ambiguity and deployed support remain held')
    return results
