"""Checks for AWS::AppRunner::VpcConnector."""
import ipaddress
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.known_template import resolved
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'APPRUNNER_CONNECTOR_SUBNET_TYPES': [CF+'aws-resource-apprunner-vpcconnector.html',CF+'aws-resource-ec2-subnet.html'],
}


def connector_subnets(ctx,resource):
    raw=value(ctx,resource,'/properties/Subnets')
    if not resolved(resource) or not isinstance(raw,list) or not raw or len(raw)>1000:return 'NEEDS_REVIEW'
    pending=False
    invalid=False
    owners=set()
    for i in range(len(raw)):
        subnet=linked(ctx,resource,'/properties/Subnets/'+str(i),'AWS::EC2::Subnet')
        if not resolved(subnet):
            pending=True
            continue
        native=value(ctx,subnet,'/properties/Ipv6Native')
        if native is True:invalid=True
        elif native is ABSENT:
            cidr=value(ctx,subnet,'/properties/CidrBlock')
            try:
                if not literal(cidr) or '/' not in cidr or ipaddress.ip_network(cidr,strict=False).version!=4:pending=True
            except ValueError:pending=True
        elif native is not False:pending=True
        owner=linked(ctx,subnet,'/properties/VpcId','AWS::EC2::VPC')
        if not resolved(owner):pending=True
        else:owners.add(owner.id)
    return 'FAIL' if invalid or len(owners)>1 else 'NEEDS_REVIEW' if pending or not owners else 'PASS'


@resource_check('AWS::AppRunner::VpcConnector')
def evaluate_apprunner_connector_subnet_types(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::AppRunner::VpcConnector' and value(ctx,resource,'/properties/Subnets') is not ABSENT:
        emit('APPRUNNER_CONNECTOR_SUBNET_TYPES','/properties/Subnets',connector_subnets(ctx,resource),'explicit linked subnets must share a VPC and not be IPv6-only; absent Ipv6Native can be resolved from an explicit IPv4 CIDR. Unknown identities/address types and external connectivity remain held')
    return results
