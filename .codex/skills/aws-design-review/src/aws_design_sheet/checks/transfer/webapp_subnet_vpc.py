"""Checks for AWS::Transfer::WebApp."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.literals import expand
from ..common.scoped_resolution import resolved
from ..common.vpc_ids import vpc_id

SOURCES = {
    'TRANSFER_WEBAPP_SUBNET_VPC': ['https://docs.aws.amazon.com/transfer/latest/APIReference/API_WebAppVpcConfig.html'],
}


def subnet_vpc(ctx,r,path):
    subnet=linked(ctx,r,path,'AWS::EC2::Subnet')
    if not resolved(r) or not resolved(subnet):return 'NEEDS_REVIEW'
    expected=value(ctx,r,'/properties/EndpointDetails/Vpc/VpcId');actual=value(ctx,subnet,'/properties/VpcId')
    if not vpc_id(expected) or not vpc_id(actual):return 'NEEDS_REVIEW'
    return 'PASS' if expected==actual else 'FAIL'


@resource_check('AWS::Transfer::WebApp')
def evaluate_transfer_webapp_subnet_vpc(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::Transfer::WebApp':
        for path in expand(ctx,resource,'/properties/EndpointDetails/Vpc/SubnetIds/*'):
            emit('TRANSFER_WEBAPP_SUBNET_VPC',path,subnet_vpc(ctx,resource,path),'linked subnet literal VpcId must match explicit endpoint VpcId; unknown/defaults, VPC aliases, conditional/external references, security groups and actual access remain held')
    return results
