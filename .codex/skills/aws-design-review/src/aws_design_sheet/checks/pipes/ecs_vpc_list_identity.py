"""Checks for AWS::Pipes::Pipe."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.scoped_resolution import resolved
from ..common.vpc_ids import vpc_id

SOURCES = {
    'PIPES_ECS_VPC_LIST_IDENTITY': ['https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-pipes-pipe-awsvpcconfiguration.html'],
}


def list_vpcs(ctx,r,path,kind):
    raw=value(ctx,r,path)
    if not resolved(r) or not isinstance(raw,list) or not raw:return 'NEEDS_REVIEW'
    owners=[]
    for i in range(len(raw)):
        member=linked(ctx,r,path+'/'+str(i),kind)
        if not resolved(member):return 'NEEDS_REVIEW'
        owner=value(ctx,member,'/properties/VpcId')
        if not vpc_id(owner):return 'NEEDS_REVIEW'
        owners.append(owner)
    return 'PASS' if len(set(owners))==1 else 'FAIL'


@resource_check('AWS::Pipes::Pipe')
def evaluate_pipes_ecs_vpc_list_identity(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::Pipes::Pipe':
        root='/properties/TargetParameters/EcsTaskParameters/NetworkConfiguration/AwsvpcConfiguration'
        for key,kind in (('Subnets','AWS::EC2::Subnet'),('SecurityGroups','AWS::EC2::SecurityGroup')):
            path=root+'/'+key
            if value(ctx,resource,path) is not ABSENT:
                emit('PIPES_ECS_VPC_LIST_IDENTITY',path,list_vpcs(ctx,resource,path,kind),'all explicit linked members within this list must share a literal VpcId; cross-list alignment, task-definition awsvpc applicability, defaults, aliases and external/conditional references remain held')
    return results
