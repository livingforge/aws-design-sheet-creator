"""Checks for AWS::AppRunner::VpcConnector."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'APPRUNNER_SECURITY_GROUP_VPC': [CF+'aws-resource-apprunner-vpcconnector.html'],
}


def runner_vpc(ctx,r):
    if not resolved(r):return 'NEEDS_REVIEW'
    ids=[]
    for key,kind in [('Subnets','AWS::EC2::Subnet'),('SecurityGroups','AWS::EC2::SecurityGroup')]:
        raw=value(ctx,r,'/properties/'+key)
        if not isinstance(raw,list) or not raw or len(raw)>1000:return 'NEEDS_REVIEW'
        for i in range(len(raw)):
            member=linked(ctx,r,'/properties/'+key+'/'+str(i),kind)
            if not resolved(member):return 'NEEDS_REVIEW'
            vpc=linked(ctx,member,'/properties/VpcId','AWS::EC2::VPC')
            if not resolved(vpc):return 'NEEDS_REVIEW'
            ids.append(vpc.id)
    return 'PASS' if len(set(ids))==1 else 'FAIL'


@resource_check('AWS::AppRunner::VpcConnector')
def evaluate_apprunner_security_group_vpc(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::AppRunner::VpcConnector' and value(ctx,resource,'/properties/SecurityGroups') is not ABSENT:
        emit('APPRUNNER_SECURITY_GROUP_VPC','/properties/SecurityGroups',runner_vpc(ctx,resource),'explicit linked subnets and security groups must resolve to the same known VPC; omitted defaults, conditional/external links, networking and permissions remain open')
    return results
