"""Checks for AWS::Grafana::Workspace."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.scoped_resolution import resolved

SOURCES = {
    'GRAFANA_WORKSPACE_VPC_MEMBERS': ['https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-grafana-workspace-vpcconfiguration.html'],
}


def grafana_vpc(ctx,resource):
    if not resolved(resource):return 'NEEDS_REVIEW'
    owners=set()
    pending=False
    for field,kind in [('SubnetIds','AWS::EC2::Subnet'),('SecurityGroupIds','AWS::EC2::SecurityGroup')]:
        path='/properties/VpcConfiguration/'+field
        raw=value(ctx,resource,path)
        if not isinstance(raw,list) or not raw or len(raw)>1000:
            pending=True
            continue
        for i in range(len(raw)):
            member=linked(ctx,resource,path+'/'+str(i),kind)
            owner=linked(ctx,member,'/properties/VpcId','AWS::EC2::VPC') if resolved(member) else None
            if not resolved(owner):pending=True
            else:owners.add(owner.id)
    return 'FAIL' if len(owners)>1 else 'NEEDS_REVIEW' if pending or not owners else 'PASS'


@resource_check('AWS::Grafana::Workspace')
def evaluate_grafana_workspace_vpc_members(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::Grafana::Workspace':
        path='/properties/VpcConfiguration'
        if value(ctx,resource,path) is not ABSENT:
            emit('GRAFANA_WORKSPACE_VPC_MEMBERS',path,grafana_vpc(ctx,resource),'explicit subnet and security-group links must resolve to one VPC identity; unknown members, templates, external resources, connectivity and regional availability remain held')
    return results
