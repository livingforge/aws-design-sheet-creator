"""Explicit DAX subnet group VPC identity; no live inventory assumptions."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.scoped_resolution import resolved

SOURCES={'DAX_SUBNET_GROUP_VPC':[
 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-dax-cluster.html',
 'https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DAX.create-cluster.cli.html']}


@resource_check('AWS::DAX::Cluster')
def evaluate_dax_network(design,resource):
    if resource.type!='AWS::DAX::Cluster':return []
    ctx=_Context(design,resource);path='/properties/SubnetGroupName';verdict='NEEDS_REVIEW'
    group=linked(ctx,resource,path,'AWS::DAX::SubnetGroup') if resolved(resource) else None
    if resolved(group):
        subnets=value(ctx,group,'/properties/SubnetIds')
        if isinstance(subnets,list) and 0<len(subnets)<=1000:
            identities=[];pending=False
            for i in range(len(subnets)):
                subnet=linked(ctx,group,'/properties/SubnetIds/'+str(i),'AWS::EC2::Subnet')
                vpc=linked(ctx,subnet,'/properties/VpcId','AWS::EC2::VPC') if resolved(subnet) else None
                if resolved(vpc):identities.append(vpc.id)
                else:pending=True
            if len(set(identities))>1:verdict='FAIL'
            elif not pending:verdict='PASS'
    finding=ctx.finding('DAX_SUBNET_GROUP_VPC',path,verdict,
        'Explicit linked subnet group members must belong to one VPC; PASS covers only supplied VPC identities. Missing, conditional, external or oversized membership needs review; two proven different VPCs fail even with other unresolved members.')
    finding['source_checked_at']='2026-10-04'
    return [finding]
