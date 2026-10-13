"""Compare explicit DMS subnet-group and security-group VPC identities."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.scoped_resolution import resolved
from ..common.vpc_ids import vpc_id

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
CONFIGS={
    'AWS::DMS::ReplicationConfig':('ComputeConfig/ReplicationSubnetGroupId','ComputeConfig/VpcSecurityGroupIds','DMS_SERVERLESS_VPC_IDENTITY','aws-properties-dms-replicationconfig-computeconfig.html'),
    'AWS::DMS::ReplicationInstance':('ReplicationSubnetGroupIdentifier','VpcSecurityGroupIds','DMS_INSTANCE_VPC_IDENTITY','aws-resource-dms-replicationinstance.html'),
}
SOURCES={rule:[CF+page,CF+'aws-resource-dms-replicationsubnetgroup.html'] for _,_,rule,page in CONFIGS.values()}


def alignment(ctx,r,subnet_group_path,security_groups_path):
    if not resolved(r):return 'NEEDS_REVIEW'
    group=linked(ctx,r,subnet_group_path,'AWS::DMS::ReplicationSubnetGroup')
    owners=[];pending=not resolved(group)
    for owner,path,kind in ((group,'/properties/SubnetIds','AWS::EC2::Subnet'),(r,security_groups_path,'AWS::EC2::SecurityGroup')):
        if not resolved(owner):continue
        members=value(ctx,owner,path)
        if not isinstance(members,list) or not members or len(members)>1000:
            pending=True;continue
        for i in range(len(members)):
            member=linked(ctx,owner,path+'/'+str(i),kind)
            if not resolved(member):pending=True;continue
            vpc=linked(ctx,member,'/properties/VpcId','AWS::EC2::VPC')
            if resolved(vpc):owners.append(('resource',vpc.id));continue
            raw=value(ctx,member,'/properties/VpcId')
            if vpc_id(raw):owners.append(('literal',raw))
            else:pending=True
    if any(len({v for k,v in owners if k==kind})>1 for kind in ('resource','literal')):return 'FAIL'
    if pending or not owners or len({k for k,v in owners})>1:return 'NEEDS_REVIEW'
    return 'PASS'


@resource_check('AWS::DMS::ReplicationConfig','AWS::DMS::ReplicationInstance')
def evaluate_dms_vpc_alignment(design,resource):
    subnet,groups,rule,_=CONFIGS[resource.type]
    ctx=_Context(design,resource);path='/properties/'+groups
    if value(ctx,resource,path) is ABSENT:return []
    f=ctx.finding(rule,path,alignment(ctx,resource,'/properties/'+subnet,path),
        'Explicit subnet-group subnets and security groups must share one comparable VPC identity. Missing, external, conditional or mixed literal/resource aliases remain reviewable. This checks VPC membership, not traffic rules or runtime connectivity.')
    f['source_checked_at']='2026-10-04'
    return [f]
