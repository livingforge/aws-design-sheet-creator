"""Compare explicit subnet/security-group VPC identities for Pipe configurations."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.scoped_resolution import resolved
from ..common.vpc_ids import vpc_id

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'PIPES_VPC_CONFIGURATION_IDENTITY':[CF+'aws-properties-pipes-pipe-awsvpcconfiguration.html',CF+'aws-properties-pipes-pipe-selfmanagedkafkaaccessconfigurationvpc.html']}
ROOTS=(('/properties/TargetParameters/EcsTaskParameters/NetworkConfiguration/AwsvpcConfiguration','SecurityGroups'),('/properties/SourceParameters/SelfManagedKafkaParameters/Vpc','SecurityGroup'))


def alignment(ctx,r,root,groups):
    if not resolved(r):return 'NEEDS_REVIEW'
    owners=[];pending=False;observed=False
    for key,kind in (('Subnets','AWS::EC2::Subnet'),(groups,'AWS::EC2::SecurityGroup')):
        raw=value(ctx,r,root+'/'+key)
        if raw is ABSENT or raw==[]:
            if key=='Subnets':pending=True
            continue
        if not isinstance(raw,list) or len(raw)>1000:pending=True;continue
        observed=True
        for i in range(len(raw)):
            member=linked(ctx,r,root+'/'+key+'/'+str(i),kind)
            if not resolved(member):pending=True;continue
            vpc=linked(ctx,member,'/properties/VpcId','AWS::EC2::VPC')
            if resolved(vpc):owners.append(('resource',vpc.id));continue
            raw_owner=value(ctx,member,'/properties/VpcId')
            if vpc_id(raw_owner):owners.append(('literal',raw_owner))
            else:pending=True
    if any(len({v for k,v in owners if k==kind})>1 for kind in ('resource','literal')):return 'FAIL'
    if pending or not observed or not owners or len({k for k,v in owners})>1:return 'NEEDS_REVIEW'
    return 'PASS'


@resource_check('AWS::Pipes::Pipe')
def evaluate_pipes_vpc_alignment(design,resource):
    if resource.type!='AWS::Pipes::Pipe':return []
    ctx=_Context(design,resource);results=[]
    for root,groups in ROOTS:
        if value(ctx,resource,root) is ABSENT:continue
        f=ctx.finding('PIPES_VPC_CONFIGURATION_IDENTITY',root,alignment(ctx,resource,root,groups),
            'All explicit subnet and security-group members in this VPC configuration must share one comparable VPC identity. ECS target and Kafka source are independent configurations. Mixed literal/resource aliases, missing or conditional links remain reviewable; runtime connectivity and task network mode are separate.')
        f['source_checked_at']='2026-10-04';results.append(f)
    return results
