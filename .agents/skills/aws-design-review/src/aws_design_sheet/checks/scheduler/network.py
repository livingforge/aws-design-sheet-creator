"""Scheduler ECS task network mode and explicit VPC membership."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.logical_vpc_identity import identity
from ..common.scoped_resolution import resolved
from ..common.subnet_zones import explicit

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={
 'SCHEDULER_ECS_NETWORK_MODE':[CF+'aws-properties-scheduler-schedule-ecsparameters.html',CF+'aws-resource-ecs-taskdefinition.html','https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_RunTask.html'],
 'SCHEDULER_ECS_VPC_IDENTITY':[CF+'aws-properties-scheduler-schedule-awsvpcconfiguration.html'],
}
ROOT='/properties/Target/EcsParameters'
NETWORK=ROOT+'/NetworkConfiguration'
VPC=NETWORK+'/AwsvpcConfiguration'


def mode(ctx,r):
    if not resolved(r) or read(ctx,r,ROOT+'/TaskDefinitionArn') is not ABSENT:return 'NEEDS_REVIEW'
    task=linked(ctx,r,ROOT+'/TaskDefinitionArn','AWS::ECS::TaskDefinition')
    if not resolved(task):return 'NEEDS_REVIEW'
    network=value(ctx,task,'/properties/NetworkMode')
    # Do not infer Linux bridge when Windows/default task context is unresolved.
    if network is ABSENT:return 'NEEDS_REVIEW'
    config=value(ctx,r,NETWORK)
    known=isinstance(config,dict) and '$state' not in config and not any(k.startswith('Fn::') or k=='Ref' for k in config)
    if network=='awsvpc':
        if config is ABSENT:return 'FAIL'
        if known:return 'PASS'
    elif network in ('none','bridge','host'):
        if config is ABSENT:return 'NOT_APPLICABLE'
        if known:return 'FAIL'
    return 'NEEDS_REVIEW'


def vpcs(ctx,r):
    if not resolved(r):return 'NEEDS_REVIEW'
    identities=[];pending=False
    for key,kind,limit in [('Subnets','AWS::EC2::Subnet',16),('SecurityGroups','AWS::EC2::SecurityGroup',5)]:
        raw=value(ctx,r,VPC+'/'+key)
        if key=='SecurityGroups' and raw is ABSENT:continue
        if not isinstance(raw,list) or not 1<=len(raw)<=limit:pending=True;continue
        identities.extend(identity(ctx,explicit(ctx,r,VPC+'/'+key+'/'+str(i),kind)) for i in range(len(raw)))
    known=[v for v in identities if v is not None]
    if any(a[0]==b[0] and a!=b for a in known for b in known):return 'FAIL'
    return 'PASS' if not pending and len(known)==len(identities) and len(set(known))==1 else 'NEEDS_REVIEW'


@resource_check('AWS::Scheduler::Schedule')
def evaluate_scheduler_network(design,resource):
    if resource.type!='AWS::Scheduler::Schedule':return []
    ctx=_Context(design,resource);out=[]
    for rule,path,applicable,check,reason in [
        ('SCHEDULER_ECS_NETWORK_MODE',NETWORK,ROOT,mode,'An explicitly linked task using awsvpc requires NetworkConfiguration; other explicit network modes do not support it. Configuration content, launch compatibility and regional support are separate.'),
        ('SCHEDULER_ECS_VPC_IDENTITY',VPC,VPC,vpcs,'All explicit subnet and security-group members must share one comparable VPC identity. Omitted security groups use the documented VPC default. Mixed logical/physical aliases, conditional links and external topology remain reviewable.')]:
        if value(ctx,resource,applicable) is ABSENT:continue
        f=ctx.finding(rule,path,check(ctx,resource),reason+' PASS covers only the declared relationship, not deployability.');f['source_checked_at']='2026-10-04';out.append(f)
    return out
