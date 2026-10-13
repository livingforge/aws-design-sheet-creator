"""Bounded ARC execution-block unions and associated-alarm references."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
API='https://docs.aws.amazon.com/arc-region-switch/latest/api/'
SOURCES={
 'ARC_EXECUTION_BLOCK_UNION':[CF+'aws-properties-arcregionswitch-plan-step.html',CF+'aws-properties-arcregionswitch-plan-executionblockconfiguration.html',API+'API_ExecutionBlockConfiguration.html'],
 'ARC_TRIGGER_ALARM_REFERENCE':[CF+'aws-properties-arcregionswitch-plan-triggercondition.html',CF+'aws-properties-arcregionswitch-plan-associatedalarm.html'],
}
BLOCKS={
 'ARCRegionSwitchPlan':'RegionSwitchPlanConfig','ARCRoutingControl':'ArcRoutingControlConfig',
 'AuroraGlobalDatabase':'GlobalAuroraConfig','AuroraProvisionedScaling':'AuroraProvisionedScalingConfig',
 'AuroraServerlessScaling':'AuroraServerlessScalingConfig','CustomActionLambda':'CustomActionLambdaConfig',
 'DocumentDb':'DocumentDbConfig','EC2AutoScaling':'Ec2AsgCapacityIncreaseConfig',
 'ECSServiceScaling':'EcsCapacityIncreaseConfig','EKSResourceScaling':'EksResourceScalingConfig',
 'LambdaEventSourceMapping':'LambdaEventSourceMappingConfig','ManualApproval':'ExecutionApprovalConfig',
 'NeptuneGlobalDatabase':'NeptuneGlobalDatabaseConfig','Parallel':'ParallelConfig',
 'RdsCreateCrossRegionReplica':'RdsCreateCrossRegionReadReplicaConfig','RdsPromoteReadReplica':'RdsPromoteReadReplicaConfig',
 'RdsSwitchoverReadReplica':'RdsSwitchoverReadReplicaConfig','Route53HealthCheck':'Route53HealthCheckConfig',
}


def block_verdict(ctx,r,path):
    kind=value(ctx,r,path+'/ExecutionBlockType')
    raw=value(ctx,r,path+'/ExecutionBlockConfiguration')
    if not literal(kind) or kind not in BLOCKS:return 'NEEDS_REVIEW'
    if raw is ABSENT:return 'FAIL'
    if not isinstance(raw,dict) or '$state' in raw or any(k not in BLOCKS.values() for k in raw):return 'NEEDS_REVIEW'
    values={key:value(ctx,r,path+'/ExecutionBlockConfiguration/'+key) for key in raw}
    if any(not isinstance(v,dict) or '$state' in v for v in values.values()):return 'NEEDS_REVIEW'
    return 'PASS' if list(values)==[BLOCKS[kind]] else 'FAIL'


@resource_check('AWS::ARCRegionSwitch::Plan')
def evaluate_arcregionswitch_workflow_blocks(design,resource):
    if resource.type!='AWS::ARCRegionSwitch::Plan':return []
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    pending=[(path,0) for path in expand(ctx,resource,'/properties/Workflows/*/Steps')];count=0
    while pending:
        base,depth=pending.pop();raw=value(ctx,resource,base)
        if depth>32 or not isinstance(raw,list) or count+len(raw)>1000:
            emit('ARC_EXECUTION_BLOCK_UNION',base,'NEEDS_REVIEW','step traversal requires explicit lists within depth 32 and 1000 steps');continue
        count+=len(raw)
        for i in range(len(raw)):
            path=base+'/'+str(i);step=value(ctx,resource,path)
            verdict=block_verdict(ctx,resource,path) if isinstance(step,dict) and '$state' not in step else 'NEEDS_REVIEW'
            emit('ARC_EXECUTION_BLOCK_UNION',path+'/ExecutionBlockConfiguration',verdict,'known execution block type requires exactly its matching configuration member; block contents, workflow resource state and IAM permissions are separate')
            children=path+'/ExecutionBlockConfiguration/ParallelConfig/Steps'
            if value(ctx,resource,children) is not ABSENT:pending.append((children,depth+1))
    alarms=value(ctx,resource,'/properties/AssociatedAlarms')
    for path in expand(ctx,resource,'/properties/Triggers/*/Conditions/*/AssociatedAlarmName'):
        name=value(ctx,resource,path)
        if not literal(name) or not isinstance(alarms,dict) or '$state' in alarms or any(not literal(k) or '/' in k or '~' in k for k in alarms):verdict='NEEDS_REVIEW'
        else:verdict='PASS' if name in alarms else 'FAIL'
        emit('ARC_TRIGGER_ALARM_REFERENCE',path,verdict,'explicit trigger condition names must identify a supplied AssociatedAlarms map entry; alarm type/content, metrics, runtime state and cross-account access remain open')
    return results
