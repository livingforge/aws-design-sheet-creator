"""Guard legacy first-element assumptions without changing preserved rule records."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-batch-jobdefinition.html'
API='https://docs.aws.amazon.com/batch/latest/APIReference/API_RegisterJobDefinition.html'
SOURCES={'BATCH_PLATFORM_CAPABILITY_MODE':[CF,API],'BATCH_MANAGED_INSTANCE_PROPERTIES':[CF,API]}
GUARDED={
 'BATCH.JOBDEFINITION.FARGATE_NOT_MULTINODE',
 'BATCH.JOBDEFINITION.FARGATE_EXECUTION_ROLE_REQUIRED',
 'BATCH.JOBDEFINITION.FARGATE_UNSUPPORTED_CONTAINER_PROPERTIES',
 'BATCH.JOBDEFINITION.EC2_NO_FARGATE_CONTAINER_SETTINGS',
 'BATCH.JOBDEFINITION.FARGATE_LOG_DRIVER',
}
MODES=('EC2','FARGATE','MANAGED_INSTANCES')


def guard_batch_findings(rule,design,resource,findings):
    if resource.type!='AWS::Batch::JobDefinition' or rule.id not in GUARDED:return findings
    ctx=_Context(design,resource);path='/properties/PlatformCapabilities';raw=value(ctx,resource,path)
    if raw is ABSENT or isinstance(raw,list) and len(raw)==1 and raw[0] in MODES:return findings
    guarded=[]
    for original in findings:
        row=dict(original)
        row.update(verdict='NEEDS_REVIEW',reason='PlatformCapabilities does not identify one explicit supported mode; preserved rule first-element condition cannot establish applicability. '+original['reason'],
            evidence_ids=list(dict.fromkeys(original.get('evidence_ids',[])+ctx.evidence)),
            dependencies=list(dict.fromkeys(original.get('dependencies',[])+ctx.dependencies+[resource.id+path])))
        guarded.append(row)
    return guarded


@resource_check('AWS::Batch::JobDefinition')
def evaluate_batch_platform_guard(design,resource):
    if resource.type!='AWS::Batch::JobDefinition':return []
    ctx=_Context(design,resource);path='/properties/PlatformCapabilities';raw=value(ctx,resource,path);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if raw is not ABSENT:
        mode='NEEDS_REVIEW'
        if isinstance(raw,list):
            if any(literal(v) and v not in MODES for v in raw):mode='FAIL'
            elif len(raw)==1 and raw[0] in MODES:mode='PASS'
        emit('BATCH_PLATFORM_CAPABILITY_MODE',path,mode,'single explicit supported mode resolves legacy applicability; empty, mixed/multiple and unknown modes held without assuming the first element; omitted default EC2 is retained')
    if raw==['MANAGED_INSTANCES']:
        ecs=value(ctx,resource,'/properties/EcsProperties');container=value(ctx,resource,'/properties/ContainerProperties');nodes=value(ctx,resource,'/properties/NodeProperties');kind=value(ctx,resource,'/properties/Type')
        if ecs is ABSENT or isinstance(container,dict) and '$state' not in container or isinstance(nodes,dict) and '$state' not in nodes or kind=='multinode':verdict='FAIL'
        elif isinstance(ecs,dict) and '$state' not in ecs and container is ABSENT and nodes is ABSENT and kind=='container':verdict='PASS'
        else:verdict='NEEDS_REVIEW'
        emit('BATCH_MANAGED_INSTANCE_PROPERTIES','/properties/EcsProperties',verdict,'explicit MANAGED_INSTANCES requires ecsProperties and forbids containerProperties/multinode; task contents and runtime eligibility remain separate')
    return results
