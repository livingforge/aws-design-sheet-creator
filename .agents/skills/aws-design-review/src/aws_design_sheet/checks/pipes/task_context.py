"""Pipe ECS task network-mode and accelerator resource requirement context."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal
from ..common.scoped_resolution import resolved
from .accelerator_device_member import device_member

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={
 'PIPES_ECS_TASK_NETWORK_MODE':[CF+'aws-properties-pipes-pipe-pipetargetecstaskparameters.html',CF+'aws-resource-ecs-taskdefinition.html'],
 'PIPES_RESOURCE_ACCELERATOR_MEMBER':[CF+'aws-properties-pipes-pipe-ecsresourcerequirement.html'],
}
ROOT='/properties/TargetParameters/EcsTaskParameters'


@resource_check('AWS::Pipes::Pipe')
def evaluate_pipes_task_context(design,resource):
    if resource.type!='AWS::Pipes::Pipe':return []
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if value(ctx,resource,ROOT) is not ABSENT:
        task=linked(ctx,resource,ROOT+'/TaskDefinitionArn','AWS::ECS::TaskDefinition')
        config=value(ctx,resource,ROOT+'/NetworkConfiguration');verdict='NEEDS_REVIEW'
        if resolved(resource) and resolved(task):
            mode=value(ctx,task,'/properties/NetworkMode')
            if mode is ABSENT:mode='bridge'
            known=isinstance(config,dict) and '$state' not in config
            if mode=='awsvpc':
                if config is ABSENT:verdict='FAIL'
                elif known:verdict='PASS'
            elif mode in ('none','bridge','host'):
                if config is ABSENT:verdict='NOT_APPLICABLE'
                elif known:verdict='FAIL'
        emit('PIPES_ECS_TASK_NETWORK_MODE',ROOT+'/NetworkConfiguration',verdict,'NetworkConfiguration is required for a linked awsvpc task and unsupported for other known network modes. Omitted task NetworkMode uses documented bridge default. Unknown task/configuration remains reviewable; configuration contents and launch compatibility are separate.')
    for path in expand(ctx,resource,ROOT+'/Overrides/ContainerOverrides/*/ResourceRequirements/*'):
        kind=value(ctx,resource,path+'/Type')
        if kind=='InferenceAccelerator':
            emit('PIPES_RESOURCE_ACCELERATOR_MEMBER',path+'/Value',device_member(ctx,resource,path+'/Value'),'InferenceAccelerator requirement Value must name a device from the linked task definition. This validates membership only, not retired service availability or GPU capacity.')
        elif not literal(kind):emit('PIPES_RESOURCE_ACCELERATOR_MEMBER',path,'NEEDS_REVIEW','Unknown requirement type; accelerator applicability cannot be established.')
    return results
