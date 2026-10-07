"""Checks for AWS::Pipes::Pipe."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.literals import expand, literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'PIPES_ACCELERATOR_DEVICE_MEMBER': [CF+'aws-properties-pipes-pipe-ecsinferenceacceleratoroverride.html'],
}


def device_member(ctx,r,path):
    name=value(ctx,r,path)
    task=linked(ctx,r,'/properties/TargetParameters/EcsTaskParameters/TaskDefinitionArn','AWS::ECS::TaskDefinition')
    if not literal(name) or name.startswith('$') or not resolved(r) or not resolved(task):return 'NEEDS_REVIEW'
    devices=value(ctx,task,'/properties/InferenceAccelerators')
    if not isinstance(devices,list) or len(devices)>1000:return 'NEEDS_REVIEW'
    names=[value(ctx,task,'/properties/InferenceAccelerators/'+str(i)+'/DeviceName') for i in range(len(devices))]
    if not all(literal(x) for x in names) or len(set(names))!=len(names):return 'NEEDS_REVIEW'
    return 'PASS' if name in names else 'FAIL'


@resource_check('AWS::Pipes::Pipe')
def evaluate_pipes_accelerator_device_member(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::Pipes::Pipe':
        for path in expand(ctx,resource,'/properties/TargetParameters/EcsTaskParameters/Overrides/InferenceAcceleratorOverrides/*/DeviceName'):
            emit('PIPES_ACCELERATOR_DEVICE_MEMBER',path,device_member(ctx,resource,path),'explicit override device name must occur in the linked task definition explicit accelerator list; unknown/default lists, launch compatibility, resource requirements, device types and feature availability remain held')
    return results
