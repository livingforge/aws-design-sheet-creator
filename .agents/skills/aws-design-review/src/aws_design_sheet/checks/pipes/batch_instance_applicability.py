"""Checks for AWS::Pipes::Pipe."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'PIPES_BATCH_INSTANCE_APPLICABILITY': [CF+'aws-properties-pipes-pipe-batchcontaineroverrides.html',CF+'aws-resource-batch-jobdefinition.html'],
}


def batch_instance(ctx,r,path):
    if not resolved(r) or not literal(value(ctx,r,path)):return 'NEEDS_REVIEW'
    job=linked(ctx,r,'/properties/TargetParameters/BatchJobParameters/JobDefinition','AWS::Batch::JobDefinition')
    if not resolved(job):return 'NEEDS_REVIEW'
    kind=value(ctx,job,'/properties/Type');platform=value(ctx,job,'/properties/PlatformCapabilities')
    if platform is ABSENT:platform=['EC2']
    if kind=='container' or platform==['FARGATE']:return 'FAIL'
    if kind=='multinode' and platform in (['EC2'],['MANAGED_INSTANCES']):return 'PASS'
    return 'NEEDS_REVIEW'


@resource_check('AWS::Pipes::Pipe')
def evaluate_pipes_batch_instance_applicability(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict):
        f=ctx.finding(rule,path,verdict,'bounded explicit structural constraint; unknown values, omitted defaults, other nested conditions and runtime state remain held')
        f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::Pipes::Pipe':
        path='/properties/TargetParameters/BatchJobParameters/ContainerOverrides/InstanceType'
        if value(ctx,resource,path) is not ABSENT:
            f=ctx.finding('PIPES_BATCH_INSTANCE_APPLICABILITY',path,batch_instance(ctx,resource,path),'InstanceType override is for a declared multi-node non-Fargate job. Omitted PlatformCapabilities uses the documented EC2 default. Unknown or ambiguous platforms remain reviewable. PASS covers this override applicability only, not general job-platform compatibility, instance availability or execution.');f['source_checked_at']='2026-10-04';results.append(f)
    return results
