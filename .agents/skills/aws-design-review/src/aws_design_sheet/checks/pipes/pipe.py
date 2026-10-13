"""Checks for AWS::Pipes::Pipe."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'PIPES_SYNC_WORKFLOW_TYPE': [CF+'aws-properties-pipes-pipe-pipetargetstatemachineparameters.html'],
    'PIPES_DEDUP_FIFO_TARGET': [CF+'aws-properties-pipes-pipe-pipetargetsqsqueueparameters.html',CF+'aws-resource-sqs-queue.html'],
}
SYNC='/properties/TargetParameters/StepFunctionStateMachineParameters/InvocationType'
DEDUP='/properties/TargetParameters/SqsQueueParameters/MessageDeduplicationId'


def pipe_target(ctx,resource,path):
    raw=value(ctx,resource,path)
    if not resolved(resource) or not literal(raw):return 'NEEDS_REVIEW'
    if path==SYNC and raw!='REQUEST_RESPONSE':return 'NEEDS_REVIEW'
    target=linked(ctx,resource,'/properties/Target','AWS::StepFunctions::StateMachine' if path==SYNC else 'AWS::SQS::Queue')
    if not resolved(target):return 'NEEDS_REVIEW'
    kind=value(ctx,target,'/properties/StateMachineType' if path==SYNC else '/properties/FifoQueue')
    if path==SYNC:
        return 'PASS' if kind=='EXPRESS' else 'FAIL' if kind=='STANDARD' else 'NEEDS_REVIEW'
    if kind is ABSENT:kind=False  # CloudFormation creates a standard queue by default.
    return 'PASS' if kind is True else 'FAIL' if kind is False else 'NEEDS_REVIEW'


@resource_check('AWS::Pipes::Pipe')
def evaluate_pipes_pipe(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict):
        finding=ctx.finding(rule,path,verdict,'explicit local constraint only; unknown/default values, unresolved targets, permissions and actual service/asset state remain held')
        finding['source_checked_at']='2026-10-04';results.append(finding)
    if resource.type=='AWS::Pipes::Pipe':
        for path,rule in ((SYNC,'PIPES_SYNC_WORKFLOW_TYPE'),(DEDUP,'PIPES_DEDUP_FIFO_TARGET')):
            if value(ctx,resource,path) is not ABSENT:emit(rule,path,pipe_target(ctx,resource,path))
    return results
