"""Checks for AWS::Scheduler::Schedule."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value

SOURCES = {
    'SCHEDULER_FIFO_DEDUP': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-scheduler-schedule-sqsparameters.html',
    ],
}


@resource_check('AWS::Scheduler::Schedule')
def evaluate_scheduler_fifo_dedup(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(p):return value(ctx,resource,p)
    def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
    if resource.type=='AWS::Scheduler::Schedule':
        queue=linked(ctx,resource,'/properties/Target/Arn','AWS::SQS::Queue');fifo=value(ctx,queue,'/properties/FifoQueue') if queue else None;dedup=value(ctx,queue,'/properties/ContentBasedDeduplication') if queue else None
        v='NOT_APPLICABLE' if fifo is False else 'PASS' if fifo is True and dedup is True else 'FAIL' if fifo is True and dedup is False else 'NEEDS_REVIEW'
        emit('SCHEDULER_FIFO_DEDUP','/properties/Target/Arn',v,'explicit linked FIFO target requires explicit content-based deduplication true; omitted flags, universal targets and external queue state held')
    return results
