"""Checks for AWS::Scheduler::Schedule."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal
from ..common.numbers import number

SOURCES = {
    'SCHEDULER_CAPACITY_BASE_COUNT': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-scheduler-schedule-capacityproviderstrategyitem.html',
    ],
}


@resource_check('AWS::Scheduler::Schedule')
def evaluate_scheduler_capacity_base_count(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::Scheduler::Schedule':
        path='/properties/Target/EcsParameters/CapacityProviderStrategy';raw=get(path)
        if raw is not ABSENT:
            providers=[];pending=not isinstance(raw,list)
            for i in range(len(raw)) if isinstance(raw,list) else ():
                p=path+'/'+str(i);base=get(p+'/Base')
                if base is ABSENT:continue
                provider=get(p+'/CapacityProvider')
                if number(base) is not None and literal(provider):providers.append(provider)
                else:pending=True
            pending|=len(set(providers))!=len(providers)
            emit('SCHEDULER_CAPACITY_BASE_COUNT',path,'FAIL' if len(set(providers))>1 else 'NEEDS_REVIEW' if pending else 'PASS','only one distinct capacity provider can have explicit numeric Base, including zero; omitted defaults are not counted; duplicate names and unknown values remain under review')
    return results
