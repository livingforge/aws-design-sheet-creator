"""Checks for AWS::Pipes::Pipe."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'PIPES_CAPACITY_BASE_COUNT': [CF+'aws-properties-pipes-pipe-capacityproviderstrategyitem.html'],
}


@resource_check('AWS::Pipes::Pipe')
def evaluate_pipes_capacity_base_count(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::Pipes::Pipe':
        path='/properties/TargetParameters/EcsTaskParameters/CapacityProviderStrategy';raw=get(path)
        if raw is not ABSENT:
            providers=[];pending=not isinstance(raw,list)
            for i in range(len(raw)) if isinstance(raw,list) else ():
                p=path+'/'+str(i);base=get(p+'/Base')
                if base is ABSENT:continue
                provider=get(p+'/CapacityProvider')
                if type(base) is int and literal(provider):providers.append(provider)
                else:pending=True
            pending|=len(set(providers))!=len(providers)
            emit('PIPES_CAPACITY_BASE_COUNT',path,'FAIL' if len(set(providers))>1 else 'NEEDS_REVIEW' if pending else 'PASS','only one distinct capacity provider may have explicit Base, including zero; repeated names, unknown values and actual ECS provider availability remain under review')
    return results
