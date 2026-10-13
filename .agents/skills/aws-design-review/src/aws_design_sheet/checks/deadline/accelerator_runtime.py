"""Checks for AWS::Deadline::Fleet."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'DEADLINE_ACCELERATOR_RUNTIME': [CF+'aws-properties-deadline-fleet-acceleratorcapabilities.html',CF+'aws-properties-deadline-fleet-acceleratorselection.html'],
}


@resource_check('AWS::Deadline::Fleet')
def evaluate_deadline_accelerator_runtime(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::Deadline::Fleet':
        path='/properties/Configuration/ServiceManagedEc2/InstanceCapabilities/AcceleratorCapabilities/Selections';raw=value(ctx,resource,path)
        if raw is not ABSENT:
            fixed=set();latest=False;omitted=False;pending=not isinstance(raw,list)
            for i in range(len(raw)) if isinstance(raw,list) else ():
                runtime=value(ctx,resource,path+'/'+str(i)+'/Runtime')
                if runtime is ABSENT:omitted=True
                elif runtime=='latest':latest=True
                elif literal(runtime) and re.fullmatch(r'grid:r[0-9]+',runtime):fixed.add(runtime)
                else:pending=True
            invalid=len(fixed)>1 or latest and omitted
            if fixed and (latest or omitted):pending=True
            emit('DEADLINE_ACCELERATOR_RUNTIME',path,'FAIL' if invalid else 'NEEDS_REVIEW' if pending else 'PASS','fixed accelerator runtimes must agree; explicit latest plus omitted runtime is forbidden; latest-to-fixed resolution, unknown values and chip compatibility remain separate')
    return results
