"""Checks for AWS::DLM::LifecyclePolicy."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'DLM_DEPRECATION_SAME_UNIT': [CF+'aws-properties-dlm-lifecyclepolicy-deprecaterule.html',CF+'aws-properties-dlm-lifecyclepolicy-crossregioncopydeprecaterule.html'],
}


@resource_check('AWS::DLM::LifecyclePolicy')
def evaluate_dlm_deprecation_same_unit(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(p):return value(ctx,resource,p)
    def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
    if resource.type=='AWS::DLM::LifecyclePolicy':
        for schedule in expand(ctx,resource,'/properties/PolicyDetails/Schedules/*'):
            for base in [schedule]+list(expand(ctx,resource,schedule+'/CrossRegionCopyRules/*')):
                p=base+'/DeprecateRule/Interval';interval=get(p)
                if interval is ABSENT:continue
                retained=get(base+'/RetainRule/Interval');unit=get(base+'/DeprecateRule/IntervalUnit');other=get(base+'/RetainRule/IntervalUnit')
                known=type(interval) is int and type(retained) is int and unit in ('DAYS','WEEKS','MONTHS','YEARS') and unit==other
                emit('DLM_DEPRECATION_SAME_UNIT',p,'NEEDS_REVIEW' if not known else 'PASS' if interval<=retained else 'FAIL','explicit deprecation interval cannot exceed retention in the same documented unit; calendar conversion, count-based and archive-kind alignment held')
    return results
