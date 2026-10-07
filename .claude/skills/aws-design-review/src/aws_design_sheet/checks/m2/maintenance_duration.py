"""Checks for AWS::M2::Environment."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.maintenance_windows import window

SOURCES = {
    'M2_MAINTENANCE_DURATION': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-m2-environment.html',
    ],
}


@resource_check('AWS::M2::Environment')
def evaluate_m2_maintenance_duration(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    path='/properties/PreferredMaintenanceWindow';raw=get(path)
    if raw is not ABSENT:
        span=window(raw,True)
        emit('M2_MAINTENANCE_DURATION',path,'NEEDS_REVIEW' if span is None else 'PASS' if span[1]-span[0]<1440 else 'FAIL','explicit weekly maintenance window must be shorter than 24 hours, including week wraparound; equal endpoints and unknown/nonstandard formats remain under review')
    return results
