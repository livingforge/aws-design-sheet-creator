"""Checks for AWS::Pinpoint::ApplicationSettings."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'PINPOINT_APPLICATION_LIMITS': [CF+'aws-properties-pinpoint-applicationsettings-limits.html'],
}


@resource_check('AWS::Pinpoint::ApplicationSettings')
def evaluate_pinpoint_application_limits(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::Pinpoint::ApplicationSettings':
        for key,low,high in [('Daily',None,100),('Total',None,100),('MaximumDuration',60,None),('MessagesPerSecond',1,20000)]:
            path='/properties/Limits/'+key
            raw=value(ctx,resource,path)
            if raw is ABSENT:continue
            verdict='NEEDS_REVIEW' if type(raw) is not int or low is None and raw<0 else 'FAIL' if low is not None and raw<low or high is not None and raw>high else 'PASS'
            emit('PINPOINT_APPLICATION_LIMITS',path,verdict,'explicit integer sending limits use documented Daily/Total ceiling 100, duration floor 60 and messages/second 1..20000; unknown/default values, undocumented Daily/Total floors and delivery behavior remain held')
    return results
