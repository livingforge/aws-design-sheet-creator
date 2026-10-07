"""Checks for AWS::Pinpoint::Campaign."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'PINPOINT_CAMPAIGN_NUMERIC_BOUNDS': [CF+'aws-resource-pinpoint-campaign.html',CF+'aws-properties-pinpoint-campaign-limits.html'],
}


@resource_check('AWS::Pinpoint::Campaign')
def evaluate_pinpoint_campaign_numeric_bounds(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::Pinpoint::Campaign':
        for key,low,high in (('Priority',1,5),('Limits/Daily',None,100),('Limits/Total',None,100),('Limits/MaximumDuration',60,None),('Limits/MessagesPerSecond',1,20000)):
            path='/properties/'+key;raw=get(path)
            if raw is ABSENT:continue
            verdict='NEEDS_REVIEW' if type(raw) is not int else 'FAIL' if low is not None and raw<low or high is not None and raw>high else 'PASS'
            emit('PINPOINT_CAMPAIGN_NUMERIC_BOUNDS',path,verdict,'checks documented explicit integer campaign numeric bounds only; message body limits, unknown values and runtime delivery remain separate')
    return results
