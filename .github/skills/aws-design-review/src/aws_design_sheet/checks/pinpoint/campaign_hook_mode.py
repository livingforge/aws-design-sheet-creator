"""Checks for AWS::Pinpoint::ApplicationSettings, AWS::Pinpoint::Campaign."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'PINPOINT_CAMPAIGN_HOOK_MODE': [CF+'aws-properties-pinpoint-campaign-campaignhook.html',CF+'aws-properties-pinpoint-applicationsettings-campaignhook.html'],
}


@resource_check('AWS::Pinpoint::Campaign', 'AWS::Pinpoint::ApplicationSettings')
def evaluate_pinpoint_campaign_hook_mode(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type in ('AWS::Pinpoint::Campaign','AWS::Pinpoint::ApplicationSettings'):
        path='/properties/'+('Hook' if resource.type=='AWS::Pinpoint::Campaign' else 'CampaignHook')+'/Mode';raw=value(ctx,resource,path)
        if raw is not ABSENT:
            verdict='NEEDS_REVIEW' if not literal(raw) or raw=='DELIVERY' else 'PASS' if raw=='FILTER' else 'FAIL'
            emit('PINPOINT_CAMPAIGN_HOOK_MODE',path,verdict,'FILTER is documented; DELIVERY remains held because listed but deprecated and unsupported; omitted defaults, Lambda permissions and delivery behavior remain held')
    return results
