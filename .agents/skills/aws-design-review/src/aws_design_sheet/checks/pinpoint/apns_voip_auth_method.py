"""Checks for AWS::Pinpoint::APNSVoipChannel."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'PINPOINT_APNS_VOIP_AUTH_METHOD': [CF+'aws-resource-pinpoint-apnsvoipchannel.html'],
}


@resource_check('AWS::Pinpoint::APNSVoipChannel')
def evaluate_pinpoint_apns_voip_auth_method(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::Pinpoint::APNSVoipChannel':
        path='/properties/DefaultAuthenticationMethod';raw=value(ctx,resource,path)
        if raw is not ABSENT:emit('PINPOINT_APNS_VOIP_AUTH_METHOD',path,'NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in ('key','certificate') else 'FAIL','explicit VoIP authentication method uses key or certificate; defaults, unknowns, credentials and delivery remain held')
    return results
