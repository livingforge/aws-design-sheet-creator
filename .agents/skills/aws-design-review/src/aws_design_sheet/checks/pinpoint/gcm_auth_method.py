"""Checks for AWS::Pinpoint::GCMChannel."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'PINPOINT_GCM_AUTH_METHOD': [CF+'aws-resource-pinpoint-gcmchannel.html'],
}


@resource_check('AWS::Pinpoint::GCMChannel')
def evaluate_pinpoint_gcm_auth_method(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    def enum(raw,allowed):return 'NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in allowed else 'FAIL'
    if resource.type=='AWS::Pinpoint::GCMChannel':
        path='/properties/DefaultAuthenticationMethod';raw=value(ctx,resource,path)
        if raw is not ABSENT:emit('PINPOINT_GCM_AUTH_METHOD',path,enum(raw,('KEY','TOKEN')),'explicit authentication method must be KEY or TOKEN; omitted default, credentials requiredness/validity and runtime delivery remain held')
    return results
