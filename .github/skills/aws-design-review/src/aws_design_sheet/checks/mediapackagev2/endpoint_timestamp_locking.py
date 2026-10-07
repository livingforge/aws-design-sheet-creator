"""Checks for AWS::MediaPackageV2::OriginEndpoint."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.literals import literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'MEDIAPACKAGE_ENDPOINT_TIMESTAMP_LOCKING': [CF+'aws-properties-mediapackagev2-originendpoint-segment.html'],
}


def channel_locking(ctx,resource):
    if not resolved(resource):return 'NEEDS_REVIEW'
    timestamp=value(ctx,resource,'/properties/Segment/OutputTimestampMode')
    if timestamp not in ('PASSTHROUGH','REBASED_TO_CHANNEL_START'):return 'NEEDS_REVIEW'
    channel=linked(ctx,resource,'/properties/ChannelName','AWS::MediaPackageV2::Channel')
    if not resolved(channel):return 'NEEDS_REVIEW'
    # Channel names are unique only within their channel group. A link alone
    # does not establish the composite identity supplied by this endpoint.
    name=read(ctx,resource,'/properties/ChannelName')
    group=value(ctx,resource,'/properties/ChannelGroupName')
    if not literal(name) or not literal(group) or name!=value(ctx,channel,'/properties/ChannelName') or group!=value(ctx,channel,'/properties/ChannelGroupName'):return 'NEEDS_REVIEW'
    mode=value(ctx,channel,'/properties/OutputLockingMode')
    return 'PASS' if mode=='NON_EPOCH_LOCKED' else 'FAIL' if mode=='EPOCH_LOCKED' else 'NEEDS_REVIEW'


@resource_check('AWS::MediaPackageV2::OriginEndpoint')
def evaluate_mediapackagev2_endpoint_timestamp_locking(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::MediaPackageV2::OriginEndpoint':
        path='/properties/Segment/OutputTimestampMode'
        if value(ctx,resource,path) is not ABSENT:
            emit('MEDIAPACKAGE_ENDPOINT_TIMESTAMP_LOCKING',path,channel_locking(ctx,resource),'explicit timestamp mode requires a uniquely linked channel with matching explicit group/name and NON_EPOCH_LOCKED; unresolved identity, unknown/default locking and update immutability remain held')
    return results
