"""Checks for AWS::Location::TrackerConsumer."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'LOCATION_TRACKER_CONSUMER_ACCOUNT': [CF+'aws-resource-location-trackerconsumer.html'],
}


def consumer_account(ctx,resource,path):
    if resource.template is not None and resource.template.state.value!='KNOWN':return 'NEEDS_REVIEW'
    raw=value(ctx,resource,path)
    if not literal(raw) or not re.fullmatch(r'[0-9]{12}',resource.scope.account):return 'NEEDS_REVIEW'
    match=re.fullmatch(r'arn:(aws|aws-cn|aws-us-gov):geo:[a-z]{2}(?:-[a-z]+)+-[0-9]+:([0-9]{12}):geofence-collection/[A-Za-z0-9_.\-]+',raw)
    if not match:return 'NEEDS_REVIEW'
    return 'PASS' if match[2]==resource.scope.account else 'FAIL'


@resource_check('AWS::Location::TrackerConsumer')
def evaluate_location_tracker_consumer_account(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::Location::TrackerConsumer':
        path='/properties/ConsumerArn'
        if value(ctx,resource,path) is not ABSENT:
            emit('LOCATION_TRACKER_CONSUMER_ACCOUNT',path,consumer_account(ctx,resource,path),'literal geofence collection ARN must belong to the deployment account; unresolved/external identity, tracker existence, permissions, Region and partition remain held')
    return results
