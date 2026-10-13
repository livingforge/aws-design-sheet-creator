"""Checks for AWS::Kinesis::StreamConsumer."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.literals import known_scope, literal

SOURCES = {
    'KINESIS_CONSUMER_NAME_UNIQUE': ['https://docs.aws.amazon.com/kinesis/latest/APIReference/API_RegisterStreamConsumer.html'],
}


def stream_identity(ctx,resource):
    if not known_scope(resource):return None
    stream=linked(ctx,resource,'/properties/StreamARN','AWS::Kinesis::Stream')
    if stream:return ('resource',stream.id)
    arn=value(ctx,resource,'/properties/StreamARN')
    if not literal(arn):return None
    match=re.fullmatch(r'arn:(aws|aws-cn|aws-us-gov):kinesis:([^:]+):([0-9]{12}):stream/[A-Za-z0-9_.-]+',arn)
    if match and match[2]==resource.scope.region and match[3]==resource.scope.account:return ('arn',arn)
    return None


@resource_check('AWS::Kinesis::StreamConsumer')
def evaluate_kinesis_consumer_name_unique(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::Kinesis::StreamConsumer':
        name=get('/properties/ConsumerName');own=stream_identity(ctx,resource)
        pending=not literal(name) or own is None;duplicate=False
        for other in design.resources:
            if other.id==resource.id or other.type!=resource.type or other.scope!=resource.scope:continue
            other_name=value(ctx,other,'/properties/ConsumerName')
            if literal(name) and literal(other_name) and other_name!=name:continue
            identity=stream_identity(ctx,other)
            if own and identity and own[0]==identity[0] and own!=identity:continue
            if literal(name) and name==other_name and own and identity==own:duplicate=True
            else:pending=True
        emit('KINESIS_CONSUMER_NAME_UNIQUE','/properties/ConsumerName','FAIL' if duplicate else 'NEEDS_REVIEW' if pending else 'PASS','consumer names must be unique per comparable stream within the design scope; mixed identities, conditional references and external consumers remain unverified')
    return results
