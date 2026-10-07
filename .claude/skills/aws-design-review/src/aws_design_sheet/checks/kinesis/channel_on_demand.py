"""Checks for AWS::Kinesis::Channel."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.known_template import resolved
from ..common.literals import expand

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'KINESIS_CHANNEL_ON_DEMAND': [CF+'aws-resource-kinesis-channel.html'],
}


@resource_check('AWS::Kinesis::Channel')
def evaluate_kinesis_channel_on_demand(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::Kinesis::Channel':
        for path in expand(ctx,resource,'/properties/StreamConfigurationList/*/StreamARN'):
            stream=linked(ctx,resource,path,'AWS::Kinesis::Stream') if resolved(resource) else None
            mode=value(ctx,stream,'/properties/StreamModeDetails/StreamMode') if resolved(stream) else None
            emit('KINESIS_CHANNEL_ON_DEMAND',path,'PASS' if mode=='ON_DEMAND' else 'FAIL' if mode=='PROVISIONED' else 'NEEDS_REVIEW','unique linked source stream must explicitly use ON_DEMAND; omitted modes, conditional links, external streams and actual deployment state remain held')
    return results
