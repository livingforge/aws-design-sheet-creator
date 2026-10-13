"""Checks for AWS::GameLiftStreams::StreamGroup."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import known_scope, literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'GAMELIFT_STREAM_HOME_LOCATION': [CF+'aws-resource-gameliftstreams-streamgroup.html'],
}


@resource_check('AWS::GameLiftStreams::StreamGroup')
def evaluate_gameliftstreams_stream_home_location(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::GameLiftStreams::StreamGroup':
        path='/properties/LocationConfigurations'
        raw=value(ctx,resource,path)
        if raw is not ABSENT:
            verdict='NEEDS_REVIEW'
            if known_scope(resource) and isinstance(raw,list) and len(raw)<=100:
                names=[value(ctx,resource,path+'/'+str(i)+'/LocationName') for i in range(len(raw))]
                verdict='PASS' if resource.scope.region in names else 'FAIL' if all(literal(n) for n in names) else 'NEEDS_REVIEW'
            emit('GAMELIFT_STREAM_HOME_LOCATION',path,verdict,'explicit locations must include deployment home Region; capacity, availability and unknown entries remain separate')
    return results
