"""Checks for AWS::Cognito::IdentityPool."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT, read
from ..common.literals import known_scope, literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'COGNITO_STREAM_LINK_SCOPE': [CF+'aws-properties-cognito-identitypool-cognitostreams.html',CF+'aws-resource-kinesis-stream.html'],
}


def stream_scope(ctx,resource,path):
    # StreamName is a name, not an ARN. Require literal matching names in
    # addition to an explicit relation before comparing cross-scope targets.
    name = read(ctx,resource,path)
    refs = [r for r in ctx.design.relations if r.source_resource_id==resource.id and r.source_path==path]
    if not known_scope(resource) or not literal(name) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}',name) or len(refs)!=1 or refs[0].condition:
        return 'NEEDS_REVIEW'
    stream = ctx.by_id.get(refs[0].target_resource_id)
    if stream is None or stream.type!='AWS::Kinesis::Stream' or not known_scope(stream) or stream.scope.environment!=resource.scope.environment:
        return 'NEEDS_REVIEW'
    if any(r.template is not None and r.template.state.value!='KNOWN' for r in (resource,stream)):
        return 'NEEDS_REVIEW'
    target_name = value(ctx,stream,'/properties/Name')
    if not literal(target_name) or target_name!=name:
        return 'NEEDS_REVIEW'
    ctx.evidence.extend(refs[0].evidence_ids)
    return 'PASS' if (stream.scope.account,stream.scope.region)==(resource.scope.account,resource.scope.region) else 'FAIL'


@resource_check('AWS::Cognito::IdentityPool')
def evaluate_cognito_stream_link_scope(design,resource):
    ctx = _Context(design,resource)
    results = []
    def emit(rule,path,verdict,reason):
        finding = ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at'] = '2026-10-04'
        results.append(finding)
    if resource.type == 'AWS::Cognito::IdentityPool':
        path = '/properties/CognitoStreams/StreamName'
        if value(ctx,resource,path) is not ABSENT:
            emit('COGNITO_STREAM_LINK_SCOPE',path,stream_scope(ctx,resource,path),'literal StreamName and uniquely linked Kinesis Name must match before comparing account/Region; ARN-like names, unresolved names, other environments, existence and PutRecord permissions remain held')
    return results
