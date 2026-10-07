"""Checks for AWS::OpenSearchServerless::SecurityPolicy."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.json_verdict import json_verdict

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'OPENSEARCHSERVERLESS_SECURITY_POLICY_JSON': [CF+'aws-resource-opensearchserverless-securitypolicy.html'],
}


@resource_check('AWS::OpenSearchServerless::SecurityPolicy')
def evaluate_opensearchserverless_security_policy_json(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::OpenSearchServerless::SecurityPolicy':
        path='/properties/Policy'
        raw=value(ctx,resource,path)
        if raw is not ABSENT:
            emit('OPENSEARCHSERVERLESS_SECURITY_POLICY_JSON',path,json_verdict(raw),'bounded JSON syntax only; policy-specific object structure, key/network semantics, whitespace service acceptance, dynamic/oversized input and actual authorization remain held')
    return results
