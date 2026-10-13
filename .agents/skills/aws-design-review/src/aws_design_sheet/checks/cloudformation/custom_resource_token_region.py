"""Checks for AWS::CloudFormation::CustomResource."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CUSTOM_RESOURCE_TOKEN_REGION': [CF+'aws-resource-cloudformation-customresource.html'],
}


@resource_check('AWS::CloudFormation::CustomResource')
def evaluate_cloudformation_custom_resource_token_region(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(p):return value(ctx,resource,p)
    def emit(rule,p,v,reason):
        result=ctx.finding(rule,p,v,reason);result['source_checked_at']='2026-10-04';results.append(result)
    def enum(rule,p,allowed):
        raw=get(p)
        if raw is not ABSENT:emit(rule,p,'NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in allowed else 'FAIL','literal value checked against current explicit CF allowed values; no omitted values inferred')
    if resource.type=='AWS::CloudFormation::CustomResource':
        p='/properties/ServiceToken';raw=get(p);v='NEEDS_REVIEW'
        match=re.fullmatch(r'arn:aws[-a-z]*:(?:sns|lambda):([a-z0-9-]+):[0-9]{12}:[^\s]+',raw) if literal(raw) else None
        if match and re.fullmatch(r'[a-z]+(?:-[a-z]+)+-[0-9]+',resource.scope.region):v='PASS' if match[1]==resource.scope.region else 'FAIL'
        emit('CUSTOM_RESOURCE_TOKEN_REGION',p,v,'recognized literal SNS/Lambda token region matches deployment region; unresolved targets, external permissions and response handling held')
    return results
