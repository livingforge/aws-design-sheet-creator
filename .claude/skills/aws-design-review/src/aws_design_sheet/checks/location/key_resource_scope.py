"""Checks for AWS::Location::APIKey."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'LOCATION_KEY_RESOURCE_SCOPE': [CF+'aws-properties-location-apikey-apikeyrestrictions.html'],
}


def resource_scope(ctx,resource,path):
    raw=value(ctx,resource,path)
    if resource.template is not None and resource.template.state.value!='KNOWN':return 'NEEDS_REVIEW'
    if not literal(raw) or not re.fullmatch(r'[0-9]{12}',resource.scope.account) or not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-[0-9]+',resource.scope.region):return 'NEEDS_REVIEW'
    match=re.fullmatch(r'arn:(aws|aws-cn|aws-us-gov):geo:([a-z]{2}(?:-[a-z]+)+-[0-9]+):([0-9]{12}):(map|place-index|route-calculator)/[A-Za-z0-9_.?*\-]+',raw)
    if not match:return 'NEEDS_REVIEW'
    return 'PASS' if (match[2],match[3])==(resource.scope.region,resource.scope.account) else 'FAIL'


@resource_check('AWS::Location::APIKey')
def evaluate_location_key_resource_scope(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::Location::APIKey':
        for path in expand(ctx,resource,'/properties/Restrictions/AllowResources/*'):
            emit('LOCATION_KEY_RESOURCE_SCOPE',path,resource_scope(ctx,resource,path),'literal legacy geo map/place-index/route-calculator ARN must match the key account and Region; partition, enhanced APIs, unknown/dynamic identities, existence and permissions remain held')
    return results
