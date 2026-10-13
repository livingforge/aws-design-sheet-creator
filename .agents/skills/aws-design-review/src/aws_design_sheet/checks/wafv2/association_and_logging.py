"""Checks for AWS::WAFv2::LoggingConfiguration, AWS::WAFv2::WebACLAssociation."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'WAFV2_ASSOCIATION_ACL_SCOPE': [CF+'aws-resource-wafv2-webaclassociation.html',CF+'aws-resource-wafv2-webacl.html'],
    'WAFV2_LINKED_LOG_NAME_PREFIX': [CF+'aws-resource-wafv2-loggingconfiguration.html'],
}


def acl_scope(ctx,r):
    acl=linked(ctx,r,'/properties/WebACLArn','AWS::WAFv2::WebACL')
    if not resolved(r) or not resolved(acl):return 'NEEDS_REVIEW'
    scope=value(ctx,acl,'/properties/Scope')
    return 'PASS' if scope=='REGIONAL' else 'FAIL' if scope=='CLOUDFRONT' else 'NEEDS_REVIEW'


def log_name(ctx,r,path):
    if not resolved(r):return 'NEEDS_REVIEW'
    for kind,key in (('AWS::Logs::LogGroup','LogGroupName'),('AWS::S3::Bucket','BucketName'),('AWS::KinesisFirehose::DeliveryStream','DeliveryStreamName')):
        destination=linked(ctx,r,path,kind)
        if not resolved(destination):continue
        name=value(ctx,destination,'/properties/'+key)
        if not literal(name):return 'NEEDS_REVIEW'
        return 'PASS' if name.startswith('aws-waf-logs-') else 'FAIL'
    return 'NEEDS_REVIEW'


@resource_check('AWS::WAFv2::WebACLAssociation', 'AWS::WAFv2::LoggingConfiguration')
def evaluate_wafv2_association_and_logging(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::WAFv2::WebACLAssociation' and value(ctx,resource,'/properties/WebACLArn') is not ABSENT:
        emit('WAFV2_ASSOCIATION_ACL_SCOPE','/properties/WebACLArn',acl_scope(ctx,resource),'uniquely linked web ACL requires explicit REGIONAL scope; unknown/external/conditional links, protected-resource Region/type, permissions and propagation remain held')
    if resource.type=='AWS::WAFv2::LoggingConfiguration':
        for path in expand(ctx,resource,'/properties/LogDestinationConfigs/*'):
            emit('WAFV2_LINKED_LOG_NAME_PREFIX',path,log_name(ctx,resource,path),'uniquely linked destination explicit name must start with aws-waf-logs-; generated/unknown names, external/conditional links, cross-scope destinations and effective permissions remain held')
    return results
