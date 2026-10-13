"""Checks for AWS::KinesisFirehose::DeliveryStream."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.key_types_and_base64 import key_type
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'FIREHOSE_CUSTOMER_KEY_TYPE': [CF+'aws-properties-kinesisfirehose-deliverystream-deliverystreamencryptionconfigurationinput.html',CF+'aws-resource-kms-key.html'],
    'FIREHOSE_GLUE_ROLE_ACCOUNT': [CF+'aws-properties-kinesisfirehose-deliverystream-schemaconfiguration.html'],
}
CONVERSION='/properties/ExtendedS3DestinationConfiguration/DataFormatConversionConfiguration'


def role_account(ctx,resource,path):
    if resource.template is not None and resource.template.state.value!='KNOWN':return 'NEEDS_REVIEW'
    if value(ctx,resource,CONVERSION+'/Enabled') is not True:return 'NEEDS_REVIEW'
    raw=value(ctx,resource,path)
    if not literal(raw) or not re.fullmatch(r'\d{12}',resource.scope.account):return 'NEEDS_REVIEW'
    match=re.fullmatch(r'arn:(aws|aws-cn|aws-us-gov):iam::(\d{12}):role/[A-Za-z0-9_+=,.@/\-]+',raw)
    if not match:return 'NEEDS_REVIEW'
    return 'PASS' if match[2]==resource.scope.account else 'FAIL'


@resource_check('AWS::KinesisFirehose::DeliveryStream')
def evaluate_kinesisfirehose_delivery_stream(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::KinesisFirehose::DeliveryStream':
        base='/properties/DeliveryStreamEncryptionConfigurationInput'
        path=base+'/KeyARN'
        if value(ctx,resource,path) is not ABSENT:
            verdict=key_type(ctx,resource,path) if value(ctx,resource,base+'/KeyType')=='CUSTOMER_MANAGED_CMK' else 'NEEDS_REVIEW'
            emit('FIREHOSE_CUSTOMER_KEY_TYPE',path,verdict,'explicit customer-managed encryption requires a symmetric key; omitted/unknown specs, external keys, key permissions/state, AWS-owned key exclusivity and stream quota remain held')
        path=CONVERSION+'/SchemaConfiguration/RoleARN'
        if value(ctx,resource,path) is not ABSENT:
            emit('FIREHOSE_GLUE_ROLE_ACCOUNT',path,role_account(ctx,resource,path),'with conversion explicitly enabled, a literal Glue schema role ARN must belong to the stream account; unknown/default activation, unresolved roles, permissions and other destination identity constraints remain held')
    return results
