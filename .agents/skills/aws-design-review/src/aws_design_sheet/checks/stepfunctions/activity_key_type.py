"""Checks for AWS::StepFunctions::Activity."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.key_types_and_base64 import key_type

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'STEPFUNCTIONS_ACTIVITY_KEY_TYPE': [CF+'aws-properties-stepfunctions-activity-encryptionconfiguration.html'],
}


@resource_check('AWS::StepFunctions::Activity')
def evaluate_stepfunctions_activity_key_type(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::StepFunctions::Activity':
        path='/properties/EncryptionConfiguration/KmsKeyId'
        if value(ctx,resource,path) is not ABSENT:
            mode=value(ctx,resource,'/properties/EncryptionConfiguration/Type')
            emit('STEPFUNCTIONS_ACTIVITY_KEY_TYPE',path,key_type(ctx,resource,path) if mode=='CUSTOMER_MANAGED_KMS_KEY' else 'NEEDS_REVIEW','explicit customer-managed encryption uses a linked symmetric key; unknown/default/HMAC specs, aliases, ownership/ARN requirements and permissions remain held')
    return results
