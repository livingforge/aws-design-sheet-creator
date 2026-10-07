"""Checks for AWS::Kendra::Index."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.key_types_and_base64 import key_type

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'KENDRA_INDEX_KMS_KEY_TYPE': [CF+'aws-properties-kendra-index-serversideencryptionconfiguration.html',CF+'aws-resource-kms-key.html'],
}


def _emitter(ctx,results):
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    return emit


@resource_check('AWS::Kendra::Index')
def evaluate_kendra_index_kms_key_type(design,resource):
    ctx=_Context(design,resource)
    results=[]
    emit=_emitter(ctx,results)
    path='/properties/ServerSideEncryptionConfiguration/KmsKeyId'
    if value(ctx,resource,path) is not ABSENT:
        emit('KENDRA_INDEX_KMS_KEY_TYPE',path,key_type(ctx,resource,path),'uniquely linked key with explicit recognized asymmetric KeySpec is unsupported; omitted spec, HMAC/unknown types, aliases, external keys, permissions and key state remain held')
    return results
