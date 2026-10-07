"""Checks for AWS::S3Vectors::VectorBucket."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.kms_key_types import key_type

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'S3VECTORS_BUCKET_KEY_TYPE': [CF+'aws-properties-s3vectors-vectorbucket-encryptionconfiguration.html',CF+'aws-resource-kms-key.html',CF+'aws-resource-kms-replicakey.html'],
}


@resource_check('AWS::S3Vectors::VectorBucket')
def evaluate_s3vectors_bucket_key_type(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::S3Vectors::VectorBucket':
        path='/properties/EncryptionConfiguration/KmsKeyArn'
        if value(ctx,resource,path) is not ABSENT:
            verdict=key_type(ctx,resource,path) if value(ctx,resource,'/properties/EncryptionConfiguration/SseType')=='aws:kms' else 'NEEDS_REVIEW'
            emit('S3VECTORS_BUCKET_KEY_TYPE',path,verdict,'explicit SSE-KMS linked key must use symmetric encryption specification and encryption usage; documented KMS defaults apply, HMAC/asymmetric keys fail. Unknown specs/usages, full ARN validation, ownership and key policy remain separate')
    return results
