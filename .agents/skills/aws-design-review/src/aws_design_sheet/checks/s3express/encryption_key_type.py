"""Checks for AWS::S3Express::DirectoryBucket."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.key_types_and_base64 import key_type
from ..common.literals import expand

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'S3EXPRESS_ENCRYPTION_KEY_TYPE': [CF+'aws-properties-s3express-directorybucket-serversideencryptionbydefault.html'],
}


@resource_check('AWS::S3Express::DirectoryBucket')
def evaluate_s3express_encryption_key_type(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::S3Express::DirectoryBucket':
        for path in expand(ctx,resource,'/properties/BucketEncryption/ServerSideEncryptionConfiguration/*/ServerSideEncryptionByDefault/KMSMasterKeyID'):
            algorithm=value(ctx,resource,path.rsplit('/',1)[0]+'/SSEAlgorithm')
            emit('S3EXPRESS_ENCRYPTION_KEY_TYPE',path,key_type(ctx,resource,path) if algorithm=='aws:kms' else 'NEEDS_REVIEW','explicit SSE-KMS linked key must have symmetric encryption specification; default/unknown spec, key ownership, aliases, cross-account ARN requirements, lifetime history and policy remain held')
    return results
