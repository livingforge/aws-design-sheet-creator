"""Checks for AWS::Synthetics::Canary."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'SYNTHETICS_ARTIFACT_ENCRYPTION_MODE': [CF+'aws-properties-synthetics-canary-s3encryption.html','https://docs.aws.amazon.com/AmazonSynthetics/latest/APIReference/API_S3EncryptionConfig.html'],
}


@resource_check('AWS::Synthetics::Canary')
def evaluate_synthetics_artifact_encryption_mode(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::Synthetics::Canary':
        path='/properties/ArtifactConfig/S3Encryption/EncryptionMode';raw=value(ctx,resource,path)
        if raw is not ABSENT:
            verdict='NEEDS_REVIEW' if not literal(raw) or raw=='SSE-KMS' else 'PASS' if raw in ('SSE_S3','SSE_KMS') else 'FAIL'
            emit('SYNTHETICS_ARTIFACT_ENCRYPTION_MODE',path,verdict,'explicit API enum only; hyphenated SSE-KMS prose conflict, defaults, runtime applicability, key requirements and artifact permissions remain held')
    return results
