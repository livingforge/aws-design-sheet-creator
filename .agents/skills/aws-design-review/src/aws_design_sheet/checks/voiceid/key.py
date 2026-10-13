"""Voice ID encryption key kind, independent of service lifecycle availability."""
from ..registry import resource_check
from ..common.context_values import _Context
from ..common.field_reads import ABSENT, read
from ..common.kms_key_types import key_type

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'VOICEID_SYMMETRIC_ENCRYPTION_KEY':[CF+'aws-properties-voiceid-domain-serversideencryptionconfiguration.html',CF+'aws-resource-kms-key.html',CF+'aws-resource-kms-replicakey.html']}


@resource_check('AWS::VoiceID::Domain')
def evaluate_voiceid_key(design,resource):
    if resource.type!='AWS::VoiceID::Domain':return []
    ctx=_Context(design,resource);path='/properties/ServerSideEncryptionConfiguration/KmsKeyId'
    verdict=key_type(ctx,resource,path,allow_alias=True) if read(ctx,resource,path) is ABSENT else 'NEEDS_REVIEW'
    f=ctx.finding('VOICEID_SYMMETRIC_ENCRYPTION_KEY',path,verdict,'Explicit customer managed KMS key must be a symmetric encryption key; asymmetric, HMAC and signing-only keys cannot encrypt Voice ID data. Documented KeySpec/KeyUsage defaults and resolved alias/replica links are supported. Literal physical IDs, unknown key metadata, permissions, key state and service lifecycle remain reviewable. PASS does not imply service availability.')
    f['source_checked_at']='2026-10-04';return [f]
