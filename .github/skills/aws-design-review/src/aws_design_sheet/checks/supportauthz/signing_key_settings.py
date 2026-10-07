"""Checks for AWS::SupportAuthZ::SupportPermit."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.signing_keys import signing_settings

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'SUPPORTAUTHZ_SIGNING_KEY_SETTINGS': [CF+'aws-properties-supportauthz-supportpermit-signingkeyinfo.html',CF+'aws-resource-kms-key.html',CF+'aws-resource-kms-replicakey.html'],
}


def signing_key(ctx,r,path):
    return signing_settings(ctx,r,path,('ECC_NIST_P384',))


@resource_check('AWS::SupportAuthZ::SupportPermit')
def evaluate_supportauthz_signing_key_settings(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::SupportAuthZ::SupportPermit':
        path='/properties/SigningKeyInfo/KmsKey'
        if value(ctx,resource,path) is not ABSENT:
            emit('SUPPORTAUTHZ_SIGNING_KEY_SETTINGS',path,signing_key(ctx,resource,path),'linked customer managed key requires ECC_NIST_P384 and SIGN_VERIFY; documented defaults and explicit replica primary settings are evaluated; unknown specs, aliases, key state and permissions remain held')
    return results
