"""Checks for AWS::LicenseManager::License."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.signing_keys import signing_settings

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'LICENSEMANAGER_ISSUER_SIGNING_KEY': [CF+'aws-properties-licensemanager-license-issuerdata.html','https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose-key-spec.html',CF+'aws-resource-kms-key.html',CF+'aws-resource-kms-replicakey.html'],
}
RSA=('RSA_2048','RSA_3072','RSA_4096')


def signing_key(ctx,resource,path):
    return signing_settings(ctx,resource,path,RSA)


@resource_check('AWS::LicenseManager::License')
def evaluate_licensemanager_issuer_signing_key(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::LicenseManager::License':
        path='/properties/Issuer/SignKey'
        if value(ctx,resource,path) is not ABSENT:
            emit('LICENSEMANAGER_ISSUER_SIGNING_KEY',path,signing_key(ctx,resource,path),'linked key must use SIGN_VERIFY and RSA supporting RSASSA_PSS_SHA_256; documented defaults and explicit replica primary settings are evaluated; unknown configuration, external keys, state and permissions remain held')
    return results
