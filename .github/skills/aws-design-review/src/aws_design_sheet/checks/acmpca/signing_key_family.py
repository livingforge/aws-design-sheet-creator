"""Checks for AWS::ACMPCA::Certificate."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value

SOURCES = {
    'ACMPCA_SIGNING_KEY_FAMILY': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-acmpca-certificate.html',
    ],
}


@resource_check('AWS::ACMPCA::Certificate')
def evaluate_acmpca_signing_key_family(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(p):return value(ctx,resource,p)
    def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
    if resource.type=='AWS::ACMPCA::Certificate':
        p='/properties/SigningAlgorithm';algorithm=get(p);ca=linked(ctx,resource,'/properties/CertificateAuthorityArn','AWS::ACMPCA::CertificateAuthority');key=value(ctx,ca,'/properties/KeyAlgorithm') if ca else None
        family='RSA' if algorithm in ('SHA256WITHRSA','SHA384WITHRSA','SHA512WITHRSA') else 'EC' if algorithm in ('SHA256WITHECDSA','SHA384WITHECDSA','SHA512WITHECDSA') else None
        keyfamily='RSA' if key in ('RSA_2048','RSA_3072','RSA_4096') else 'EC' if key in ('EC_prime256v1','EC_secp384r1','EC_secp521r1') else None
        emit('ACMPCA_SIGNING_KEY_FAMILY',p,'NEEDS_REVIEW' if family is None or keyfamily is None else 'PASS' if family==keyfamily else 'FAIL','compares documented RSA/ECDSA families with explicit linked CA key algorithm; SM2/ML-DSA, future algorithms, CSR and external CA state held')
    return results
