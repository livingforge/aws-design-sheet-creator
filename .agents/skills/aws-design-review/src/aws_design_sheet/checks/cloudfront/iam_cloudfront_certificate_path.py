"""Checks for AWS::CloudFront::Distribution."""
from ..registry import resource_check
from ..common.artifact_values import value
from ..common.context_values import CFN, _Context, linked
from ..common.field_reads import ABSENT, UNKNOWN

SOURCES = {
    'IAM_CLOUDFRONT_CERTIFICATE_PATH': [CFN + 'aws-resource-iam-servercertificate.html'],
}


@resource_check('AWS::CloudFront::Distribution')
def cloudfront_certificate(design, resource):
    ctx = _Context(design, resource)
    path = '/properties/DistributionConfig/ViewerCertificate/IamCertificateId'
    if value(ctx, resource, path) is ABSENT:
        return []
    certificate = linked(ctx, resource, path, 'AWS::IAM::ServerCertificate')
    cert_path = value(ctx, certificate, '/properties/Path') if certificate else UNKNOWN
    verdict = ('FAIL' if cert_path is ABSENT else
               ('PASS' if cert_path.startswith('/cloudfront') and cert_path.endswith('/') else 'FAIL')
               if isinstance(cert_path, str) else 'NEEDS_REVIEW')
    return [ctx.finding('IAM_CLOUDFRONT_CERTIFICATE_PATH', path, verdict,
        'explicitly linked IAM certificate for CloudFront requires a /cloudfront prefix and trailing slash')]
