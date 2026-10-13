"""Checks for AWS::SNS::Topic."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.scope import symmetric_key_verdict

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'SNS_ENCRYPTION_KEY_TYPE': ['https://docs.aws.amazon.com/sns/latest/dg/sns-key-management.html', CF + 'aws-resource-kms-key.html'],
}


@resource_check('AWS::SNS::Topic')
def sns_encryption_key_type(design, resource):
    ctx = _Context(design, resource)
    path = '/properties/KmsMasterKeyId'
    if value(ctx, resource, path) is ABSENT:
        return []
    key = linked(ctx, resource, path, 'AWS::KMS::Key')
    return [ctx.finding('SNS_ENCRYPTION_KEY_TYPE', path, symmetric_key_verdict(ctx, key),
        'SNS requires a symmetric encryption key; only linked KeySpec/KeyUsage declarations are checked, not permissions or runtime key state')]
