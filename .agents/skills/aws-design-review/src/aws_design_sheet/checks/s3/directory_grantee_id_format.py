"""Checks for AWS::S3::AccessGrant."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT, UNKNOWN

SOURCES = {
    'S3_DIRECTORY_GRANTEE_ID_FORMAT': [
        'https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_Grantee.html',
        'https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_DescribeUser.html',
        'https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_DescribeGroup.html'],
}
DIRECTORY_ID = re.compile(r'(?:[0-9a-f]{10}-)?[A-Fa-f0-9]{8}(?:-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12}')


def _unresolved(v):
    return v is UNKNOWN or (isinstance(v, str) and '{{resolve:' in v)


@resource_check('AWS::S3::AccessGrant')
def evaluate_s3_directory_grantee_id(design, resource):
    ctx = _Context(design, resource)
    kind = value(ctx, resource, '/properties/Grantee/GranteeType')
    path = '/properties/Grantee/GranteeIdentifier'
    identifier = value(ctx, resource, path)
    if kind == 'IAM' or (kind is ABSENT and identifier is ABSENT):
        return []
    if kind not in ('DIRECTORY_USER', 'DIRECTORY_GROUP') or not isinstance(identifier, str) or _unresolved(identifier):
        verdict = 'NEEDS_REVIEW'
    else:
        verdict = 'PASS' if DIRECTORY_ID.fullmatch(identifier) else 'FAIL'
    return [{**ctx.finding('S3_DIRECTORY_GRANTEE_ID_FORMAT', path, verdict,
        'compares directory user/group IDs with the Identity Store API pattern, including its optional 10-hex prefix; S3 acceptance and identity existence require separate confirmation'),
        'severity': 'WARNING'}]
