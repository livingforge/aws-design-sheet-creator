"""Checks for AWS::RDS::DBSecurityGroup, AWS::RDS::DBSecurityGroupIngress."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT, UNKNOWN

SOURCES = {
    'RDS_SECURITY_GROUP_AUTHORIZATION_SOURCE': [
        'https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_AuthorizeDBSecurityGroupIngress.html'],
}


def _unresolved(v):
    return v is UNKNOWN or (isinstance(v, str) and '{{resolve:' in v)


@resource_check('AWS::RDS::DBSecurityGroupIngress', 'AWS::RDS::DBSecurityGroup')
def evaluate_rds_security_group_authorization_source(design, resource):
    ctx = _Context(design, resource)
    prefixes = ['/properties/']
    if resource.type.endswith('::DBSecurityGroup'):
        entries = value(ctx, resource, '/properties/DBSecurityGroupIngress')
        if not isinstance(entries, list):
            return []  # Collection shape/presence belongs to the schema.
        prefixes = [f'/properties/DBSecurityGroupIngress/{i}/' for i in range(len(entries))]
    rows = []
    for prefix in prefixes:
        local = _Context(design, resource)
        values = [value(local, resource, prefix + key) for key in ('CIDRIP', 'EC2SecurityGroupId', 'EC2SecurityGroupName')]
        if all(v is ABSENT for v in values):
            verdict = 'FAIL'
        elif any(isinstance(v, str) and v and not _unresolved(v) for v in values):
            verdict = 'PASS'
        else:
            verdict = 'NEEDS_REVIEW'
        rows.append(local.finding('RDS_SECURITY_GROUP_AUTHORIZATION_SOURCE', prefix.rstrip('/'), verdict,
            'at least one CIDR or EC2 security-group identifier/name is required; this check does not assert exclusivity or validate VPC-specific owner fields'))
    return rows
