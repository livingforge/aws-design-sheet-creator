"""Checks for AWS::EC2::IPAMPool."""
from ..registry import resource_check
from ..common.artifact_values import value
from ..common.context_values import CFN, _Context, linked
from ..common.field_reads import ABSENT

SOURCES = {
    'EC2_IPAM_PUBLIC_SOURCE_SCOPE': [CFN + 'aws-resource-ec2-ipampool.html',
        'https://docs.aws.amazon.com/vpc/latest/ipam/add-scope-ipam.html'],
}


@resource_check('AWS::EC2::IPAMPool')
def ipam_scope(design, resource):
    ctx = _Context(design, resource)
    path = '/properties/PublicIpSource'
    source = value(ctx, resource, path)
    if source is ABSENT:
        return []
    scope = linked(ctx, resource, '/properties/IpamScopeId', 'AWS::EC2::IPAMScope')
    # Additional scopes created as IPAMScope resources are private. Default
    # public/private scopes on IPAM cannot be distinguished by current relations.
    verdict = 'FAIL' if scope and isinstance(source, str) else 'NEEDS_REVIEW'
    return [{**ctx.finding('EC2_IPAM_PUBLIC_SOURCE_SCOPE', path, verdict,
        'PublicIpSource is used only in a public scope; explicitly created IPAMScope is private; external/default scopes require review'),
        'severity': 'WARNING'}]
