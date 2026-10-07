"""EKS design-local collisions and declared cluster version consistency."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, UNKNOWN

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'EKS_ACCESS_PRINCIPAL_DUPLICATE': [CF + 'aws-resource-eks-accessentry.html'],
    'EKS_CAPABILITY_NAME_DUPLICATE': [CF + 'aws-resource-eks-capability.html'],
    'EKS_CERTIFICATE_AUTHORITY_COUNT': [CF + 'aws-resource-eks-certificateauthority.html'],
    'EKS_NODEGROUP_CLUSTER_VERSION': [CF + 'aws-resource-eks-nodegroup.html'],
    'EKS_CLUSTER_NAME_DUPLICATE': [CF + 'aws-resource-eks-cluster.html'],
}


def cluster_identity(ctx, resource):
    cluster = linked(ctx, resource, '/properties/ClusterName', 'AWS::EKS::Cluster')
    if cluster:
        return ('resource', cluster.id)
    name = value(ctx, resource, '/properties/ClusterName')
    if isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]*', name):
        return ('name', name)
    return None


def item_identity(ctx, resource, path):
    if path is None:
        return ('resource', resource.id)
    if path == '/properties/PrincipalArn':
        for kind in ('AWS::IAM::Role', 'AWS::IAM::User'):
            principal = linked(ctx, resource, path, kind)
            if principal:
                return ('resource', principal.id)
        raw = value(ctx, resource, path)
        if isinstance(raw, str) and re.fullmatch(r'arn:[a-z0-9-]+:iam::\d{12}:(?:role|user)/[^{}\s]+', raw):
            return ('arn', raw)
    else:
        raw = value(ctx, resource, path)
        if isinstance(raw, str) and raw and '{{' not in raw:
            return ('name', raw)
    return None


@resource_check(
    'AWS::EKS::AccessEntry',
    'AWS::EKS::Cluster',
    'AWS::EKS::Capability',
    'AWS::EKS::CertificateAuthority',
    'AWS::EKS::Nodegroup',
)
def eks_links(design, resource):
    ctx = _Context(design, resource)
    if resource.type == 'AWS::EKS::Cluster':
        name = value(ctx, resource, '/properties/Name')
        known = (isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,99}', name)
                 and re.fullmatch(r'[0-9]{12}', resource.scope.account)
                 and re.fullmatch(r'[a-z]+(?:-[a-z]+)+-[0-9]+', resource.scope.region))
        duplicates = [other.id for other in design.resources if known and other.type == resource.type
                      and other.id != resource.id and other.scope == resource.scope
                      and value(ctx, other, '/properties/Name') == name]
        return [ctx.finding('EKS_CLUSTER_NAME_DUPLICATE', '/properties/Name',
            'FAIL' if duplicates else 'NEEDS_REVIEW',
            'cluster names must be unique per account/Region; checks distinct same-scope design declarations only, not external clusters or unresolved names')]
    if resource.type == 'AWS::EKS::Nodegroup':
        version = value(ctx, resource, '/properties/Version')
        if version is ABSENT:
            return []
        cluster = linked(ctx, resource, '/properties/ClusterName', 'AWS::EKS::Cluster')
        cluster_version = value(ctx, cluster, '/properties/Version') if cluster else UNKNOWN
        known = all(isinstance(v, str) and re.fullmatch(r'\d+\.\d+', v) for v in (version, cluster_version))
        verdict = ('PASS' if version == cluster_version else 'FAIL') if known else 'NEEDS_REVIEW'
        return [{**ctx.finding('EKS_NODEGROUP_CLUSTER_VERSION', '/properties/Version', verdict,
            'declared node-group creation version must match the linked cluster version; existing cluster state and update sequencing remain external'),
            'severity': 'WARNING'}]
    rule, path, limit = {
        'AWS::EKS::AccessEntry': ('EKS_ACCESS_PRINCIPAL_DUPLICATE', '/properties/PrincipalArn', 1),
        'AWS::EKS::Capability': ('EKS_CAPABILITY_NAME_DUPLICATE', '/properties/CapabilityName', 1),
        'AWS::EKS::CertificateAuthority': ('EKS_CERTIFICATE_AUTHORITY_COUNT', None, 2),
    }[resource.type]
    cluster_id = cluster_identity(ctx, resource)
    identity = item_identity(ctx, resource, path)
    matches = []
    if cluster_id and identity:
        for other in design.resources:
            if other.type != resource.type or other.scope != resource.scope:
                continue
            other_ctx = _Context(design, other)
            if cluster_identity(other_ctx, other) != cluster_id:
                continue
            other_id = item_identity(other_ctx, other, path)
            if other_id and (path is None or other_id == identity):
                matches.append(other.id)
                ctx.evidence.extend(other_ctx.evidence)
    return [ctx.finding(rule, path or '/properties/ClusterName',
        'FAIL' if len(matches) > limit else 'NEEDS_REVIEW',
        'design resources exceed the per-cluster uniqueness/count limit: ' + ', '.join(matches)
        if len(matches) > limit else 'no proven design collision; external resources, mixed aliases and unresolved references still require review')]
