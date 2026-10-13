"""Cluster storage and namespace facts available without AWS API access."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, UNKNOWN

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'ECS_CLUSTER_STORAGE_SINGLE_REGION': [CF + 'aws-properties-ecs-cluster-managedstorageconfiguration.html', CF + 'aws-resource-kms-key.html'],
    'ECS_CLUSTER_NAMESPACE_NAME': [CF + 'aws-properties-ecs-cluster-serviceconnectdefaults.html'],
    'ECS_CLUSTER_NAMESPACE_SCOPE': [CF + 'aws-properties-ecs-cluster-serviceconnectdefaults.html'],
}


@resource_check('AWS::ECS::Cluster')
def cluster_links(design, resource):
    ctx = _Context(design, resource)
    results = []
    for field in ('KmsKeyId', 'FargateEphemeralStorageKmsKeyId'):
        path = '/properties/Configuration/ManagedStorageConfiguration/' + field
        if value(ctx, resource, path) is ABSENT:
            continue
        key = linked(ctx, resource, path, 'AWS::KMS::Key')
        multi = value(ctx, key, '/properties/MultiRegion') if key else UNKNOWN
        verdict = 'FAIL' if multi is True else 'PASS' if multi is False or multi is ABSENT else 'NEEDS_REVIEW'
        results.append(ctx.finding('ECS_CLUSTER_STORAGE_SINGLE_REGION', path, verdict,
            'managed storage requires a single-Region key; this checks the linked key declaration, not permissions or existing state'))
    path = '/properties/ServiceConnectDefaults/Namespace'
    namespace = value(ctx, resource, path)
    if namespace is ABSENT:
        return results
    match = re.fullmatch(r'arn:[a-z0-9-]+:servicediscovery:([a-z0-9-]+):(\d{12}):namespace/[A-Za-z0-9-]+', namespace) if isinstance(namespace, str) else None
    if match:
        region, account = match.groups()
        comparisons = [region == resource.scope.region if re.fullmatch(r'[a-z]+(?:-[a-z]+)+-\d+', resource.scope.region) else None,
                       account == resource.scope.account if re.fullmatch(r'\d{12}', resource.scope.account) else None]
        verdict = 'FAIL' if False in comparisons else 'NEEDS_REVIEW' if None in comparisons else 'PASS'
        results.append(ctx.finding('ECS_CLUSTER_NAMESPACE_SCOPE', path, verdict,
            'namespace ARN must identify this account and Region; namespace existence remains external'))
    else:
        verdict = 'NEEDS_REVIEW'
        if isinstance(namespace, str) and '{{' not in namespace and not namespace.startswith('arn:'):
            verdict = 'FAIL' if any(c in namespace for c in '><"/') or len(namespace) > 1024 else 'PASS'
        results.append(ctx.finding('ECS_CLUSTER_NAMESPACE_NAME', path, verdict,
            'namespace names allow at most 1024 characters and exclude >, <, double quotes and slash; ARN syntax is handled separately'))
    return results
