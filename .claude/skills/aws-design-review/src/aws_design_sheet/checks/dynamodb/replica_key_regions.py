"""Replica facts available without querying live DynamoDB or KMS."""
import re
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

SOURCES = {'DYNAMODB_REPLICA_KMS_REGION': [
    'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-dynamodb-globaltable-replicassespecification.html',
]}


def replica_key_regions(design, resource):
    if resource.type != 'AWS::DynamoDB::GlobalTable':
        return []
    ctx = _Context(design, resource)
    replicas = value(ctx, resource, '/properties/Replicas')
    if replicas is ABSENT:
        return []
    if not isinstance(replicas, list):
        return [ctx.finding('DYNAMODB_REPLICA_KMS_REGION', '/properties/Replicas',
            'NEEDS_REVIEW', 'replicas are unresolved')]
    results = []
    for i in range(len(replicas)):
        base = f'/properties/Replicas/{i}'
        path = base + '/SSESpecification/KMSMasterKeyId'
        key = value(ctx, resource, path)
        if key is ABSENT:
            continue
        region = value(ctx, resource, base + '/Region')
        match = re.fullmatch(r'arn:[a-z0-9-]+:kms:([a-z0-9-]+):\d{12}:(?:key|alias)/[^{}\s]+', key) if isinstance(key, str) else None
        verdict = 'NEEDS_REVIEW'
        if match and isinstance(region, str) and re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-\d+', region):
            verdict = 'PASS' if match[1] == region else 'FAIL'
        results.append(ctx.finding('DYNAMODB_REPLICA_KMS_REGION', path, verdict,
            'literal KMS key/alias ARNs must name the replica region; key existence, status, ownership and bare IDs still require review'))
    return results
