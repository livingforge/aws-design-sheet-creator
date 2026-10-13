"""Checks for AWS::DynamoDB::GlobalTable, AWS::DynamoDB::Table."""
from __future__ import annotations

from ..registry import resource_check
from ..common.design_uniqueness import _Context
from ..common.field_reads import ABSENT, read


SOURCES = {
    "DYNAMODB_INDEX_PROJECTION_AGGREGATE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-dynamodb-globaltable-projection.html"],
    "DYNAMODB_GLOBAL_TABLE_DEPLOYMENT_REGION": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-dynamodb-globaltable.html#cfn-dynamodb-globaltable-replicas"],
    "DYNAMODB_GLOBAL_TABLE_WITNESS_REGION": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-dynamodb-globaltable-globaltablewitness.html"],
}


@resource_check('AWS::DynamoDB::Table', 'AWS::DynamoDB::GlobalTable')
def dynamodb_projection(design, resource):
    ctx = _Context(design, resource)
    count = 0
    pending = False
    found = False
    for name in ('GlobalSecondaryIndexes', 'LocalSecondaryIndexes'):
        path = '/properties/' + name
        indexes = read(ctx, resource, path)
        if indexes is ABSENT:
            continue
        found = True
        if not isinstance(indexes, list):
            pending = True
            continue
        for i in range(len(indexes)):
            kind = read(ctx, resource, path + f'/{i}/Projection/ProjectionType')
            values = read(ctx, resource, path + f'/{i}/Projection/NonKeyAttributes')
            if kind == 'INCLUDE' and isinstance(values, list):
                count += len(values)  # The same attribute in separate indexes counts twice.
            elif kind not in ('KEYS_ONLY', 'ALL'):
                pending = True
    verdict = ('NOT_APPLICABLE' if not found else 'FAIL' if count > 100 else
               'NEEDS_REVIEW' if pending else 'PASS')
    return ctx.finding('DYNAMODB_INDEX_PROJECTION_AGGREGATE', '/properties/GlobalSecondaryIndexes', verdict,
                       'INCLUDE projections across all indexes must total at most 100 attributes')


@resource_check('AWS::DynamoDB::GlobalTable')
def dynamodb_regions(design, resource):
    ctx = _Context(design, resource)
    replicas = read(ctx, resource, '/properties/Replicas')
    known = []
    pending = not isinstance(replicas, list)
    for i in range(len(replicas) if isinstance(replicas, list) else 0):
        region = read(ctx, resource, f'/properties/Replicas/{i}/Region')
        if isinstance(region, str):
            known.append(region)
        else:
            pending = True
    verdict = ('PASS' if resource.scope.region in known else 'NEEDS_REVIEW' if pending else 'FAIL')
    results = [ctx.finding('DYNAMODB_GLOBAL_TABLE_DEPLOYMENT_REGION', '/properties/Replicas', verdict,
                           'replicas must include the deployment Region')]
    witnesses = read(ctx, resource, '/properties/GlobalTableWitnesses')
    if isinstance(witnesses, list):
        for i in range(len(witnesses)):
            region = read(ctx, resource, f'/properties/GlobalTableWitnesses/{i}/Region')
            verdict = ('FAIL' if isinstance(region, str) and region in known else
                       'NEEDS_REVIEW' if not isinstance(region, str) or pending else 'PASS')
            results.append(ctx.finding('DYNAMODB_GLOBAL_TABLE_WITNESS_REGION',
                                      f'/properties/GlobalTableWitnesses/{i}/Region', verdict,
                                      'witness Region must differ from every replica Region'))
    return results
