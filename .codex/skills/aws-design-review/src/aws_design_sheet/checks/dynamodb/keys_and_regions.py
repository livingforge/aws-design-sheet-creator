"""Checks for AWS::DynamoDB::GlobalTable, AWS::DynamoDB::Table."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from .replica_key_regions import replica_key_regions

SOURCES = {
    'DYNAMODB_KEY_ATTRIBUTE_DEFINED': ['https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_CreateTable.html'],
    'DYNAMODB_INDEX_NAMES_COMBINED': ['https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_CreateTable.html'],
    'DYNAMODB_MRSC_REGION_SET': ['https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/V2globaltables_HowItWorks.html'],
}


@resource_check('AWS::DynamoDB::Table', 'AWS::DynamoDB::GlobalTable')
def dynamodb_keys(design, resource):
    ctx = _Context(design, resource)
    base = '/properties/'
    definitions = value(ctx, resource, base + 'AttributeDefinitions')
    names, pending = set(), not isinstance(definitions, list)
    for i in range(len(definitions) if isinstance(definitions, list) else 0):
        name = value(ctx, resource, base + f'AttributeDefinitions/{i}/AttributeName')
        if isinstance(name, str):
            names.add(name)
        else:
            pending = True
    paths = [base + 'KeySchema']
    groups = []
    for kind in ('GlobalSecondaryIndexes', 'LocalSecondaryIndexes'):
        items = value(ctx, resource, base + kind)
        ids = []
        unresolved = items is not ABSENT and not isinstance(items, list)
        for i in range(len(items) if isinstance(items, list) else 0):
            path = base + kind + f'/{i}'
            paths.append(path + '/KeySchema')
            name = value(ctx, resource, path + '/IndexName')
            if isinstance(name, str):
                ids.append(name)
            else:
                unresolved = True
        groups.append((ids, unresolved))
    results = replica_key_regions(design, resource)
    for path in paths:
        keys = value(ctx, resource, path)
        if keys is ABSENT:
            continue
        bad, unknown = False, pending or not isinstance(keys, list)
        for i in range(len(keys) if isinstance(keys, list) else 0):
            name = value(ctx, resource, path + f'/{i}/AttributeName')
            if isinstance(name, str) and name not in names and not pending:
                bad = True
            elif not isinstance(name, str):
                unknown = True
        results.append(ctx.finding('DYNAMODB_KEY_ATTRIBUTE_DEFINED', path,
            'FAIL' if bad else 'NEEDS_REVIEW' if unknown else 'PASS',
            'table and index key attributes must be present in AttributeDefinitions'))
    duplicate = set(groups[0][0]) & set(groups[1][0])
    results.append(ctx.finding('DYNAMODB_INDEX_NAMES_COMBINED', base + 'GlobalSecondaryIndexes',
        'FAIL' if duplicate else 'NEEDS_REVIEW' if any(g[1] for g in groups) else 'PASS',
        'local and global secondary indexes must not share an index name'))
    if resource.type == 'AWS::DynamoDB::GlobalTable' and value(ctx, resource, base + 'MultiRegionConsistency') == 'STRONG':
        sets = ({'us-east-1', 'us-east-2', 'us-west-2'}, {'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1'},
                {'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3'})
        locations, unknown = set(), False
        for kind in ('Replicas', 'GlobalTableWitnesses'):
            items = value(ctx, resource, base + kind)
            if items is ABSENT:
                continue
            if not isinstance(items, list):
                unknown = True
                continue
            for i in range(len(items)):
                region = value(ctx, resource, base + kind + f'/{i}/Region')
                group = next((j for j, regions in enumerate(sets) if isinstance(region, str) and region in regions), None)
                if group is None:
                    unknown = True
                else:
                    locations.add(group)
        verdict = 'FAIL' if len(locations) > 1 else 'NEEDS_REVIEW' if unknown or not locations else 'PASS'
        results.append(ctx.finding('DYNAMODB_MRSC_REGION_SET', base + 'Replicas', verdict,
            'MRSC replicas and witnesses must not cross documented region sets; unlisted regions require review'))
    return results
