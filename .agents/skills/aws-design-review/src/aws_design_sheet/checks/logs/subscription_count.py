"""Declared subscription-filter counts, without querying existing AWS filters."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value

SOURCES = {'LOGS_SUBSCRIPTION_FILTER_COUNT': [
    'https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutSubscriptionFilter.html']}
SOURCES['LOGS_DIRECT_DESTINATION_ACCOUNT'] = SOURCES['LOGS_SUBSCRIPTION_FILTER_COUNT']


def group_identity(ctx, resource):
    group = linked(ctx, resource, '/properties/LogGroupName', 'AWS::Logs::LogGroup')
    if group:
        return ('resource', group.id)
    name = value(ctx, resource, '/properties/LogGroupName')
    if isinstance(name, str) and re.fullmatch(r'[.\-_/#A-Za-z0-9]{1,512}', name):
        return ('name', name)
    return None


@resource_check('AWS::Logs::SubscriptionFilter')
def subscription_count(design, resource):
    ctx = _Context(design, resource)
    identity = group_identity(ctx, resource)
    names = set()
    known_scope = (re.fullmatch(r'[0-9]{12}', resource.scope.account)
                   and re.fullmatch(r'[a-z]+(?:-[a-z]+)+-[0-9]+', resource.scope.region))
    if identity and known_scope:
        for other in design.resources:
            if other.type != resource.type or other.scope != resource.scope:
                continue
            if group_identity(ctx, other) != identity:
                continue
            name = value(ctx, other, '/properties/FilterName')
            if isinstance(name, str) and 1 <= len(name) <= 512 and not any(c in name for c in ':*${}'):
                names.add(name)
    results = [ctx.finding('LOGS_SUBSCRIPTION_FILTER_COUNT', '/properties/LogGroupName',
        'FAIL' if len(names) > 2 else 'NEEDS_REVIEW',
        'a log group supports at most two subscription filters; counts distinct explicit filter names for one same-scope literal or linked group, not external filters, generated names or mixed aliases')]
    path = '/properties/DestinationArn'
    raw = value(ctx, resource, path)
    verdict = 'NEEDS_REVIEW'
    if isinstance(raw, str) and re.fullmatch(r'[0-9]{12}', resource.scope.account):
        match = re.fullmatch(r'arn:(aws|aws-cn|aws-us-gov):(kinesis|firehose|lambda):[a-z0-9-]+:([0-9]{12}):([^{}\s]+)', raw)
        if match:
            service, account, suffix = match[2], match[3], match[4]
            expected = {'kinesis': r'stream/[A-Za-z0-9_.-]+',
                        'firehose': r'deliverystream/[A-Za-z0-9_.-]+',
                        'lambda': r'function:[A-Za-z0-9_-]+(?::[A-Za-z0-9_$-]+)?'}
            if re.fullmatch(expected[service], suffix):
                verdict = 'PASS' if account == resource.scope.account else 'FAIL'
    results.append(ctx.finding('LOGS_DIRECT_DESTINATION_ACCOUNT', path, verdict,
        'direct Kinesis, Firehose and Lambda destinations must belong to the subscription account; logical destinations, external existence, IAM permissions, partition/Region compatibility and unresolved references remain unverified'))
    return results
