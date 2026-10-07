"""Log-group capabilities established by explicit same-scope references."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from .policy_limits import URL as ACCOUNT_POLICY_URL, prefix
from .processors import transformer_processors

SOURCES = {'LOGS_TRANSFORMER_STANDARD_CLASS': [
    'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-logs-transformer.html',
    'https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_CreateLogGroup.html',
]}
SOURCES['LOGS_TRANSFORMED_INPUT_DECLARATION'] = [
    'https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutSubscriptionFilter.html',
    'https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutMetricFilter.html', ACCOUNT_POLICY_URL]


def declared_account_transformer(ctx, resource, group):
    if not re.fullmatch(r'\d{12}', resource.scope.account) or not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-\d+', resource.scope.region):
        return False
    name = value(ctx, group, '/properties/LogGroupName')
    for policy in ctx.design.resources:
        if policy.type != 'AWS::Logs::AccountPolicy' or policy.scope != resource.scope:
            continue
        if value(ctx, policy, '/properties/PolicyType') != 'TRANSFORMER_POLICY':
            continue
        scope = value(ctx, policy, '/properties/Scope')
        if scope is not ABSENT and scope != 'ALL':
            continue
        selected = prefix(value(ctx, policy, '/properties/SelectionCriteria'))
        if selected == '' or (selected is not None and isinstance(name, str)
                and re.fullmatch(r'[A-Za-z0-9_./#-]{1,512}', name) and name.startswith(selected)):
            return True
    return False


@resource_check('AWS::Logs::MetricFilter', 'AWS::Logs::SubscriptionFilter')
def transformed_input_declaration(design, resource):
    ctx = _Context(design, resource)
    path = '/properties/ApplyOnTransformedLogs'
    enabled = value(ctx, resource, path)
    if enabled is ABSENT:
        return []
    group = linked(ctx, resource, '/properties/LogGroupName', 'AWS::Logs::LogGroup')
    found = False
    if enabled is True and group:
        for other in design.resources:
            if other.type != 'AWS::Logs::Transformer' or other.scope != resource.scope:
                continue
            transformed_group = linked(ctx, other, '/properties/LogGroupIdentifier', group.type)
            if transformed_group and transformed_group.id == group.id:
                found = True
                break
        if not found:
            found = declared_account_transformer(ctx, resource, group)
    return [ctx.finding('LOGS_TRANSFORMED_INPUT_DECLARATION', path,
        'PASS' if found else 'NEEDS_REVIEW',
        'a group-level or matching account-level transformer is declared; activation, deployment order, overlapping policies and transformer validity remain separate checks' if found else
        'a matching transformer declaration is not proven; external transformers, unresolved links/selection criteria and false-flag applicability remain unverified')]


@resource_check('AWS::Logs::Transformer')
def transformer_class(design, resource):
    ctx = _Context(design, resource)
    path = '/properties/LogGroupIdentifier'
    group = linked(ctx, resource, path, 'AWS::Logs::LogGroup')
    verdict = 'NEEDS_REVIEW'
    if group:
        kind = value(ctx, group, '/properties/LogGroupClass')
        if kind is ABSENT or kind == 'STANDARD':
            verdict = 'PASS'
        elif kind in ('INFREQUENT_ACCESS', 'DELIVERY'):
            verdict = 'FAIL'
    return transformer_processors(design, resource) + [ctx.finding('LOGS_TRANSFORMER_STANDARD_CLASS', path, verdict,
        'transformers require a Standard log group; omitted class defaults to STANDARD, unresolved targets require review')]


@resource_check('AWS::Logs::Integration')
def integration_singleton(design, resource):
    ctx = _Context(design, resource)
    names = set()
    if re.fullmatch(r'\d{12}', resource.scope.account) and re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-\d+', resource.scope.region):
        for other in design.resources:
            if other.type != resource.type or other.scope != resource.scope:
                continue
            name = value(ctx, other, '/properties/IntegrationName')
            if isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9._/#-]{1,50}', name):
                names.add(name)
    return [ctx.finding('LOGS_INTEGRATION_SINGLETON', '/properties/IntegrationName',
        'FAIL' if len(names) > 1 else 'NEEDS_REVIEW',
        'distinct named integrations exceed the one-integration limit in a known scope; same-name aliases and external integrations remain unverified')]


SOURCES['LOGS_INTEGRATION_SINGLETON'] = [
    'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-logs-integration.html']
