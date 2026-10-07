"""Proven account-policy collisions within one declared deployment scope."""
import json
import re
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

URL='https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutAccountPolicy.html'
SOURCES={rule:[URL] for rule in ('LOGS_ACCOUNT_POLICY_SINGLETON','LOGS_ACCOUNT_POLICY_PREFIX_OVERLAP','LOGS_ACCOUNT_POLICY_SCOPED_COUNT','LOGS_ACCOUNT_POLICY_DATASOURCE_COLLISION')}


def literal_name(raw):
    return isinstance(raw,str) and bool(raw) and '{' not in raw


def prefix(raw):
    if raw is ABSENT:
        return ''  # No selection criteria applies to all log groups.
    match=re.fullmatch(r'\s*LogGroupNamePrefix\s*=\s*("(?:[^"\\]|\\.)*")\s*',raw) if isinstance(raw,str) else None
    if not match:
        return None
    try:
        result=json.loads(match[1])
    except ValueError:
        return None
    return result if literal_name(result) else None


def data_source(raw):
    quoted=r'("(?:[^"\\]|\\.)*")'
    match=re.fullmatch(r'\s*(DataSourceName|DataSourceType)\s*=\s*'+quoted+r'\s+AND\s+(DataSourceName|DataSourceType)\s*=\s*'+quoted+r'\s*',raw) if isinstance(raw,str) else None
    if not match or match[1]==match[3]:
        return None
    try:
        parts={match[1]:json.loads(match[2]),match[3]:json.loads(match[4])}
    except ValueError:
        return None
    return (parts['DataSourceName'],parts['DataSourceType']) if all(literal_name(v) for v in parts.values()) else None


def account_policy_limits(design,resource):
    ctx=_Context(design,resource)
    kind=value(ctx,resource,'/properties/PolicyType')
    name=value(ctx,resource,'/properties/PolicyName')
    if not literal_name(name) or kind not in ('DATA_PROTECTION_POLICY','SUBSCRIPTION_FILTER_POLICY','TRANSFORMER_POLICY','FIELD_INDEX_POLICY'):
        return []
    if not re.fullmatch(r'\d{12}',resource.scope.account) or not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-\d+',resource.scope.region):
        rule='LOGS_ACCOUNT_POLICY_SINGLETON' if kind in ('DATA_PROTECTION_POLICY','SUBSCRIPTION_FILTER_POLICY') else 'LOGS_ACCOUNT_POLICY_PREFIX_OVERLAP'
        return [ctx.finding(rule,'/properties/PolicyName','NEEDS_REVIEW','account or region identity is unresolved')]
    names={name}
    own_prefix=prefix(value(ctx,resource,'/properties/SelectionCriteria'))
    scoped_names={name} if own_prefix not in (None,'') else set()
    own_source=data_source(value(ctx,resource,'/properties/SelectionCriteria'))
    data_names={name} if own_source else set()
    source_collision=False
    overlap=False
    for other in design.resources:
        if other.id==resource.id or other.type!=resource.type or other.scope!=resource.scope:
            continue
        other_kind=value(ctx,other,'/properties/PolicyType')
        other_name=value(ctx,other,'/properties/PolicyName')
        if other_kind!=kind or not literal_name(other_name) or other_name==name:
            continue
        names.add(other_name)
        other_prefix=prefix(value(ctx,other,'/properties/SelectionCriteria'))
        other_source=data_source(value(ctx,other,'/properties/SelectionCriteria'))
        if other_source:
            data_names.add(other_name)
        source_collision |= own_source is not None and own_source==other_source
        if other_prefix not in (None,''):
            scoped_names.add(other_name)
        if own_prefix is not None and other_prefix is not None:
            overlap |= own_prefix.startswith(other_prefix) or other_prefix.startswith(own_prefix)
    if kind in ('DATA_PROTECTION_POLICY','SUBSCRIPTION_FILTER_POLICY'):
        return [ctx.finding('LOGS_ACCOUNT_POLICY_SINGLETON','/properties/PolicyName',
            'FAIL' if len(names)>1 else 'NEEDS_REVIEW',
            'multiple distinct policy names of this singleton type occur in one scope' if len(names)>1 else
            'no declared duplicate; existing account policies and ambiguous names remain unverified')]
    count=len(names) if kind=='TRANSFORMER_POLICY' else len(scoped_names)
    rows = [ctx.finding('LOGS_ACCOUNT_POLICY_PREFIX_OVERLAP','/properties/SelectionCriteria',
        'FAIL' if overlap else 'NEEDS_REVIEW',
        'distinct policies of this type have proven overlapping log-group prefixes' if overlap else
        'no declared overlap; other selection grammars, external policies and unresolved criteria remain unverified'),
        ctx.finding('LOGS_ACCOUNT_POLICY_SCOPED_COUNT','/properties/PolicyName',
        'FAIL' if count>20 or kind=='FIELD_INDEX_POLICY' and len(data_names)>20 else 'NEEDS_REVIEW',
        'checks the twenty-policy transformer limit and separate twenty-policy field-index prefix/data-source limits; declared counts do not verify remaining live quota')]
    if kind=='FIELD_INDEX_POLICY':
        rows.append(ctx.finding('LOGS_ACCOUNT_POLICY_DATASOURCE_COLLISION','/properties/SelectionCriteria',
            'FAIL' if source_collision else 'NEEDS_REVIEW',
            'distinct field-index policies use the same explicit data source name/type pair' if source_collision else
            'no proven duplicate data-source pair; external policies and other selection grammars remain unverified'))
    return rows
