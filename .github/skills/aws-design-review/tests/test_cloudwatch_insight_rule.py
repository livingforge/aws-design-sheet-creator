import json
import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, UNKNOWN
from test_autoscaling_group_nested_constraints import design


def valid_body():
    return {'Schema': {'Name': 'CloudWatchLogRule', 'Version': 1}, 'LogGroupNames': ['logs*'],
            'LogFormat': 'JSON', 'Contribution': {'Keys': ['$.ip']}, 'AggregateOn': 'Count'}


def check(raw, **props):
    resource = target('insight', 'AWS::CloudWatch::InsightRule', RuleBody=raw, **props)
    return {r['rule_id']: r['verdict'] for r in run_resource_checks(design(resource), resource)}


@pytest.mark.parametrize('patch,expected', [
    ({}, 'PASS'), ({'LogGroupARNs': ['arn:aws:logs:region:account:log-group/name']}, 'FAIL'),
    ({'LogFormat': 'CLF'}, 'PASS'), ({'LogFormat': 'XML'}, 'FAIL'),
    ({'AggregateOn': 'Average'}, 'FAIL'), ({'Schema': {'Name': 'FutureRule', 'Version': 2}}, 'NEEDS_REVIEW'),
    ({'Schema': {'Name': 'CloudWatchLogRule', 'Version': True}}, 'NEEDS_REVIEW'),
    ({'LogGroupNames': 'logs'}, 'FAIL'), ({'Contribution': {}}, 'FAIL'),
    ({'Contribution': {'Keys': ['$.ip'] * 5}}, 'FAIL'),
    ({'Contribution': {'Keys': ['$.ip'], 'ValueOf': '$.bytes'}}, 'FAIL'),
    ({'AggregateOn': 'Sum', 'Contribution': {'Keys': ['$.ip'], 'ValueOf': '$.bytes'}}, 'PASS'),
])
def test_root_structure(patch, expected):
    body = valid_body(); body.update(patch)
    assert check(json.dumps(body))['CLOUDWATCH_INSIGHT_STRUCTURE'] == expected


@pytest.mark.parametrize('filter,expected', [
    ({'Match': '$.method', 'In': ['GET']}, 'PASS'),
    ({'Match': '$.method', 'In': ['GET'] * 10}, 'PASS'),
    ({'Match': '$.method', 'In': ['GET'] * 11}, 'FAIL'),
    ({'Match': '$.method', 'StartsWith': 'GET'}, 'FAIL'),
    ({'Match': '$.bytes', 'GreaterThan': 5}, 'PASS'),
    ({'Match': '$.bytes', 'GreaterThan': True}, 'FAIL'),
    ({'Match': '$.method', 'IsPresent': False}, 'PASS'),
    ({'Match': '$.method', 'IsPresent': 'false'}, 'FAIL'),
    ({'Match': '$.bytes', 'GreaterThan': 5, 'LessThan': 10}, 'FAIL'),
    ({'In': ['GET']}, 'FAIL'),
])
def test_filter_types(filter, expected):
    body = valid_body(); body['Contribution']['Filters'] = [filter]
    assert check(json.dumps(body))['CLOUDWATCH_INSIGHT_STRUCTURE'] == expected


@pytest.mark.parametrize('count,expected', [(4, 'PASS'), (5, 'FAIL')])
def test_filter_limit(count, expected):
    body = valid_body(); body['Contribution']['Filters'] = [{'Match': '$.ip', 'IsPresent': True}] * count
    assert check(json.dumps(body))['CLOUDWATCH_INSIGHT_STRUCTURE'] == expected


@pytest.mark.parametrize('raw,expected', [
    ('[]', 'FAIL'), ('{', 'FAIL'), ('NaN', 'FAIL'), (UNKNOWN, 'NEEDS_REVIEW'),
    ('{{resolve:ssm:rule}}', 'NEEDS_REVIEW'),
])
def test_unresolved_and_invalid_json(raw, expected):
    assert check(raw)['CLOUDWATCH_INSIGHT_STRUCTURE'] == expected


def test_log_sources_exclusive_and_clf_aliases_not_rejected():
    body = valid_body(); del body['LogGroupNames']
    assert check(json.dumps(body))['CLOUDWATCH_INSIGHT_STRUCTURE'] == 'FAIL'
    body.update(LogGroupARNs=['arn'], LogFormat='CLF', Fields={'4': 'IpAddress'})
    body['Contribution']['Keys'] = ['IpAddress']
    assert check(json.dumps(body))['CLOUDWATCH_INSIGHT_STRUCTURE'] == 'PASS'


@pytest.mark.parametrize('count,expected', [(50, 'PASS'), (51, 'FAIL')])
def test_tag_limit(count, expected):
    tags = [{'Key': str(i), 'Value': 'x'} for i in range(count)]
    assert check(json.dumps(valid_body()), Tags=tags)['CLOUDWATCH_INSIGHT_TAG_COUNT'] == expected
