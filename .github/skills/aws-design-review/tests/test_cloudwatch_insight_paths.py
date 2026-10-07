import json
import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def check(body):
    main = target('rule', 'AWS::CloudWatch::InsightRule', RuleBody=body if isinstance(body, str) or body == UNKNOWN else json.dumps(body))
    return {r['rule_id']: r['verdict'] for r in run_resource_checks(linked_design(main), main)}


def body(fmt='JSON', path='$.ip'):
    return {'Schema': {'Name': 'CloudWatchLogRule', 'Version': 1}, 'LogFormat': fmt,
            'LogGroupNames': ['group'], 'Contribution': {'Keys': [path]}, 'AggregateOn': 'Count'}


@pytest.mark.parametrize('path,expected', [
    ('$.userAgent', 'PASS'), ('$.endpoints[0]', 'PASS'), ('$.users[1].name', 'PASS'),
    ('$.requestParameters.instanceId', 'PASS'), ('$.a[1].b[2]', 'PASS'),
    ('$.c-count', 'NEEDS_REVIEW'), ('$.1name', 'NEEDS_REVIEW'),
    ('$["name"]', 'NEEDS_REVIEW'), ('$.a[-1]', 'NEEDS_REVIEW'),
    ('$.a[*]', 'NEEDS_REVIEW'), ('${path}', 'NEEDS_REVIEW'), (UNKNOWN, 'NEEDS_REVIEW'),
])
def test_json_paths(path, expected):
    assert check(body(path=path))['CLOUDWATCH_INSIGHT_FIELD_PATHS'] == expected


@pytest.mark.parametrize('path,expected', [('1', 'PASS'), ('99', 'PASS'), ('0', 'FAIL'), ('-1', 'FAIL'),
    ('IpAddress', 'PASS'), ('Other', 'NEEDS_REVIEW')])
def test_clf_paths(path, expected):
    value = body('CLF', path)
    value['Fields'] = {'4': 'IpAddress'}
    assert check(value)['CLOUDWATCH_INSIGHT_FIELD_PATHS'] == expected


@pytest.mark.parametrize('fields,expected', [
    ({'1': 'Ip', '2': 'Bytes'}, 'PASS'), ({'0': 'Ip'}, 'FAIL'), ({'-1': 'Ip'}, 'FAIL'),
    ({'1': 'Ip', '2': 'Ip'}, 'NEEDS_REVIEW'), ({'word': 'Ip'}, 'NEEDS_REVIEW'),
    ({'1': UNKNOWN}, 'NEEDS_REVIEW'), ([], 'NEEDS_REVIEW'),
])
def test_clf_aliases(fields, expected):
    value = body('CLF', 'Ip')
    value['Fields'] = fields
    assert check(value)['CLOUDWATCH_INSIGHT_CLF_FIELDS'] == expected


@pytest.mark.parametrize('account,expected', [('*', 'PASS'), ('111111111111', 'PASS'),
    ('1111*', 'FAIL'), ('*1111', 'FAIL'), ('11*11', 'FAIL'), ('**', 'FAIL'),
    ('123', 'NEEDS_REVIEW'), ('${account}', 'NEEDS_REVIEW')])
def test_arn_account_wildcards(account, expected):
    value = body()
    value.pop('LogGroupNames')
    value['LogGroupARNs'] = [f'arn:aws:logs:ap-northeast-1:{account}:log-group/Group*']
    assert check(value)['CLOUDWATCH_INSIGHT_ARN_ACCOUNT_WILDCARD'] == expected


def test_filters_and_valueof_are_checked():
    value = body()
    value['AggregateOn'] = 'Sum'
    value['Contribution'].update(ValueOf='$.bytes', Filters=[{'Match': '$.nested.status', 'EqualTo': 200}])
    assert check(value)['CLOUDWATCH_INSIGHT_FIELD_PATHS'] == 'PASS'
    value['Contribution']['Filters'][0]['Match'] = '$[*]'
    assert check(value)['CLOUDWATCH_INSIGHT_FIELD_PATHS'] == 'NEEDS_REVIEW'


@pytest.mark.parametrize('raw', [UNKNOWN, '{}', '{bad', '{"Schema":{},"Schema":{}}',
    json.dumps({'Schema': {'Name': 'CloudWatchLogRule', 'Version': 2}})])
def test_unknown_body(raw):
    result = check(raw)
    assert all(result[k] == 'NEEDS_REVIEW' for k in ('CLOUDWATCH_INSIGHT_FIELD_PATHS',
        'CLOUDWATCH_INSIGHT_CLF_FIELDS', 'CLOUDWATCH_INSIGHT_ARN_ACCOUNT_WILDCARD'))
