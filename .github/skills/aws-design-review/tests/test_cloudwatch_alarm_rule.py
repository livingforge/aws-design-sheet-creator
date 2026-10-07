import pytest

from aws_design_sheet.checks.cloudwatch.alarm_rule import parse_expression
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN

PREFIX = 'CLOUDWATCH_ALARM_RULE_'


def alarm(name, expression=None, **extra):
    properties = {'AlarmName': name, **extra}
    if expression is not None:
        properties['AlarmRule'] = expression
    return target(name, 'AWS::CloudWatch::CompositeAlarm' if expression is not None else 'AWS::CloudWatch::Alarm', **properties)


def rows(main, *others):
    return {r['rule_id'].removeprefix(PREFIX): r for r in run_resource_checks(linked_design(main, others), main)
            if r['rule_id'].startswith(PREFIX)}


@pytest.mark.parametrize('raw,refs', [
    ('TRUE', ()), ('FALSE', ()), (' NOT (TRUE OR FALSE) ', ()),
    ('ALARM(cpu) AND NOT ALARM(deploy)', ('cpu', 'deploy')),
    ('(ALARM(cpu) OR ALARM(disk)) AND OK(net)', ('cpu', 'disk', 'net')),
    ('INSUFFICIENT_DATA("alarm with spaces")', ('alarm with spaces',)),
    ('ALARM("alarm(with)paren") OR OK(ALARM)', ('alarm(with)paren', 'ALARM')),
    ('(' * 1000 + 'TRUE' + ')' * 1000, ()),
])
def test_supported_grammar(raw, refs):
    assert parse_expression(raw).references == refs


@pytest.mark.parametrize('raw', [
    UNKNOWN, '', 'false', 'ALARM()', 'ALARM("unclosed)', 'ALARM(${name})',
    'ALARM("{{resolve:ssm:name}}")', 'ALARM(a) XOR ALARM(b)', 'TRUE FALSE',
    'AND TRUE', 'TRUE NOT FALSE', '(TRUE', 'TRUE)', '()', 'NOT',
    'ALARM(a) garbage', 'TRUE' * 3000, 'ALARM("escaped\\"name")',
])
def test_unsupported_expression_requires_review(raw):
    main = alarm('main', raw)
    assert parse_expression(raw) is None
    assert {r['verdict'] for r in rows(main).values()} == {'NEEDS_REVIEW'}


@pytest.mark.parametrize('count,expected', [(100, 'PASS'), (101, 'FAIL')])
def test_distinct_child_limit(count, expected):
    main = alarm('main', ' OR '.join(f'ALARM(child-{i})' for i in range(count)))
    result = rows(main)
    assert result['CHILD_COUNT']['verdict'] == expected
    assert result['DECLARATIONS']['verdict'] == 'NEEDS_REVIEW'


def test_repeated_references_and_arn_aliases():
    expressions = [f'ALARM(child-{i})' for i in range(100)]
    expressions += ['OK(child-0)', 'ALARM("arn:aws:cloudwatch:ap-northeast-1:111111111111:alarm:child-0")']
    assert rows(alarm('main', ' OR '.join(expressions)))['CHILD_COUNT']['verdict'] == 'PASS'


@pytest.mark.parametrize('change', ['none', 'region', 'account', 'environment', 'duplicate', 'unknown'])
def test_declaration_identity(change):
    main = alarm('main', 'ALARM(child)')
    child = alarm('child')
    others = [child]
    if change in ('region', 'account', 'environment'):
        setattr(child.scope, change, 'other')
    if change == 'duplicate':
        other = alarm('child')
        other.id = 'duplicate'
        others.append(other)
    if change == 'unknown':
        main.scope.account = child.scope.account = 'unknown'
    result = rows(main, *others)
    expected = 'PASS' if change == 'none' else 'NEEDS_REVIEW'
    assert result['DECLARATIONS']['verdict'] == expected
    assert result['CYCLE']['verdict'] == expected


@pytest.mark.parametrize('expression', ['ALARM(main)', 'ALARM("arn:aws:cloudwatch:ap-northeast-1:111111111111:alarm:main")'])
def test_self_cycle_is_operational_warning(expression):
    finding = rows(alarm('main', expression))['CYCLE']
    assert finding['verdict'] == 'FAIL'
    assert finding['severity'] == 'WARNING'


def test_transitive_cycle_and_unknown_descendant():
    main = alarm('main', 'ALARM(second)')
    second = alarm('second', 'ALARM(third)')
    third = alarm('third', 'ALARM(main)')
    assert rows(main, second, third)['CYCLE']['verdict'] == 'FAIL'
    third = alarm('third', UNKNOWN)
    assert rows(main, second, third)['CYCLE']['verdict'] == 'NEEDS_REVIEW'
    third = alarm('third', 'FALSE')
    assert rows(main, second, third)['CYCLE']['verdict'] == 'PASS'


def test_foreign_arn_not_resolved_by_name():
    main = alarm('main', 'ALARM("arn:aws:cloudwatch:us-west-2:111111111111:alarm:child")')
    result = rows(main, alarm('child'))
    assert result['DECLARATIONS']['verdict'] == 'NEEDS_REVIEW'
    assert result['CHILD_COUNT']['verdict'] == 'NEEDS_REVIEW'


def test_constant_expression_has_no_dependencies():
    assert {r['verdict'] for r in rows(alarm('main', 'FALSE')).values()} == {'PASS'}
