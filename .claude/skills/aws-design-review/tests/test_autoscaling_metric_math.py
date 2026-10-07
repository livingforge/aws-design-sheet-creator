import pytest
from aws_design_sheet.checks.autoscaling.metric_math import arithmetic_references
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def check(queries, predictive=False):
    props = {'TargetTrackingConfiguration': {'CustomizedMetricSpecification': {'Metrics': queries}}}
    if predictive:
        props = {'PredictiveScalingConfiguration': {'MetricSpecifications': [
            {'CustomizedLoadMetricSpecification': {'MetricDataQueries': queries}}]}}
    main = target('policy', 'AWS::AutoScaling::ScalingPolicy', **props)
    return [r for r in run_resource_checks(linked_design(main), main) if r['rule_id'] == 'AUTOSCALING_MATH_REFERENCES']


@pytest.mark.parametrize('expr,refs', [('m1/m2', {'m1', 'm2'}), ('(m1)/(m2)', {'m1', 'm2'}),
    ('-5*m1 + m2^2', {'m1', 'm2'}), ('50.25 - errors_total', {'errors_total'}),
    ('(' * 100 + 'm1' + ')' * 100, {'m1'})])
def test_arithmetic_subset(expr, refs):
    assert arithmetic_references(expr) == refs


@pytest.mark.parametrize('expr', ['SEARCH("name")',
    '${expression}', UNKNOWN, 'm1//2', 'm1**2', '1e3*m1', 'm1 m2',
    '(m1', 'm1)', '', '1_000*m1'])
def test_unrecognized_math_is_review(expr):
    assert arithmetic_references(expr) is None
    assert check([{'Id': 'm1', 'MetricStat': {}}, {'Id': 'e1', 'Expression': expr}])[0]['verdict'] == 'NEEDS_REVIEW'


@pytest.mark.parametrize('predictive', [False, True])
@pytest.mark.parametrize('expr,expected', [('m1/2', 'PASS'), ('missing/2', 'FAIL'), ('e1/2', 'NEEDS_REVIEW')])
def test_references(predictive, expr, expected):
    queries = [{'Id': 'm1', 'MetricStat': {}}, {'Id': 'e1', 'Expression': expr}]
    assert check(queries, predictive)[0]['verdict'] == expected


def test_unknown_and_duplicate_ids():
    for identifier in (UNKNOWN, 'e1'):
        queries = [{'Id': identifier, 'MetricStat': {}}, {'Id': 'e1', 'Expression': 'missing'}]
        assert check(queries)[0]['verdict'] == 'NEEDS_REVIEW'


def test_descendant_unknown_and_cycles():
    for tail in ('e2+1', 'SEARCH("unknown")', UNKNOWN):
        queries = [{'Id': 'm1', 'MetricStat': {}}, {'Id': 'e1', 'Expression': 'e2'},
                   {'Id': 'e2', 'Expression': 'e3'}, {'Id': 'e3', 'Expression': tail}]
        assert check(queries)[0]['verdict'] == 'NEEDS_REVIEW'
    queries = [{'Id': 'm1', 'MetricStat': {}}, {'Id': 'e1', 'Expression': 'e2+e3'},
               {'Id': 'e2', 'Expression': 'm1/2'}, {'Id': 'e3', 'Expression': 'm1*2'}]
    assert {r['verdict'] for r in check(queries)} == {'PASS'}


def test_unknown_metric_leaf_and_absent_expression():
    assert check([{'Id': 'm1', 'MetricStat': UNKNOWN}, {'Id': 'e1', 'Expression': 'm1'}])[0]['verdict'] == 'NEEDS_REVIEW'
    assert check([{'Id': 'm1', 'MetricStat': {}}]) == []
