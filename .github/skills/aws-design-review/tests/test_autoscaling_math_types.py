import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def check(expression, extra=(), returns=True):
    queries = [{'Id': 'm1', 'MetricStat': {}}, {'Id': 'm2', 'MetricStat': {}},
               *extra, {'Id': 'result', 'Expression': expression, 'ReturnData': returns}]
    main = target('policy', 'AWS::AutoScaling::ScalingPolicy', TargetTrackingConfiguration={
        'CustomizedMetricSpecification': {'Metrics': queries}})
    return next(r['verdict'] for r in run_resource_checks(linked_design(main), main)
                if r['rule_id'] == 'AUTOSCALING_MATH_ARGUMENT_TYPES' and r['path'].endswith(f'/{len(queries)-1}/Expression'))


@pytest.mark.parametrize('expression,expected', [
    ('ABS(m1-m2)', 'PASS'), ('CEIL(m1)', 'PASS'), ('FLOOR(m1)', 'PASS'),
    ('DIFF(m1)', 'PASS'), ('LOG10(m1)', 'PASS'), ('RATE(m1)', 'PASS'),
    ('SUM([m1,m2])', 'PASS'), ('AVG(METRICS())', 'PASS'),
    ('m1-AVG(m1)', 'PASS'), ('TIME_SERIES(MAX(m1))', 'PASS'),
    ('FIRST(METRICS())', 'PASS'), ('m1/METRIC_COUNT(METRICS())', 'PASS'),
    ('SUM(METRICS("m"))', 'PASS'), ('SUM([METRICS("m1"),METRICS("m2")])', 'PASS'),
    ('SUM(m1)', 'FAIL'), ('AVG(m1)', 'FAIL'), ('METRICS()', 'FAIL'), ('5', 'FAIL'),
    ('ABS(5)', 'FAIL'), ('SUM(5)', 'FAIL'), ('FIRST(m1)', 'FAIL'),
    ('METRIC_COUNT(m1)', 'FAIL'), ('TIME_SERIES(m1)', 'FAIL'), ('AVG()', 'FAIL'),
    ('ABS(m1,m2)', 'FAIL'), ('METRICS(5)', 'FAIL'), ('SUM([1,2])', 'FAIL'),
    ('SUM(METRICS("absent"))', 'NEEDS_REVIEW'), ('SUM([])', 'NEEDS_REVIEW'),
    ('m1/PERIOD(m1)', 'PASS'), ('PERIOD(m1)', 'FAIL'), ('m1/PERIOD(m1+1)', 'FAIL'),
    ('m1/PERIOD(5)', 'FAIL'), ('m1/PERIOD(missing)', 'NEEDS_REVIEW'),
    ('FIRST(ANOMALY_DETECTION_BAND(m1))', 'PASS'),
    ('LAST(ANOMALY_DETECTION_BAND(m1,4))', 'PASS'),
    ('ANOMALY_DETECTION_BAND(m1)', 'FAIL'), ('ANOMALY_DETECTION_BAND(5)', 'FAIL'),
    ('ANOMALY_DETECTION_BAND(m1,m2)', 'FAIL'),
    ('FIRST(ANOMALY_DETECTION_BAND(m1+1))', 'NEEDS_REVIEW'),
    ('FUTURE(m1)', 'NEEDS_REVIEW'), ('SUM', 'NEEDS_REVIEW'), ('ABS(m1,)', 'NEEDS_REVIEW'),
    ('SUM(missing)', 'NEEDS_REVIEW'), ('IF(m1,1,2)', 'PASS'),
    ('m1 # comment', 'NEEDS_REVIEW'), ('1e3*m1', 'NEEDS_REVIEW'), (UNKNOWN, 'NEEDS_REVIEW'),
])
def test_function_types(expression, expected):
    assert check(expression) == expected


def test_nonreturned_scalar_and_unknown_return_flag():
    assert check('AVG(m1)', returns=False) == 'NEEDS_REVIEW'
    assert check('AVG(m1)', returns=UNKNOWN) == 'NEEDS_REVIEW'


def test_nested_query_types_and_cycles():
    assert check('TIME_SERIES(e1)', [{'Id': 'e1', 'Expression': 'AVG(m1)'}]) == 'PASS'
    assert check('ABS(e1)', [{'Id': 'e1', 'Expression': 'AVG(m1)'}]) == 'FAIL'
    assert check('ABS(e1)', [{'Id': 'e1', 'Expression': 'result'}]) == 'NEEDS_REVIEW'
    assert check('ABS(e1)', [{'Id': 'e1', 'Expression': UNKNOWN}]) == 'NEEDS_REVIEW'
    assert check('m1/PERIOD(e1)', [{'Id': 'e1', 'Expression': 'm1+1'}]) == 'FAIL'


def test_parser_budget():
    assert check('ABS(' * 210 + 'm1' + ')' * 210) == 'NEEDS_REVIEW'
