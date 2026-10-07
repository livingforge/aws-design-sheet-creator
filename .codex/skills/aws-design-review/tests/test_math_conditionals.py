import pytest
from test_autoscaling_math_types import check


@pytest.mark.parametrize('expression,expected', [
    ('FILL(m1,0)', 'PASS'), ('FILL(m1,REPEAT)', 'PASS'), ('FILL(m1,LINEAR)', 'PASS'),
    ('SUM(FILL(METRICS(),m1))', 'PASS'), ('SUM(FILL(METRICS(),0))', 'PASS'),
    ('FILL(m1,m2)', 'NEEDS_REVIEW'), ('FILL(m1,"REPEAT")', 'NEEDS_REVIEW'),
    ('FILL(5,0)', 'FAIL'), ('FILL(m1)', 'FAIL'), ('FILL(m1,METRICS())', 'FAIL'),
    ('FILL(m1,UNKNOWN_MODE)', 'NEEDS_REVIEW'), ('REPEAT', 'NEEDS_REVIEW'),
    ('IF(m1>400,m1)', 'PASS'), ('IF(m1<=400,10,2)', 'PASS'),
    ('IF(m1!=m2,m1,m2)', 'PASS'), ('IF(m1==m2,1,0)', 'PASS'),
    ('IF(1,m1,m2)', 'PASS'), ('IF(1,m1)', 'PASS'),
    ('IF(1,2,3)', 'NEEDS_REVIEW'), ('IF(1,2,m1)', 'NEEDS_REVIEW'),
    ('IF(METRICS(),m1,m2)', 'FAIL'), ('IF(m1,METRICS(),m2)', 'FAIL'),
    ('IF(m1)', 'FAIL'), ('IF(m1,m2,0,1)', 'FAIL'),
    ('IF(0<m1<10,m1)', 'NEEDS_REVIEW'), ('IF(m1>0 AND m2>0,m1)', 'NEEDS_REVIEW'),
    ('FIRST(SORT(METRICS(),AVG,DESC))', 'PASS'),
    ('SUM(SORT(METRICS(),SUM,ASC,5))', 'PASS'), ('SORT(METRICS(),MIN,ASC)', 'FAIL'),
    ('FIRST(SORT(m1,AVG,DESC))', 'FAIL'), ('FIRST(SORT(METRICS(),STDDEV,DESC))', 'FAIL'),
    ('FIRST(SORT(METRICS(),AVG,DESC,m1))', 'FAIL'),
    ('FIRST(SORT(METRICS(),AVG,"DESC"))', 'NEEDS_REVIEW'),
    ('FIRST(SORT(METRICS(),AVG,FUTURE_ORDER))', 'NEEDS_REVIEW'),
    ('ABS(ASC)', 'NEEDS_REVIEW'),
])
def test_documented_conditional_and_sort_types(expression, expected):
    assert check(expression) == expected


@pytest.mark.parametrize('function', ['MINUTE', 'HOUR', 'DAY', 'DATE', 'MONTH', 'YEAR', 'EPOCH'])
@pytest.mark.parametrize('argument,expected', [('m1', 'PASS'), ('5', 'FAIL'), ('METRICS()', 'FAIL')])
def test_timestamp_function_types(function, argument, expected):
    assert check(function + '(' + argument + ')') == expected


@pytest.mark.parametrize('expression,expected', [
    ('SUM(REMOVE_EMPTY(METRICS()))', 'PASS'), ('REMOVE_EMPTY(METRICS())', 'FAIL'),
    ('REMOVE_EMPTY(m1)', 'FAIL'), ('REMOVE_EMPTY(5)', 'FAIL'),
    ('IF(DAY(m1)<6,m1)', 'PASS'), ('IF(MONTH(m1)==4,m1)', 'PASS'),
])
def test_documented_array_and_date_combinations(expression, expected):
    assert check(expression) == expected
