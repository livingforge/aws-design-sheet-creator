import pytest
from aws_design_sheet.checks.cloudwatch import anomaly_timezone as timezone
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, UNKNOWN
from test_autoscaling_group_nested_constraints import design


@pytest.mark.parametrize('name,expected', [('Asia/Tokyo', 'PASS'), ('America/New_York', 'PASS'),
    ('US/Eastern', 'PASS'), ('Etc/UTC', 'PASS'), ('UTC', 'PASS'), ('asia/tokyo', 'FAIL'),
    ('Tokyo', 'FAIL'), ('Asia/Tokyo\n', 'FAIL'), ('../UTC', 'FAIL'),
    (UNKNOWN, 'NEEDS_REVIEW'), ('{{resolve:ssm:tz}}', 'NEEDS_REVIEW')])
def test_pinned_timezone_names(name, expected):
    resource = target('anomaly', 'AWS::CloudWatch::AnomalyDetector', Configuration={'MetricTimeZone': name})
    result = run_resource_checks(design(resource), resource)
    assert result[0]['verdict'] == expected


def test_missing_dataset_never_rejects_names(monkeypatch):
    monkeypatch.setattr(timezone, 'timezone_names', lambda: None)
    resource = target('anomaly', 'AWS::CloudWatch::AnomalyDetector', Configuration={'MetricTimeZone': 'Asia/Tokyo'})
    assert timezone.anomaly_timezone(design(resource), resource)[0]['verdict'] == 'NEEDS_REVIEW'


def test_optional_timezone_absent():
    resource = target('anomaly', 'AWS::CloudWatch::AnomalyDetector')
    assert timezone.anomaly_timezone(design(resource), resource) == []
