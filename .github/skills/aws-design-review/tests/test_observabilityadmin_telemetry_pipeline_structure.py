import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.observabilityadmin.telemetry_pipeline_structure import evaluate_observabilityadmin_telemetry_pipeline_structure
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN

BODY='pipeline:\n  source:\n    cloudwatch_logs: {}\n  sink:\n    - cloudwatch_logs: {}\n'


def fixture(body=BODY):
    r=target('pipeline','AWS::ObservabilityAdmin::TelemetryPipelines',Configuration={'Body':body})
    return linked_design(r),r


@pytest.mark.parametrize('body,expected',[
    (BODY,'PASS'),(BODY.replace('cloudwatch_logs','cloudwatch_metrics'),'PASS'),
    (BODY.replace('cloudwatch_logs: {}','s3: {}',1),'PASS'),
    ('pipeline: {source: {s3: {}}, sink: [{cloudwatch_logs: {}}]}','PASS'),
    ('pipeline: {source: {}, sink: [{cloudwatch_logs: {}}]}','FAIL'),
    ('pipeline: {source: {s3: {}, cloudwatch_logs: {}}, sink: [{cloudwatch_logs: {}}]}','FAIL'),
    ('pipeline: {source: {s3: {}}, sink: []}','FAIL'),
    ('pipeline: {source: {s3: {}}, sink: [{cloudwatch_logs: {}}, {cloudwatch_logs: {}}]}','FAIL'),
    ('pipeline: {source: {s3: {}}, sink: [{cloudwatch_logs: {}, cloudwatch_metrics: {}}]}','FAIL'),
    ('pipeline: {source: {s3: {}}}','FAIL'),
    ('pipeline: {sink: [{cloudwatch_logs: {}}]}','FAIL'),
    ('pipeline: {source: [{s3: {}}], sink: [{cloudwatch_logs: {}}]}','NEEDS_REVIEW'),
    ('pipeline: {source: {s3: null}, sink: [{cloudwatch_logs: {}}]}','NEEDS_REVIEW'),
    ('pipeline: {source: &x [*x]}','NEEDS_REVIEW'),
    ('pipeline: {source: !Custom {}}','NEEDS_REVIEW'),
    ('pipeline: {}\npipeline: {}','NEEDS_REVIEW'),
    ('pipeline: [','FAIL'),(UNKNOWN,'NEEDS_REVIEW'),('${Configuration}','NEEDS_REVIEW')])
def test_cardinality_and_safe_yaml(body,expected):
    d,r=fixture(body)
    assert evaluate_observabilityadmin_telemetry_pipeline_structure(d,r)[0]['verdict']==expected


def test_conditional_resource_is_held():
    d,r=fixture();r.template=TemplateContext(state='UNRESOLVED')
    assert evaluate_observabilityadmin_telemetry_pipeline_structure(d,r)[0]['verdict']=='NEEDS_REVIEW'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r=fixture();root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert any(f['rule_id']=='TELEMETRY_PIPELINE_SOURCE_SINK' and f['verdict']=='PASS' for f in results)
