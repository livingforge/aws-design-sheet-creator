import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.redshiftserverless.monitoring_mode import evaluate_redshiftserverless_monitoring_mode
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def fixture(keys):
    r=target('workgroup','AWS::RedshiftServerless::Workgroup',ConfigParameters=[{'ParameterKey':k,'ParameterValue':'1'} for k in keys])
    return linked_design(r),r


@pytest.mark.parametrize('metric',[
    'max_query_blocks_read','max_scan_row_count','max_query_execution_time',
    'max_query_queue_time','max_query_temp_blocks_to_disk','max_join_row_count',
    'max_nested_loop_join_row_count','max_io_skew','max_query_cpu_usage_percent'])
def test_every_documented_metric_conflicts(metric):
    d,r=fixture([metric,'require_ssl','wlm_json_configuration'])
    assert evaluate_redshiftserverless_monitoring_mode(d,r)[0]['verdict']=='FAIL'
    r.fields[0].candidates[0].value.reverse()
    assert evaluate_redshiftserverless_monitoring_mode(d,r)[0]['verdict']=='FAIL'


@pytest.mark.parametrize('keys,expected',[
    (['wlm_json_configuration'],'PASS'),(['max_query_queue_time'],'PASS'),
    (['max_query_queue_time','max_scan_row_count'],'PASS'),
    (['wlm_json_configuration','search_path'],'PASS'),
    (['require_ssl','use_fips_ssl'],'NOT_APPLICABLE'),([], 'NOT_APPLICABLE'),
    ([UNKNOWN,'wlm_json_configuration'],'NEEDS_REVIEW'),
    (['unknown_key','wlm_json_configuration'],'NEEDS_REVIEW'),
    (['max_query_execution_time',UNKNOWN,'wlm_json_configuration'],'FAIL'),
    (['MAX_QUERY_EXECUTION_TIME','wlm_json_configuration'],'NEEDS_REVIEW')])
def test_modes_and_unknown_parameters(keys,expected):
    d,r=fixture(keys)
    assert evaluate_redshiftserverless_monitoring_mode(d,r)[0]['verdict']==expected


def test_conditional_resource_is_held():
    d,r=fixture(['max_scan_row_count','wlm_json_configuration']);r.template=TemplateContext(state='UNRESOLVED')
    assert evaluate_redshiftserverless_monitoring_mode(d,r)[0]['verdict']=='NEEDS_REVIEW'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r=fixture(['max_scan_row_count','wlm_json_configuration']);root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert any(f['rule_id']=='REDSHIFT_SERVERLESS_MONITORING_MODE' and f['verdict']=='FAIL' for f in results)
