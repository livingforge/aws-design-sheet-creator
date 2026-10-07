import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.iot.metric_types import evaluate_iot_metric_types, BUILTINS, OPS, ALL_OPERATORS
from test_autoscaling_group_and_scaling_policy import target,linked_design


@pytest.mark.parametrize('metric',list(BUILTINS))
@pytest.mark.parametrize('operator',sorted(ALL_OPERATORS))
def test_builtin_operators(metric,operator):
    r=target('main','AWS::IoT::SecurityProfile',Behaviors=[{'Metric':'aws:'+metric,'Criteria':{'ComparisonOperator':operator}}])
    assert evaluate_iot_metric_types(linked_design(r),r)[0]['verdict']==('PASS' if operator in OPS[BUILTINS[metric]] else 'FAIL')


@pytest.mark.parametrize('kind',['number','number-list','string-list','ip-address-list','future',{'$state':'UNRESOLVED'}])
@pytest.mark.parametrize('mode',['known','conditional','region','source_template','target_template'])
def test_custom(kind,mode):
    r=target('main','AWS::IoT::SecurityProfile',Behaviors=[{'Metric':'custom','Criteria':{'ComparisonOperator':'in-set','DurationSeconds':300}}])
    other=target('metric','AWS::IoT::CustomMetric',MetricType=kind)
    d=linked_design(r,[other],[('Behaviors/0/Metric','metric')])
    if mode=='conditional':d.relations[0].condition='maybe'
    if mode=='region':other.scope.region='us-east-1'
    if mode=='source_template':r.template=TemplateContext(state='UNRESOLVED')
    if mode=='target_template':other.template=TemplateContext(state='UNRESOLVED')
    actual=[f['verdict'] for f in evaluate_iot_metric_types(d,r)]
    expected=['NEEDS_REVIEW']*2
    if mode=='known' and isinstance(kind,str) and kind in OPS:
        expected=['PASS' if 'in-set' in OPS[kind] else 'FAIL','NOT_APPLICABLE' if kind=='number' else 'FAIL']
    assert actual==expected


@pytest.mark.parametrize('metric',list(BUILTINS))
def test_builtin_duration(metric):
    r=target('main','AWS::IoT::SecurityProfile',Behaviors=[{'Metric':'aws:'+metric,'Criteria':{'DurationSeconds':300}}])
    assert evaluate_iot_metric_types(linked_design(r),r)[0]['verdict']==('FAIL' if BUILTINS[metric].endswith('-list') else 'NOT_APPLICABLE')


@pytest.mark.parametrize('behaviors',['in-set',{'$state':'UNRESOLVED'},[{'Metric':'custom','Criteria':{'ComparisonOperator':'in-set'}}],[{'Metric':'aws:future','Criteria':{'ComparisonOperator':'in-set'}}],[{'Metric':'aws:message-byte-size','Criteria':{'ComparisonOperator':{'$state':'UNRESOLVED'}}}]])
def test_unknown_and_malformed(behaviors):
    r=target('main','AWS::IoT::SecurityProfile',Behaviors=behaviors)
    assert all(f['verdict']=='NEEDS_REVIEW' for f in evaluate_iot_metric_types(linked_design(r),r))


def test_ml_omission():
    r=target('main','AWS::IoT::SecurityProfile',Behaviors=[{'Metric':'aws:num-messages-sent','Criteria':{'MlDetectionConfig':{'ConfidenceLevel':'HIGH'}}}])
    assert evaluate_iot_metric_types(linked_design(r),r)==[]


@pytest.mark.parametrize('metric,operator,expected',[
    ('aws:disconnect-duration','greater-than','FAIL'),
    ('aws:disconnect-duration','less-than-equals','PASS'),
    ('aws:listening-tcp-ports','in-port-set','PASS'),
    ('aws:listening-tcp-ports','in-set','FAIL'),
    ('aws:destination-ip-addresses','in-cidr-set','PASS'),
    ('aws:destination-ip-address','in-cidr-set','NEEDS_REVIEW'),
    ('aws:num-messages-sent','greater-than','PASS'),
    ('aws:source-ip-address','in-set','FAIL'),
])
def test_documented_metric_exceptions(metric,operator,expected):
    r=target('main','AWS::IoT::SecurityProfile',Behaviors=[{'Metric':metric,'Criteria':{'ComparisonOperator':operator}}])
    assert evaluate_iot_metric_types(linked_design(r),r)[0]['verdict']==expected


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('main','AWS::IoT::SecurityProfile',Behaviors=[{'Metric':'aws:source-ip-address','Criteria':{'DurationSeconds':300}}])
    assert any(f['rule_id']=='IOT_METRIC_CRITERIA_TYPES' and f['verdict']=='FAIL' for f in Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results'])
