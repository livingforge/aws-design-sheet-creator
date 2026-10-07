import pytest
from aws_design_sheet.checks.neptune.event_source_type import evaluate_neptune_event_source_type
from aws_design_sheet.checks.redshift.event_source_type import evaluate_redshift_event_source_type
from aws_design_sheet.checks.registry import combine
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link
event_source_types_checks=combine(evaluate_neptune_event_source_type,evaluate_redshift_event_source_type)


def fixture(service='Redshift',source='cluster',kind='AWS::Redshift::Cluster'):
    r=target('subscription','AWS::'+service+'::EventSubscription',SourceType=source,SourceIds=['source'])
    other=target('source',kind);d=linked_design(r,[other]);link(d,r,'SourceIds/0',other)
    return d,r,other


def verdict(d,r):return event_source_types_checks(d,r)[0]['verdict']


@pytest.mark.parametrize('service,source,kind,want',[
    ('Redshift','cluster','AWS::Redshift::Cluster','PASS'),
    ('Redshift','cluster-parameter-group','AWS::Redshift::ClusterParameterGroup','PASS'),
    ('Redshift','cluster-security-group','AWS::Redshift::ClusterSecurityGroup','PASS'),
    ('Redshift','scheduled-action','AWS::Redshift::ScheduledAction','PASS'),
    ('Redshift','cluster','AWS::EC2::Instance','FAIL'),
    ('Redshift','cluster-snapshot','AWS::Redshift::Cluster','NEEDS_REVIEW'),
    ('Neptune','db-instance','AWS::Neptune::DBInstance','PASS'),
    ('Neptune','db-cluster','AWS::Neptune::DBCluster','PASS'),
    ('Neptune','db-instance','AWS::Neptune::DBCluster','FAIL'),
    ('Neptune','db-instance','AWS::RDS::DBInstance','FAIL'),
    ('Neptune','db-parameter-group','AWS::Neptune::DBParameterGroup','NEEDS_REVIEW')])
def test_type_mapping(service,source,kind,want):
    d,r,*_=fixture(service,source,kind);assert verdict(d,r)==want


@pytest.mark.parametrize('mode',['missing','conditional','duplicate','scope','unknown_source','unknown_type','unknown_list'])
def test_uncertainty(mode):
    d,r,other=fixture()
    if mode=='missing':d.resources.remove(other)
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='duplicate':link(d,r,'SourceIds/0',other)
    if mode=='scope':other.scope.region='us-east-1'
    if mode=='unknown_source':r.fields[1].candidates[0].value=[UNKNOWN]
    if mode=='unknown_type':r.fields[0].candidates[0].value=UNKNOWN
    if mode=='unknown_list':r.fields[1].candidates[0].value=UNKNOWN
    assert verdict(d,r)=='NEEDS_REVIEW'


def test_all_sources_checked():
    d,r,other=fixture();bad=target('bad','AWS::Redshift::ScheduledAction');d.resources.append(bad)
    r.fields[1].candidates[0].value.append('bad');link(d,r,'SourceIds/1',bad)
    assert verdict(d,r)=='FAIL'


def test_source_type_required():
    d,r,*_=fixture();r.fields.pop(0)
    assert verdict(d,r)=='FAIL'


def test_all_sources_no_specific_ids():
    d,r,*_=fixture();r.fields.pop();d.relations=[]
    assert verdict(d,r)=='NOT_APPLICABLE'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r,*_=fixture();root=Path(__file__).resolve().parents[1]
    results=Checker(root/"schemas",root/"profiles/vpc-subnet.json").check(d)["results"]
    assert any(f["rule_id"]=="REDSHIFT_EVENT_SOURCE_TYPE" and f["verdict"]=="PASS" for f in results)
