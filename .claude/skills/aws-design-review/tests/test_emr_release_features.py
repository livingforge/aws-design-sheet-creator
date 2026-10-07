import pytest
from aws_design_sheet.checks.emr.release_features import evaluate_emr_release_features
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def rows(version,**props):
    main=target('main','AWS::EMR::Cluster',ReleaseLabel=version,**props)
    return evaluate_emr_release_features(linked_design(main,[]),main)


@pytest.mark.parametrize('version,expected', [('emr-4.7.9','FAIL'),('emr-4.8.0','PASS'),('emr-4.10.0','PASS'),('emr-5.0.0','FAIL'),('emr-5.0.9','FAIL'),('emr-5.1.0','PASS'),('emr-7.0.0','PASS'),('emr-4.8','NEEDS_REVIEW'),('emr-5.0.0-custom','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
@pytest.mark.parametrize('kind',['MasterInstanceFleet','CoreInstanceFleet','TaskInstanceFleets'])
def test_fleet_gate(version,expected,kind):
    config={kind:[{}] if kind=='TaskInstanceFleets' else {}}
    assert rows(version,Instances=config)[0]['verdict']==expected


@pytest.mark.parametrize('version,expected',[('emr-5.12.0','FAIL'),('emr-5.12.1','PASS'),('emr-5.9.0','FAIL'),('emr-6.0.0','PASS'),(UNKNOWN,'NEEDS_REVIEW')])
def test_on_demand_gate(version,expected):
    actual=rows(version,Instances={'TaskInstanceFleets':[{'LaunchSpecifications':{'OnDemandSpecification':{'AllocationStrategy':'lowest-price'}}}]})
    assert next(f for f in actual if f['path'].endswith('AllocationStrategy'))['verdict']==expected


@pytest.mark.parametrize('version,behavior,expected',[
    ('emr-4.0.0','TERMINATE_AT_TASK_COMPLETION','FAIL'),('emr-4.1.0','TERMINATE_AT_TASK_COMPLETION','PASS'),
    ('emr-5.0.9','TERMINATE_AT_INSTANCE_HOUR','FAIL'),('emr-5.1.0','TERMINATE_AT_INSTANCE_HOUR','PASS'),
    ('emr-5.9.1','TERMINATE_AT_INSTANCE_HOUR','PASS'),('emr-5.10.0','TERMINATE_AT_INSTANCE_HOUR','NEEDS_REVIEW'),
    ('emr-7.0.0','TERMINATE_AT_TASK_COMPLETION','NEEDS_REVIEW'),('emr-5.1.0',UNKNOWN,'NEEDS_REVIEW'),
])
def test_scale_down_ambiguous_new_releases(version,behavior,expected):
    assert rows(version,ScaleDownBehavior=behavior)[0]['verdict']==expected


@pytest.mark.parametrize('version,role,strategy,expected',[
    ('emr-5.23.0','MASTER','SPREAD','PASS'),('emr-6.0.0','CORE','SPREAD','FAIL'),
    ('emr-6.0.0','TASK','SPREAD','FAIL'),('emr-6.0.0','MASTER','PARTITION','FAIL'),
    ('emr-6.0.0','MASTER','CLUSTER','FAIL'),('emr-6.0.0','MASTER','NONE','NEEDS_REVIEW'),
    ('emr-5.22.0','MASTER','SPREAD','NEEDS_REVIEW'),('emr-6.0.0',UNKNOWN,'SPREAD','NEEDS_REVIEW'),
])
def test_placement(version,role,strategy,expected):
    assert rows(version,PlacementGroupConfigs=[{'InstanceRole':role,'PlacementStrategy':strategy}])[0]['verdict']==expected


@pytest.mark.parametrize('props,expected',[
    ({'Configurations':[{}]},'PASS'),({'Configurations':UNKNOWN},'NEEDS_REVIEW'),
    ({'Instances':{'HadoopVersion':'2.4.0'}},'FAIL'),({'Instances':UNKNOWN},'NEEDS_REVIEW'),
    ({'PlacementGroupConfigs':UNKNOWN},'NEEDS_REVIEW')])
def test_known_release_and_unresolved_features(props,expected):
    actual=rows('emr-5.23.0',**props)
    assert actual and all(f['verdict']==expected for f in actual)


def test_empty_and_legacy_release():
    assert rows('emr-7.0.0',Configurations=[],PlacementGroupConfigs=[],Instances={'TaskInstanceFleets':[]})==[]
    assert rows('emr-3.0.0',Instances={'HadoopVersion':'2.4.0'})[0]['verdict']=='NEEDS_REVIEW'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    main=target('main','AWS::EMR::Cluster',ReleaseLabel='emr-5.0.0',Instances={'CoreInstanceFleet':{}})
    d=linked_design(main,[]);root=Path(__file__).resolve().parents[1]
    actual=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert any(f['rule_id']=='EMR_RELEASE_FEATURE_AVAILABILITY' and f['verdict']=='FAIL' for f in actual)
