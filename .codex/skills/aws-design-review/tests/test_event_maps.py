from pathlib import Path
import pytest
from aws_design_sheet.checks.eventsv2.maps import event_pattern, evaluate_eventsv2_maps
from aws_design_sheet.checks.fis.action_map_references import evaluate_fis_action_map_references
from aws_design_sheet.checks.codepipeline.artifact_bucket_region import evaluate_codepipeline_artifact_bucket_region
from aws_design_sheet.checks.registry import combine
event_maps_checks = combine(evaluate_eventsv2_maps, evaluate_fis_action_map_references, evaluate_codepipeline_artifact_bucket_region)
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('raw,expected',[
    ('{}','PASS'),('{"detail":{"source":["x"]}}','PASS'),('{"source":[]}','FAIL'),
    ('{"account":null}','FAIL'),('{"region":[]}','FAIL'),('{"so\\u0075rce":[]}','FAIL'),
    ('{"x":1,"x":2}','NEEDS_REVIEW'),('[]','FAIL'),('null','FAIL'),('{','FAIL'),
    ('{"x":NaN}','FAIL'),('${Pattern}','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW'),
    ('{"x":'+('['*130)+'0'+(']'*130)+'}','NEEDS_REVIEW'),(' '*3754,'NEEDS_REVIEW'),
],ids=['empty','nested','source','account','region','escaped','duplicate','array','null','syntax','nan','template','unknown','deep','long'])
def test_pattern(raw,expected):
    assert event_pattern(raw)==expected


@pytest.mark.parametrize('mode',['same','different','unknown','not_role','dynamic','unknown_account'])
def test_role_account(mode):
    raw=UNKNOWN if mode=='unknown' else {'Ref':'Role'} if mode=='dynamic' else 'arn:aws:iam::'+('222222222222' if mode=='different' else '111111111111')+(':user/user' if mode=='not_role' else ':role/path/role')
    r=target('main','AWS::EventsV2::Subscriber',InvokeConfiguration={'RoleArn':raw})
    if mode=='unknown_account':r.scope.account='unknown'
    assert event_maps_checks(linked_design(r),r)[0]['verdict']==('PASS' if mode=='same' else 'FAIL' if mode=='different' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('mode',['valid','missing_action','self','unknown_after','missing_target','unknown_target','unknown_actions','unknown_targets','unknown_action','empty_after','escaped','unknown_value'])
def test_fis_refs(mode):
    first='first/a~b' if mode=='escaped' else 'first'
    action={'StartAfter':[] if mode=='empty_after' else [UNKNOWN if mode=='unknown_after' else 'absent' if mode=='missing_action' else 'second' if mode=='self' else first],'Targets':{'Instances':'absent' if mode=='missing_target' else UNKNOWN if mode=='unknown_value' else 'nodes'}}
    if mode=='unknown_target':action['Targets']=UNKNOWN
    actions=UNKNOWN if mode=='unknown_actions' else {first:{'ActionId':'action'},'second':UNKNOWN if mode=='unknown_action' else action}
    r=target('main','AWS::FIS::ExperimentTemplate',Actions=actions,Targets=UNKNOWN if mode=='unknown_targets' else {'nodes':{}})
    expected='PASS' if mode in ('valid','empty_after') else 'FAIL' if mode in ('missing_action','self','missing_target') else 'NEEDS_REVIEW'
    assert event_maps_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('mode',['same','region','account','environment','literal','conditional','duplicate','unknown','ancestor','name_mismatch','other_type','plural_store'])
def test_bucket_region(mode):
    r=target('main','AWS::CodePipeline::Pipeline',ArtifactStore=UNKNOWN if mode=='ancestor' else {'Type':'S3','Location':UNKNOWN if mode=='unknown' else 'artifact-bucket'},**({'ArtifactStores':[]} if mode=='plural_store' else {}))
    bucket=target('bucket','AWS::S3::Bucket' if mode!='other_type' else 'AWS::SNS::Topic',BucketName='different' if mode=='name_mismatch' else 'artifact-bucket')
    links=[] if mode=='literal' else [('ArtifactStore/Location','bucket')]
    if mode=='duplicate':links=links*2
    d=linked_design(r,[bucket],links)
    if mode=='region':bucket.scope.region='us-east-1'
    if mode=='account':bucket.scope.account='222222222222'
    if mode=='environment':bucket.scope.environment='other'
    if mode=='conditional':d.relations[0].condition='Maybe'
    assert event_maps_checks(d,r)[0]['verdict']==('PASS' if mode=='same' else 'FAIL' if mode=='region' else 'NEEDS_REVIEW')


def test_checker_pattern():
    r=target('main','AWS::EventsV2::EventSource',Configuration={'AwsServiceEventsConfiguration':{'Pattern':'{"region":[]}'}})
    root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='EVENTSV2_SERVICE_PATTERN_FIELDS' and f['verdict']=='FAIL' for f in results)
