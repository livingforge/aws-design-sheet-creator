import pytest
from aws_design_sheet.checks.eventsv2.maps import evaluate_eventsv2_maps
from aws_design_sheet.checks.fis.action_map_references import evaluate_fis_action_map_references
from aws_design_sheet.checks.codepipeline.artifact_bucket_region import evaluate_codepipeline_artifact_bucket_region
from aws_design_sheet.checks.registry import combine
event_maps_checks = combine(evaluate_eventsv2_maps, evaluate_fis_action_map_references, evaluate_codepipeline_artifact_bucket_region)
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN
from test_template_dependencies import link


@pytest.mark.parametrize('case,want', [('same','PASS'),('wrong_region','FAIL'),('other_account','NEEDS_REVIEW'),('unknown_region','NEEDS_REVIEW'),('unknown_name','NEEDS_REVIEW'),('wrong_name','NEEDS_REVIEW'),('conditional','NEEDS_REVIEW'),('external','NEEDS_REVIEW'),('duplicate','NEEDS_REVIEW'),('both_stores','NEEDS_REVIEW'),('reference_only','PASS')])
def test_mapped_store(case,want):
    store={'Type':'S3'}
    if case!='reference_only':store['Location']=UNKNOWN if case=='unknown_name' else 'artifacts-test'
    entry={'Region':UNKNOWN if case=='unknown_region' else 'us-east-1','ArtifactStore':store}
    r=target('pipeline','AWS::CodePipeline::Pipeline',ArtifactStores=[entry],**({'ArtifactStore':{'Type':'S3'}} if case=='both_stores' else {}))
    b=target('bucket','AWS::S3::Bucket',BucketName='other-bucket' if case=='wrong_name' else 'artifacts-test')
    b.scope.region='us-west-2' if case=='wrong_region' else 'us-east-1'
    if case=='other_account':b.scope.account='222222222222'
    d=linked_design(r,[b])
    if case!='external':link(d,r,'ArtifactStores/0/ArtifactStore/Location',b,'maybe' if case=='conditional' else None)
    if case=='duplicate':link(d,r,'ArtifactStores/0/ArtifactStore/Location',b)
    assert event_maps_checks(d,r)[0]['verdict']==want


@pytest.mark.parametrize('stores', [UNKNOWN,'invalid',[UNKNOWN]])
def test_unknown_store_collection(stores):
    r=target('pipeline','AWS::CodePipeline::Pipeline',ArtifactStores=stores)
    findings=event_maps_checks(linked_design(r),r)
    assert findings and all(f['verdict']=='NEEDS_REVIEW' for f in findings)


def test_distinct_regions_are_checked_separately():
    r=target('pipeline','AWS::CodePipeline::Pipeline',ArtifactStores=[{'Region':'ap-northeast-1','ArtifactStore':{'Type':'S3'}},{'Region':'us-east-1','ArtifactStore':{'Type':'S3'}}])
    home=target('home','AWS::S3::Bucket');away=target('away','AWS::S3::Bucket');away.scope.region='us-east-1'
    d=linked_design(r,[home,away]);link(d,r,'ArtifactStores/0/ArtifactStore/Location',home);link(d,r,'ArtifactStores/1/ArtifactStore/Location',away)
    findings=event_maps_checks(d,r)
    assert [f['verdict'] for f in findings]==['PASS','PASS']
    assert findings[0]['path']!=findings[1]['path']


def test_single_store_reference_only():
    r=target('pipeline','AWS::CodePipeline::Pipeline',ArtifactStore={'Type':'S3'})
    b=target('bucket','AWS::S3::Bucket')
    d=linked_design(r,[b]);link(d,r,'ArtifactStore/Location',b)
    assert event_maps_checks(d,r)[0]['verdict']=='PASS'
