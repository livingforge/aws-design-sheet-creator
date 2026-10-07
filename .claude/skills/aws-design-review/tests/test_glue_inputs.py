from pathlib import Path
import pytest
from aws_design_sheet.checks.glue.names_and_session_version import evaluate_glue_names_and_session_version
from aws_design_sheet.checks.gamelift.script_bucket_region import evaluate_gamelift_script_bucket_region
from aws_design_sheet.checks.registry import combine
glue_inputs_checks = combine(evaluate_glue_names_and_session_version, evaluate_gamelift_script_bucket_region)
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('kind',['Registry','Schema'])
@pytest.mark.parametrize('raw,expected',[
    ('Abc_09-$#','PASS'),('has.period','NEEDS_REVIEW'),('日本語','NEEDS_REVIEW'),
    ('bad/name','FAIL'),('has space','FAIL'),('colon:name','FAIL'),('bad@name','FAIL'),
    ('dot./slash','FAIL'),('日本/語','FAIL'),('name\n','FAIL'),('', 'NEEDS_REVIEW'),
    (UNKNOWN,'NEEDS_REVIEW'),({'Ref':'Name'},'NEEDS_REVIEW'),('a'*256,'NEEDS_REVIEW'),
])
def test_names(kind,raw,expected):
    r=target('main','AWS::Glue::'+kind,Name=raw)
    assert glue_inputs_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('raw,expected',[
    ('1.9','FAIL'),('0.0','FAIL'),('2.0','FAIL'),('2.1','PASS'),('3.0','PASS'),('10.0','PASS'),
    ('2.10','PASS'),('2.00','NEEDS_REVIEW'),('02.1','NEEDS_REVIEW'),('2','NEEDS_REVIEW'),
    ('3.0.0','NEEDS_REVIEW'),('3.x','NEEDS_REVIEW'),(' 3.0','NEEDS_REVIEW'),
    ('3.0\n','NEEDS_REVIEW'),('9'*40+'.0','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW'),(3.0,'NEEDS_REVIEW'),
])
def test_version(raw,expected):
    r=target('main','AWS::Glue::Session',GlueVersion=raw)
    assert glue_inputs_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('mode',['same','region','account','environment','name','unknown','ancestor','conditional','ambiguous','missing','wrong_type','template','bucket_template','scope'])
def test_bucket(mode):
    from aws_design_sheet.models import TemplateContext
    r=target('main','AWS::GameLift::Script',StorageLocation=UNKNOWN if mode=='ancestor' else {'Bucket':UNKNOWN if mode=='unknown' else 'my-bucket'})
    b=target('bucket','AWS::S3::Bucket',BucketName='other-name' if mode=='name' else 'my-bucket')
    d=linked_design(r,[b],[] if mode=='missing' else [('StorageLocation/Bucket','bucket')])
    if mode in ('region','account','environment'):setattr(b.scope,mode,{'region':'us-east-1','account':'222222222222','environment':'other'}[mode])
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='ambiguous':d.relations.append(d.relations[0].model_copy(update={'id':'duplicate'}))
    if mode=='wrong_type':b.type='AWS::SNS::Topic'
    if mode=='template':r.template=TemplateContext(state='UNRESOLVED')
    if mode=='bucket_template':b.template=TemplateContext(state='UNRESOLVED')
    if mode=='scope':b.scope.account='unknown'
    assert glue_inputs_checks(d,r)[0]['verdict']==('PASS' if mode in ('same','account') else 'FAIL' if mode=='region' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('kind',['AWS::Glue::Registry','AWS::Glue::Schema','AWS::Glue::Session','AWS::GameLift::Script'])
def test_omitted(kind):
    r=target('main',kind)
    assert not glue_inputs_checks(linked_design(r),r)


def test_checker_session():
    r=target('main','AWS::Glue::Session',GlueVersion='2.0')
    root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='GLUE_SESSION_VERSION_FLOOR' and f['verdict']=='FAIL' for f in results)
