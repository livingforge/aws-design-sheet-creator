from pathlib import Path
import pytest
from aws_design_sheet.checks.imagebuilder.tag_prefix import evaluate_imagebuilder_tag_prefix, VERSIONS
from aws_design_sheet.checks.iot.fleet_metric_period import evaluate_iot_fleet_metric_period
from aws_design_sheet.checks.ivs.encoder_configuration import evaluate_ivs_encoder_configuration
from aws_design_sheet.checks.lakeformation.permission_grants import evaluate_lakeformation_permission_grants, GRANTS
from aws_design_sheet.checks.registry import combine
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
dimensions_checks=combine(evaluate_imagebuilder_tag_prefix,evaluate_iot_fleet_metric_period,evaluate_ivs_encoder_configuration,evaluate_lakeformation_permission_grants)


def check(kind,**props):
    r=target('subject','AWS::'+kind,**props)
    return dimensions_checks(linked_design(r),r)


@pytest.mark.parametrize('kind',list(VERSIONS))
@pytest.mark.parametrize('version,expected',[
    ('0.0.0','PASS'),('1073741823.1073741823.1073741823','PASS'),('1073741824.0.0','FAIL'),
    ('0.1073741824.0','FAIL'),('0.0.1073741824','FAIL'),('00001.02.000000003','PASS'),
    ('1.x.x','NEEDS_REVIEW'),('1.0.0/1','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW'),
    ('9'*5000+'.0.0','FAIL')])
def test_version_nodes(kind,version,expected):
    assert check('ImageBuilder::'+kind,Version=version)[0]['verdict']==expected


@pytest.mark.parametrize('tags,expected',[
    ({'aws:thing':'x'},'FAIL'),({'myaws:thing':UNKNOWN},'PASS'),({'AWS:thing':'x'},'NEEDS_REVIEW'),
    ({'aws:foo/bar':'x'},'FAIL'),({'aws':UNKNOWN},'PASS'),({'${Key}':'x'},'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_resource_tag_prefix(tags,expected):
    assert check('ImageBuilder::InfrastructureConfiguration',ResourceTags=tags)[0]['verdict']==expected


@pytest.mark.parametrize('period,expected',[(60,'PASS'),(86400,'PASS'),(61,'FAIL'),(119,'FAIL'),(True,'NEEDS_REVIEW'),('60','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_metric_period(period,expected):
    assert check('IoT::FleetMetric',Period=period)[0]['verdict']==expected


@pytest.mark.parametrize('video,expected',[
    ({'Width':1920,'Height':1080},'PASS'),({'Width':1080,'Height':1920},'PASS'),
    ({'Width':1920,'Height':1082},'FAIL'),({'Width':1920,'Height':1920},'FAIL'),
    ({'Height':1920},'FAIL'),({'Width':1920},'PASS'),({},'PASS'),
    ({'Height':UNKNOWN},'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW'),({'Height':True},'NEEDS_REVIEW')])
def test_pixel_limit(video,expected):
    row=next(x for x in check('IVS::EncoderConfiguration',Video=video) if x['rule_id']=='IVS_VIDEO_PIXEL_LIMIT')
    assert row['verdict']==expected


@pytest.mark.parametrize('key',['Width','Height'])
@pytest.mark.parametrize('n,expected',[(1080,'PASS'),(1079,'FAIL'),(True,'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_even_dimensions(key,n,expected):
    row=next(x for x in check('IVS::EncoderConfiguration',Video={key:n}) if x['rule_id']=='IVS_VIDEO_EVEN')
    assert row['verdict']==expected


@pytest.mark.parametrize('kind',list(GRANTS))
@pytest.mark.parametrize('granted,delegable,expected',[
    (['SELECT','ALTER'],['SELECT'],'PASS'),(['SELECT'],['ALTER'],'FAIL'),
    (['SELECT',UNKNOWN],['SELECT'],'PASS'),(['SELECT',UNKNOWN],['ALTER'],'NEEDS_REVIEW'),
    (['SELECT'],UNKNOWN,'NEEDS_REVIEW'),(['ALL'],['SELECT'],'NEEDS_REVIEW'),
    (['SELECT'],['ALL'],'NEEDS_REVIEW'),(['ALL'],['ALL'],'PASS'),
    (['SELECT'],[],'PASS'),([],['SELECT'],'FAIL'),(UNKNOWN,['SELECT'],'NEEDS_REVIEW')])
def test_grant_subset(kind,granted,delegable,expected):
    assert check('LakeFormation::'+kind,Permissions=granted,PermissionsWithGrantOption=delegable)[0]['verdict']==expected


def test_missing_granted_permissions_held():
    assert check('LakeFormation::Permissions',PermissionsWithGrantOption=['SELECT'])[0]['verdict']=='NEEDS_REVIEW'


def test_checker_integration():
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('subject','AWS::IVS::EncoderConfiguration',Video={'Width':1920,'Height':1920})
    result=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))
    row=next(x for x in result['results'] if x['rule_id']=='IVS_VIDEO_PIXEL_LIMIT')
    assert row['verdict']=='FAIL' and row['source_urls'] and row['evidence_ids']
