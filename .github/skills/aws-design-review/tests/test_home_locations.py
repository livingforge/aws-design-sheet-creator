from pathlib import Path
import pytest
from aws_design_sheet.checks.fsx.dra_local_paths import canonical_path, evaluate_fsx_dra_local_paths
from aws_design_sheet.checks.forecast.encryption_role_account import evaluate_forecast_encryption_role_account
from aws_design_sheet.checks.gamelift.home_locations import evaluate_gamelift_home_locations
from aws_design_sheet.checks.registry import combine
home_locations_checks = combine(evaluate_forecast_encryption_role_account, evaluate_gamelift_home_locations, evaluate_fsx_dra_local_paths)
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('mode',['same','different','unknown','wrong_service','dynamic'])
def test_role(mode):
    raw=UNKNOWN if mode=='unknown' else {'Ref':'Role'} if mode=='dynamic' else 'arn:aws:'+('sts' if mode=='wrong_service' else 'iam')+'::'+('222222222222' if mode=='different' else '111111111111')+':role/path/role'
    r=target('main','AWS::Forecast::Dataset',EncryptionConfig={'RoleArn':raw})
    assert home_locations_checks(linked_design(r),r)[0]['verdict']==('PASS' if mode=='same' else 'FAIL' if mode=='different' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('kind,compute',[('ContainerFleet',None),('Fleet','EC2'),('Fleet','ANYWHERE'),('Fleet',None)])
@pytest.mark.parametrize('mode',['home','missing','empty','unknown_member','unknown_array','unknown_scope'])
def test_home(kind,compute,mode):
    locations=UNKNOWN if mode=='unknown_array' else [] if mode=='empty' else [{'Location':UNKNOWN if mode=='unknown_member' else 'us-east-1' if mode=='missing' else 'ap-northeast-1'}]
    r=target('main','AWS::GameLift::'+kind,Locations=locations,**({'ComputeType':compute} if compute else {}))
    if mode=='unknown_scope':r.scope.region='unknown'
    expected='NEEDS_REVIEW' if (kind=='Fleet' and compute!='EC2') or mode in ('unknown_member','unknown_array','unknown_scope') else 'PASS' if mode=='home' else 'FAIL'
    assert home_locations_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('path,expected',[('/',()),('/a',('a',)),('/a/',('a',)),('/a/b',('a','b')),('/a//b',None),('/a/../b',None),('/a/./b',None),('a',None),('/a\\b',None),(UNKNOWN,None)])
def test_path_normalization(path,expected):
    assert canonical_path(path)==expected


@pytest.mark.parametrize('mode',['child','parent','root','boundary','alias','nine','eight','conditional','scope','unknown','template'])
def test_dra_paths(mode):
    from aws_design_sheet.models import Relation
    own='/a/b' if mode=='parent' else '/' if mode=='root' else '/a'
    r=target('main','AWS::FSx::DataRepositoryAssociation',FileSystemId='fs',FileSystemPath=own)
    fs=target('fs','AWS::FSx::FileSystem')
    paths=['/b'+str(i) for i in range(8 if mode=='nine' else 7)] if mode in ('nine','eight') else [UNKNOWN if mode=='unknown' else '/a' if mode in ('parent','alias') else '/ab' if mode=='boundary' else '/a/b']
    others=[target('dra'+str(i),'AWS::FSx::DataRepositoryAssociation',FileSystemId='fs',FileSystemPath=p) for i,p in enumerate(paths)]
    d=linked_design(r,[fs]+others,[('FileSystemId','fs')])
    for other in others:d.relations.append(Relation(id=other.id+'-fs',source_resource_id=other.id,source_path='/properties/FileSystemId',target_resource_id='fs',evidence_ids=[],condition='Maybe' if mode=='conditional' else None))
    if mode=='scope':others[0].scope.region='us-east-1'
    if mode=='template':
        from aws_design_sheet.models import TemplateContext
        r.template=TemplateContext(state='UNRESOLVED')
    assert home_locations_checks(d,r)[0]['verdict']==('FAIL' if mode in ('child','parent','root','nine') else 'NEEDS_REVIEW')


def test_checker_home():
    r=target('main','AWS::GameLift::ContainerFleet',Locations=[{'Location':'us-east-1'}])
    root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='GAMELIFT_CONTAINER_HOME_LOCATION' and f['verdict']=='FAIL' for f in results)
