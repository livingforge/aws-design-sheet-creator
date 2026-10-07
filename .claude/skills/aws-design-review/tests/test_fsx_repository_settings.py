import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.fsx.repository_settings import evaluate_fsx_repository_settings
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link


@pytest.mark.parametrize('key,v',[('AutoImportPolicy','NONE'),('ExportPath','s3://bucket/export'),('ImportedFileChunkSize',1024),('ImportPath','s3://bucket'),('CopyTagsToBackups',True)])
@pytest.mark.parametrize('mode',['explicit','absent','unknown','conditional','external','scope','template','parent_unknown'])
def test_repository_exclusion(key,v,mode):
    config={} if mode=='absent' else {key:UNKNOWN if mode=='unknown' else v}
    r=target('fs','AWS::FSx::FileSystem',FileSystemType='LUSTRE',LustreConfiguration=UNKNOWN if mode=='parent_unknown' else config)
    a=target('association','AWS::FSx::DataRepositoryAssociation',FileSystemId='fs')
    d=linked_design(r,[a]);link(d,a,'FileSystemId',r)
    if mode=='conditional':d.relations[0].condition='maybe'
    if mode=='external':d.relations=[]
    if mode=='scope':a.scope.region='us-east-1'
    if mode=='template':a.template=TemplateContext(state='UNRESOLVED')
    found=next(f for f in evaluate_fsx_repository_settings(d,r) if f['path'].endswith('/'+key))
    assert found['verdict']==('FAIL' if mode=='explicit' else 'PASS' if mode=='absent' else 'NEEDS_REVIEW')


def test_disabled_copy_tags_is_not_assumed_equivalent_to_omission():
    r=target('fs','AWS::FSx::FileSystem',FileSystemType='LUSTRE',LustreConfiguration={'CopyTagsToBackups':False})
    a=target('association','AWS::FSx::DataRepositoryAssociation',FileSystemId='fs');d=linked_design(r,[a]);link(d,a,'FileSystemId',r)
    assert evaluate_fsx_repository_settings(d,r)[-1]['verdict']=='NEEDS_REVIEW'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('fs','AWS::FSx::FileSystem',FileSystemType='LUSTRE',LustreConfiguration={'ImportPath':'s3://bucket'})
    a=target('association','AWS::FSx::DataRepositoryAssociation',FileSystemId='fs');d=linked_design(r,[a]);link(d,a,'FileSystemId',r)
    assert any(f['rule_id']=='FSX_LUSTRE_REPOSITORY_SETTINGS' and f['verdict']=='FAIL' for f in Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results'])
