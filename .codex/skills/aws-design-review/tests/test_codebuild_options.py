import pytest
from aws_design_sheet.checks.codebuild.options import evaluate_codebuild_options
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def check(props, suffix):
    r = target('build','AWS::CodeBuild::Project',**props)
    return next(f['verdict'] for f in evaluate_codebuild_options(linked_design(r),r) if f['path'].endswith(suffix))


@pytest.mark.parametrize('kind,want', [('S3','FAIL'), ('CODEPIPELINE','NOT_APPLICABLE'), ('NO_ARTIFACTS','NOT_APPLICABLE'), (UNKNOWN,'NEEDS_REVIEW')])
@pytest.mark.parametrize('field', ['Packaging','NamespaceType'])
@pytest.mark.parametrize('secondary', [False,True])
def test_artifact_ignored_options(kind,want,field,secondary):
    artifact = {'Type':kind,field:'invalid'}
    props = {'SecondaryArtifacts':[artifact]} if secondary else {'Artifacts':artifact}
    assert check(props,field) == want


@pytest.mark.parametrize('kind,want', [('LOCAL','FAIL'), ('S3','NOT_APPLICABLE'), ('NO_CACHE','NOT_APPLICABLE'), (UNKNOWN,'NEEDS_REVIEW')])
def test_local_cache_modes(kind,want):
    assert check({'Cache':{'Type':kind,'Modes':['invalid']}},'/Modes/0') == want


@pytest.mark.parametrize('kind,want', [('LINUX_CONTAINER','FAIL'), ('ARM_EC2','FAIL'), ('WINDOWS_EC2','NOT_APPLICABLE'), ('MAC_ARM','NOT_APPLICABLE'), ('LINUX_LAMBDA_CONTAINER','NOT_APPLICABLE'), ('LINUX_GPU_CONTAINER','NEEDS_REVIEW'), (UNKNOWN,'NEEDS_REVIEW')])
def test_host_kernel_context(kind,want):
    assert check({'Environment':{'Type':kind,'HostKernel':'invalid'}},'HostKernel') == want


@pytest.mark.parametrize('source,report,want', [('GITHUB',True,'FAIL'), ('BITBUCKET',True,'FAIL'), ('GITHUB',False,'NOT_APPLICABLE'), ('GITLAB',True,'NEEDS_REVIEW'), ('GITHUB',UNKNOWN,'NEEDS_REVIEW')])
def test_batch_report_context(source,report,want):
    assert check({'Source':{'Type':source,'ReportBuildStatus':report},'BuildBatchConfig':{'BatchReportMode':'invalid'}},'BatchReportMode') == want


@pytest.mark.parametrize('raw,want', [('PUBLIC_READ','PASS'), ('PRIVATE','PASS'), ('invalid','FAIL'), ('','NEEDS_REVIEW'), (UNKNOWN,'NEEDS_REVIEW')])
def test_visibility(raw,want):
    assert check({'Visibility':raw},'Visibility') == want


@pytest.mark.parametrize('props,suffix', [
    ({'Source':{'Auth':{'Type':'CODECONNECTIONS'}}},'Type'),
    ({'SecondarySources':[{'Auth':{'Type':'SECRETS_MANAGER'}}]},'Type'),
    ({'Environment':{'EnvironmentVariables':[{'Type':'PARAMETER_STORE'}]}},'Type'),
    ({'Environment':{'RegistryCredential':{'CredentialProvider':'SECRETS_MANAGER'}}},'CredentialProvider'),
    ({'LogsConfig':{'CloudWatchLogs':{'Status':'ENABLED'}}},'Status'),
    ({'LogsConfig':{'S3Logs':{'Status':'DISABLED'}}},'Status'),
    ({'FileSystemLocations':[{'Type':'EFS'}]},'Type'),
    ({'Triggers':{'BuildType':'BUILD_BATCH'}},'BuildType'),
    ({'Artifacts':{'Type':'S3','Packaging':'ZIP'}},'Packaging'),
    ({'Artifacts':{'Type':'S3','NamespaceType':'BUILD_ID'}},'NamespaceType'),
    ({'Cache':{'Type':'LOCAL','Modes':['LOCAL_CUSTOM_CACHE']}},'/Modes/0'),
    ({'Environment':{'Type':'ARM_CONTAINER','HostKernel':'LINUX_KERNEL_LATEST'}},'HostKernel'),
])
def test_explicit_valid_options(props,suffix):
    assert check(props,suffix) == 'PASS'


def test_unknown_ancestor():
    r = target('build','AWS::CodeBuild::Project',Environment=UNKNOWN)
    results = evaluate_codebuild_options(linked_design(r),r)
    assert results and all(f['verdict'] == 'NEEDS_REVIEW' for f in results)


@pytest.mark.parametrize('field,maximum', [('SecondarySources',12),('SecondarySourceVersions',12),('SecondaryArtifacts',12),('Tags',50)])
@pytest.mark.parametrize('offset', [-12,0,1])
def test_collection_bounds(field,maximum,offset):
    assert check({field:[UNKNOWN]*(maximum+offset)},'/'+field) == ('FAIL' if offset>0 else 'PASS')


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    r = target('build','AWS::CodeBuild::Project',Visibility='PRIVATE')
    root = Path(__file__).resolve().parents[1]
    results = Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='CODEBUILD_PROJECT_OPTION_ENUMS' and f['verdict']=='PASS' for f in results)
