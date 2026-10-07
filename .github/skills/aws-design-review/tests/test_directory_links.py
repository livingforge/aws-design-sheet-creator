from pathlib import Path
import pytest
from aws_design_sheet.checks.directconnect.lag_bandwidth import evaluate_directconnect_lag_bandwidth
from aws_design_sheet.checks.directoryservice.edition_size_and_subnets import evaluate_directoryservice_edition_size_and_subnets
from aws_design_sheet.checks.codebuild.credential_arn_kind import evaluate_codebuild_credential_arn_kind
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN
from aws_design_sheet.checks.registry import combine
directory_links_checks=combine(evaluate_directconnect_lag_bandwidth,evaluate_directoryservice_edition_size_and_subnets,evaluate_codebuild_credential_arn_kind)


@pytest.mark.parametrize('kind,field,allowed',[
    ('DirectConnect::Lag','ConnectionsBandwidth',['1Gbps','10Gbps','100Gbps','400Gbps']),
    ('DirectoryService::SimpleAD','Size',['Small','Large']),
])
@pytest.mark.parametrize('case',['valid','invalid','unknown','intrinsic','empty','omitted'])
def test_enums(kind,field,allowed,case):
    for valid in allowed:
        raw={'valid':valid,'invalid':'unsupported','unknown':UNKNOWN,'intrinsic':{'Ref':'Input'},'empty':''}.get(case)
        r=target('main','AWS::'+kind,**({} if case=='omitted' else {field:raw}))
        results=directory_links_checks(linked_design(r),r)
        if case=='omitted':assert results==[]
        else:assert results[0]['verdict']==('PASS' if case=='valid' else 'FAIL' if case=='invalid' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('kind',['MicrosoftAD','SimpleAD'])
@pytest.mark.parametrize('mode',['different','same','literal','conditional','scope','unknown','azid','count','ancestor','duplicate'])
def test_subnets(kind,mode):
    r=target('main','AWS::DirectoryService::'+kind,VpcSettings=UNKNOWN if mode=='ancestor' else {'SubnetIds':['one'] if mode=='count' else ['one','two']})
    a=target('one','AWS::EC2::Subnet',AvailabilityZone='ap-northeast-1a')
    b=target('two','AWS::EC2::Subnet',AvailabilityZone='ap-northeast-1a' if mode=='same' else UNKNOWN if mode=='unknown' else 'apne1-az1' if mode=='azid' else 'ap-northeast-1c')
    links=[] if mode=='literal' else [('VpcSettings/SubnetIds/0','one'),('VpcSettings/SubnetIds/1','two')]
    if mode=='duplicate':links.append(('VpcSettings/SubnetIds/1','one'))
    d=linked_design(r,[a,b],links)
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='scope':b.scope.region='us-east-1'
    results=[f for f in directory_links_checks(d,r) if f['rule_id'].endswith('SUBNET_AZS')]
    assert results[0]['verdict']==('PASS' if mode=='different' else 'FAIL' if mode=='same' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('auth',['CODECONNECTIONS','SECRETS_MANAGER'])
@pytest.mark.parametrize('service,resource',[
    ('codeconnections','connection/example'),('codestar-connections','connection/example'),
    ('secretsmanager','secret:example-abcdef'),('codeconnections','host/example'),
    ('secretsmanager','connection/example'),('s3','secret:example'),
])
def test_credential_arn(auth,service,resource):
    token=f'arn:aws:{service}:ap-northeast-1:111111111111:{resource}'
    r=target('main','AWS::CodeBuild::SourceCredential',AuthType=auth,Token=token)
    f=directory_links_checks(linked_design(r),r)[0]
    valid=(auth=='CODECONNECTIONS' and service in ('codeconnections','codestar-connections') and resource.startswith('connection/')) or (auth=='SECRETS_MANAGER' and service=='secretsmanager' and resource.startswith('secret:'))
    assert f['verdict']==('PASS' if valid else 'FAIL')
    assert token not in str(f)


@pytest.mark.parametrize('auth',['CODECONNECTIONS','SECRETS_MANAGER'])
@pytest.mark.parametrize('raw',[UNKNOWN,{'Ref':'Secret'},'{{resolve:secretsmanager:example}}','${Token}','plaintext',None],ids=['unknown','ref','dynamic','template','plain','missing'])
def test_credential_unresolved(auth,raw):
    r=target('main','AWS::CodeBuild::SourceCredential',AuthType=auth,**({} if raw is None else {'Token':raw}))
    result=directory_links_checks(linked_design(r),r)
    if raw is None:assert result==[]
    else:assert result[0]['verdict']==('FAIL' if raw=='plaintext' else 'NEEDS_REVIEW')


def test_checker_integration():
    r=target('main','AWS::DirectoryService::SimpleAD',Size='invalid')
    root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='SIMPLEAD_SIZE' and f['verdict']=='FAIL' for f in results)
