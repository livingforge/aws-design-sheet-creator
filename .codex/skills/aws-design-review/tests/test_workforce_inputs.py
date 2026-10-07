from pathlib import Path
import pytest
from aws_design_sheet.checks.sagemaker.profile_sso_and_workforce_vpc import evaluate_sagemaker_profile_sso_and_workforce_vpc
from aws_design_sheet.checks.pinpoint.apns_voip_auth_method import evaluate_pinpoint_apns_voip_auth_method
from aws_design_sheet.checks.registry import combine
workforce_inputs_checks = combine(evaluate_sagemaker_profile_sso_and_workforce_vpc, evaluate_pinpoint_apns_voip_auth_method)
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('mode,fields,expected',[
 ('SSO',{},'FAIL'),('SSO',{'SingleSignOnUserIdentifier':'UserName'},'FAIL'),
 ('SSO',{'SingleSignOnUserIdentifier':'UserName','SingleSignOnUserValue':'alice'},'PASS'),
 ('SSO',{'SingleSignOnUserIdentifier':UNKNOWN,'SingleSignOnUserValue':'alice'},'NEEDS_REVIEW'),
 ('IAM',{},'PASS'),('IAM',{'SingleSignOnUserValue':'alice'},'FAIL'),
 ('IAM',{'SingleSignOnUserValue':UNKNOWN},'NEEDS_REVIEW'),(UNKNOWN,{},'NEEDS_REVIEW'),
 ('sso',{},'NEEDS_REVIEW')],ids=['missing','half','both','unknown','iam','prohibited','iam_unknown','mode_unknown','mode_invalid'])
def test_sso(mode,fields,expected):
 r=target('main','AWS::SageMaker::UserProfile',DomainId='domain',**fields)
 d=linked_design(r,[target('domain','AWS::SageMaker::Domain',AuthMode=mode)],[('DomainId','domain')])
 assert workforce_inputs_checks(d,r)[0]['verdict']==expected


@pytest.mark.parametrize('case',['external','conditional','duplicate','wrong_type'])
def test_domain_links(case):
 r=target('main','AWS::SageMaker::UserProfile',DomainId='domain')
 domain=target('domain','AWS::S3::Bucket' if case=='wrong_type' else 'AWS::SageMaker::Domain',AuthMode='SSO')
 links=[] if case=='external' else [('DomainId','domain')]*(2 if case=='duplicate' else 1)
 d=linked_design(r,[domain],links)
 if case=='conditional':d.relations[0].condition='condition'
 assert workforce_inputs_checks(d,r)[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('case',['same','different','unknown','default','external','conditional','duplicate','invalid','wrong_type','empty','unknown_list'])
def test_vpc(case):
 config={'Subnets':['subnet'],'SecurityGroupIds':[] if case=='empty' else UNKNOWN if case=='unknown_list' else ['sg']}
 r=target('main','AWS::SageMaker::Workforce',WorkforceVpcConfig=config)
 s=target('subnet','AWS::EC2::Subnet',VpcId='vpc-12345678')
 owner='vpc-87654321' if case=='different' else UNKNOWN if case=='unknown' else 'invalid' if case=='invalid' else 'vpc-12345678'
 g=target('sg','AWS::S3::Bucket' if case=='wrong_type' else 'AWS::EC2::SecurityGroup',**({} if case=='default' else {'VpcId':owner}))
 links=[('WorkforceVpcConfig/Subnets/0','subnet')]+([] if case=='external' else [('WorkforceVpcConfig/SecurityGroupIds/0','sg')])
 if case=='duplicate':links.append(('WorkforceVpcConfig/SecurityGroupIds/0','sg'))
 d=linked_design(r,[s,g],links)
 if case=='conditional':d.relations[1].condition='condition'
 assert workforce_inputs_checks(d,r)[0]['verdict']==('PASS' if case=='same' else 'FAIL' if case=='different' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('raw,verdict',[('key','PASS'),('certificate','PASS'),('KEY','FAIL'),('TOKEN','FAIL'),(UNKNOWN,'NEEDS_REVIEW'),('${method}','NEEDS_REVIEW')])
def test_auth(raw,verdict):
 r=target('main','AWS::Pinpoint::APNSVoipChannel',DefaultAuthenticationMethod=raw)
 assert workforce_inputs_checks(linked_design(r),r)[0]['verdict']==verdict


@pytest.mark.parametrize('kind',['AWS::SageMaker::UserProfile','AWS::SageMaker::Workforce','AWS::Pinpoint::APNSVoipChannel'])
def test_absent(kind):
 r=target('main',kind);assert not workforce_inputs_checks(linked_design(r),r)


def test_checker():
 r=target('main','AWS::Pinpoint::APNSVoipChannel',DefaultAuthenticationMethod='KEY')
 root=Path(__file__).resolve().parents[1]
 results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
 assert any(f['rule_id']=='PINPOINT_APNS_VOIP_AUTH_METHOD' and f['verdict']=='FAIL' for f in results)
