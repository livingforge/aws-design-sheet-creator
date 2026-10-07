import pytest
from aws_design_sheet.checks.sagemaker.notebook_hooks_and_vpc import evaluate_sagemaker_notebook_hooks_and_vpc
from aws_design_sheet.checks.pinpoint.apns_sandbox_auth_method import evaluate_pinpoint_apns_sandbox_auth_method
from aws_design_sheet.checks.registry import combine
notebook_inputs_checks = combine(evaluate_sagemaker_notebook_hooks_and_vpc, evaluate_pinpoint_apns_sandbox_auth_method)
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('case',['same','different','unknown','default','external','conditional','duplicate','invalid','wrong_type'])
def test_vpc(case):
 r=target('main','AWS::SageMaker::NotebookInstance',SubnetId='subnet',SecurityGroupIds=['sg'])
 s=target('subnet','AWS::EC2::Subnet',VpcId='vpc-12345678')
 owner='vpc-87654321' if case=='different' else UNKNOWN if case=='unknown' else 'invalid' if case=='invalid' else 'vpc-12345678'
 g=target('sg','AWS::S3::Bucket' if case=='wrong_type' else 'AWS::EC2::SecurityGroup',**({} if case=='default' else {'VpcId':owner}))
 links=[('SubnetId','subnet')]+([] if case=='external' else [('SecurityGroupIds/0','sg')])
 if case=='duplicate':links.append(('SecurityGroupIds/0','sg'))
 d=linked_design(r,[s,g],links)
 if case=='conditional':d.relations[1].condition='condition'
 assert notebook_inputs_checks(d,r)[0]['verdict']==('PASS' if case=='same' else 'FAIL' if case=='different' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('raw,verdict',[('key','PASS'),('certificate','PASS'),('KEY','FAIL'),('TOKEN','FAIL'),(UNKNOWN,'NEEDS_REVIEW'),('${method}','NEEDS_REVIEW')])
def test_auth(raw,verdict):
 r=target('main','AWS::Pinpoint::APNSSandboxChannel',DefaultAuthenticationMethod=raw)
 assert notebook_inputs_checks(linked_design(r),r)[0]['verdict']==verdict


@pytest.mark.parametrize('kind',['AWS::SageMaker::NotebookInstance','AWS::Pinpoint::APNSSandboxChannel'])
def test_absent(kind):
 r=target('main',kind);assert not notebook_inputs_checks(linked_design(r),r)
