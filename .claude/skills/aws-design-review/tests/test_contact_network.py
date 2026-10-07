from pathlib import Path
import pytest
from aws_design_sheet.checks.ssmcontacts.rotation_personal_contact import evaluate_ssmcontacts_rotation_personal_contact
from aws_design_sheet.checks.sagemaker.domain_subnet_ipv6 import evaluate_sagemaker_domain_subnet_ipv6
from aws_design_sheet.checks.s3vectors.bucket_key_type import evaluate_s3vectors_bucket_key_type
from aws_design_sheet.checks.registry import combine
contact_network_checks = combine(evaluate_ssmcontacts_rotation_personal_contact, evaluate_sagemaker_domain_subnet_ipv6, evaluate_s3vectors_bucket_key_type)
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('case',['personal','escalation','oncall','unknown','default','external','conditional','duplicate','wrong_type'])
def test_contact(case):
 r=target('main','AWS::SSMContacts::Rotation',ContactIds=['contact'])
 kind='ESCALATION' if case=='escalation' else 'ONCALL_SCHEDULE' if case=='oncall' else UNKNOWN if case=='unknown' else 'PERSONAL'
 c=target('contact','AWS::S3::Bucket' if case=='wrong_type' else 'AWS::SSMContacts::Contact',**({} if case=='default' else {'Type':kind}))
 links=[] if case=='external' else [('ContactIds/0','contact')]
 if case=='duplicate':links+=links
 d=linked_design(r,[c],links)
 if case=='conditional':d.relations[0].condition='condition'
 assert contact_network_checks(d,r)[0]['verdict']==('PASS' if case=='personal' else 'FAIL' if case in ('escalation','oncall') else 'NEEDS_REVIEW')


@pytest.mark.parametrize('case',['ipv6','ipv4','invalid','unknown','omitted','external','lowercase','ipv4mode','conditional'])
def test_subnet(case):
 r=target('main','AWS::SageMaker::Domain',DomainSettings={'IpAddressType':'dualstack' if case=='lowercase' else 'IPV4' if case=='ipv4mode' else 'DUALSTACK'},SubnetIds=['subnet'])
 cidr='10.0.0.0/24' if case=='ipv4' else 'bad' if case=='invalid' else UNKNOWN if case=='unknown' else '2001:db8::/64'
 s=target('subnet','AWS::EC2::Subnet',**({} if case=='omitted' else {'Ipv6CidrBlock':cidr}))
 d=linked_design(r,[s],[] if case=='external' else [('SubnetIds/0','subnet')])
 if case=='conditional':d.relations[0].condition='condition'
 assert contact_network_checks(d,r)[0]['verdict']==('PASS' if case=='ipv6' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('spec,verdict',[('SYMMETRIC_DEFAULT','PASS'),('RSA_2048','FAIL'),('ECC_NIST_P256','FAIL'),('HMAC_256','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_key(spec,verdict):
 r=target('main','AWS::S3Vectors::VectorBucket',EncryptionConfiguration={'SseType':'aws:kms','KmsKeyArn':'key'})
 k=target('key','AWS::KMS::Key',KeySpec=spec)
 assert contact_network_checks(linked_design(r,[k],[('EncryptionConfiguration/KmsKeyArn','key')]),r)[0]['verdict']==verdict


@pytest.mark.parametrize('kind',['AWS::SSMContacts::Rotation','AWS::SageMaker::Domain','AWS::S3Vectors::VectorBucket'])
def test_absent(kind):
 r=target('main',kind);assert not contact_network_checks(linked_design(r),r)


def test_checker():
 r=target('main','AWS::SSMContacts::Rotation',ContactIds=['contact']);c=target('contact','AWS::SSMContacts::Contact',Type='ESCALATION')
 root=Path(__file__).resolve().parents[1]
 results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r,[c],[('ContactIds/0','contact')]))['results']
 assert any(f['rule_id']=='SSM_ROTATION_PERSONAL_CONTACT' and f['verdict']=='FAIL' for f in results)
