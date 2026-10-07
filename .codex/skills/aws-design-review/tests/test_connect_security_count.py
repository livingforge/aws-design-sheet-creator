import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.connect.security_count import evaluate_connect_security_count
from test_autoscaling_group_and_scaling_policy import target,linked_design
from test_template_dependencies import link


@pytest.fixture(scope='module')
def keys():
    return [ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode() for _ in range(3)]


@pytest.mark.parametrize('mode',['arn','linked','conditional','template','region','duplicate','pem_format_duplicate','unknown_key','different_instance'])
def test_declared_limit(keys,mode):
    arn='arn:aws:connect:ap-northeast-1:111111111111:instance/abc-123'
    rows=[target('key'+str(i),'AWS::Connect::SecurityKey',InstanceId=arn,Key=k) for i,k in enumerate(keys)]
    instance=target('instance','AWS::Connect::Instance');d=linked_design(rows[0],rows[1:]+[instance],[])
    if mode in ('linked','conditional'):
        for r in rows:link(d,r,'InstanceId',instance,'maybe' if mode=='conditional' and r is rows[-1] else None)
    if mode=='template':rows[-1].template=TemplateContext(state='UNRESOLVED')
    if mode=='region':rows[-1].scope.region='us-east-1'
    if mode=='different_instance':rows[-1].fields[0].candidates[0].value=arn+'different'
    if mode in ('duplicate','pem_format_duplicate','unknown_key'):
        raw={'$state':'UNRESOLVED'} if mode=='unknown_key' else keys[0].replace('\n','\r\n') if mode=='pem_format_duplicate' else keys[0]
        next(f for f in rows[-1].fields if f.path=='/properties/Key').candidates[0].value=raw
    assert evaluate_connect_security_count(d,rows[0])[0]['verdict']==('FAIL' if mode in ('arn','linked') else 'NEEDS_REVIEW')


def test_two_declared_keys_are_not_complete_live_inventory(keys):
    rows=[target('k'+str(i),'AWS::Connect::SecurityKey',InstanceId='arn:aws:connect:ap-northeast-1:111111111111:instance/abc',Key=k) for i,k in enumerate(keys[:2])]
    assert evaluate_connect_security_count(linked_design(rows[0],rows[1:],[]),rows[0])[0]['verdict']=='NEEDS_REVIEW'


def test_checker_dispatch(keys):
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    rows=[target('k'+str(i),'AWS::Connect::SecurityKey',InstanceId='arn:aws:connect:ap-northeast-1:111111111111:instance/abc',Key=k) for i,k in enumerate(keys)]
    d=linked_design(rows[0],rows[1:],[])
    assert any(f['rule_id']=='CONNECT_INSTANCE_SECURITY_KEY_LIMIT' and f['verdict']=='FAIL' for f in Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results'])
