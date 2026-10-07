import pytest
from aws_design_sheet.checks.voiceid.key import evaluate_voiceid_key
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link


@pytest.mark.parametrize('props,want',[({},'PASS'),({'KeySpec':'SYMMETRIC_DEFAULT','KeyUsage':'ENCRYPT_DECRYPT'},'PASS'),({'KeySpec':'RSA_2048'},'FAIL'),({'KeySpec':'HMAC_256'},'FAIL'),({'KeySpec':'ML_DSA_44'},'FAIL'),({'KeySpec':UNKNOWN},'NEEDS_REVIEW'),({'KeyUsage':'SIGN_VERIFY'},'FAIL')])
def test_key_kind(props,want):
    r=target('domain','AWS::VoiceID::Domain');key=target('key','AWS::KMS::Key',**props)
    d=linked_design(r,[key]);link(d,r,'ServerSideEncryptionConfiguration/KmsKeyId',key)
    assert evaluate_voiceid_key(d,r)[0]['verdict']==want


@pytest.mark.parametrize('case',['literal','conditional','external','scope'])
def test_unknown_key_identity(case):
    r=target('domain','AWS::VoiceID::Domain');key=target('key','AWS::KMS::Key')
    d=linked_design(r,[key]);link(d,r,'ServerSideEncryptionConfiguration/KmsKeyId',key)
    if case=='literal':r.fields=target('x',r.type,ServerSideEncryptionConfiguration={'KmsKeyId':'physical-id'}).fields
    if case=='conditional':d.relations[0].condition='Maybe'
    if case=='external':d.resources.remove(key)
    if case=='scope':key.scope.region='us-east-1'
    assert evaluate_voiceid_key(d,r)[0]['verdict']=='NEEDS_REVIEW'


def test_explicit_alias_chain():
    r=target('domain','AWS::VoiceID::Domain');alias=target('alias','AWS::KMS::Alias');key=target('key','AWS::KMS::Key')
    d=linked_design(r,[alias,key]);link(d,r,'ServerSideEncryptionConfiguration/KmsKeyId',alias);link(d,alias,'TargetKeyId',key)
    assert evaluate_voiceid_key(d,r)[0]['verdict']=='PASS'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    r=target('domain','AWS::VoiceID::Domain');key=target('key','AWS::KMS::Key');d=linked_design(r,[key]);link(d,r,'ServerSideEncryptionConfiguration/KmsKeyId',key);root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert any(f['rule_id']=='VOICEID_SYMMETRIC_ENCRYPTION_KEY' and f['verdict']=='PASS' for f in results)
