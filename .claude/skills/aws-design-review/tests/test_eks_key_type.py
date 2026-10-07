import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('props,expected',[
    ({},'PASS'),({'KeySpec':'SYMMETRIC_DEFAULT'},'PASS'),
    ({'KeyUsage':'ENCRYPT_DECRYPT'},'PASS'),({'KeySpec':'RSA_2048'},'FAIL'),
    ({'KeySpec':'HMAC_256'},'FAIL'),({'KeySpec':'ECC_NIST_EDWARDS25519'},'FAIL'),
    ({'KeySpec':'ML_DSA_44'},'FAIL'),({'KeySpec':UNKNOWN},'NEEDS_REVIEW'),
    ({'KeyUsage':UNKNOWN},'NEEDS_REVIEW'),({'KeySpec':'future'},'NEEDS_REVIEW'),
    ({'KeySpec':UNKNOWN,'KeyUsage':'SIGN_VERIFY'},'FAIL'),
    ({'KeySpec':[]},'NEEDS_REVIEW'),
])
def test_linked_key_type(props,expected):
    main=target('cluster','AWS::EKS::Cluster',EncryptionConfig=[{'Provider':{'KeyArn':{'Ref':'key'}}}])
    key=target('key','AWS::KMS::Key',**props)
    data=linked_design(main,[key],[('EncryptionConfig/0/Provider/KeyArn','key')])
    findings={r['rule_id']:r['verdict'] for r in run_resource_checks(data,main)}
    assert findings['EKS_ENCRYPTION_KEY_TYPE']==expected


def test_external_or_unresolved_configuration():
    for config in [[{'Provider':{'KeyArn':'arn:aws:kms:ap-northeast-1:123456789012:key/id'}}],UNKNOWN]:
        main=target('cluster','AWS::EKS::Cluster',EncryptionConfig=config)
        findings={r['rule_id']:r['verdict'] for r in run_resource_checks(linked_design(main),main)}
        assert findings['EKS_ENCRYPTION_KEY_TYPE']=='NEEDS_REVIEW'
