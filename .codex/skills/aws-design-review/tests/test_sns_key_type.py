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
    main=target('topic','AWS::SNS::Topic',KmsMasterKeyId={'Ref':'key'})
    key=target('key','AWS::KMS::Key',**props)
    data=linked_design(main,[key],[('KmsMasterKeyId','key')])
    findings={r['rule_id']:r['verdict'] for r in run_resource_checks(data,main)}
    assert findings['SNS_ENCRYPTION_KEY_TYPE']==expected


@pytest.mark.parametrize('raw',['alias/aws/sns','arn:aws:kms:ap-northeast-1:111111111111:key/id',UNKNOWN])
def test_external_key_needs_review(raw):
    main=target('topic','AWS::SNS::Topic',KmsMasterKeyId=raw)
    findings={r['rule_id']:r['verdict'] for r in run_resource_checks(linked_design(main),main)}
    assert findings['SNS_ENCRYPTION_KEY_TYPE']=='NEEDS_REVIEW'


def test_unencrypted_topic_skips_key_type():
    main=target('topic','AWS::SNS::Topic')
    assert not any(r['rule_id']=='SNS_ENCRYPTION_KEY_TYPE' for r in run_resource_checks(linked_design(main),main))
