import pytest
from aws_design_sheet.checks.common.kms_key_types import key_type
from aws_design_sheet.checks.common.context_values import _Context
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN
from test_template_dependencies import link


@pytest.mark.parametrize('spec',[None,'SYMMETRIC_DEFAULT','HMAC_224','HMAC_256','HMAC_384','HMAC_512','RSA_4096','ML_DSA_44','ML_DSA_65','ML_DSA_87','ECC_NIST_EDWARDS25519',UNKNOWN,'future'])
@pytest.mark.parametrize('usage',[None,'ENCRYPT_DECRYPT','SIGN_VERIFY','GENERATE_VERIFY_MAC','KEY_AGREEMENT',UNKNOWN])
def test_key_classification(spec,usage):
    props={}
    if spec is not None:props['KeySpec']=spec
    if usage is not None:props['KeyUsage']=usage
    r=target('main','AWS::WorkSpaces::Workspace',VolumeEncryptionKey='key');k=target('key','AWS::KMS::Key',**props)
    d=linked_design(r,[k],[('VolumeEncryptionKey','key')])
    expected='NEEDS_REVIEW'
    if spec in ('HMAC_224','HMAC_256','HMAC_384','HMAC_512','RSA_4096','ML_DSA_44','ML_DSA_65','ML_DSA_87','ECC_NIST_EDWARDS25519') or usage in ('SIGN_VERIFY','GENERATE_VERIFY_MAC','KEY_AGREEMENT'):expected='FAIL'
    elif spec in (None,'SYMMETRIC_DEFAULT') and usage in (None,'ENCRYPT_DECRYPT'):expected='PASS'
    assert key_type(_Context(d,r),r,'/properties/VolumeEncryptionKey')==expected


@pytest.mark.parametrize('alias',[False,True])
@pytest.mark.parametrize('case',['symmetric','hmac','asymmetric','external','conditional','wrong_account','same_region','unknown_primary','not_multi','arn_scope','unresolved_arn','wrong_partition'])
def test_replica_shared_properties(alias,case):
    r=target('main','AWS::WorkSpaces::Workspace',VolumeEncryptionKey='replica')
    arn='arn:aws:kms:us-east-1:111111111111:key/mrk-'+'a'*32
    replica=target('replica','AWS::KMS::ReplicaKey',PrimaryKeyArn=UNKNOWN if case=='unresolved_arn' else arn.replace('us-east-1','us-west-2') if case=='arn_scope' else arn.replace('arn:aws:','arn:aws-cn:') if case=='wrong_partition' else arn)
    primary=target('primary','AWS::KMS::Key',MultiRegion=case!='not_multi',KeySpec='HMAC_256' if case=='hmac' else 'RSA_2048' if case=='asymmetric' else UNKNOWN if case=='unknown_primary' else 'SYMMETRIC_DEFAULT')
    primary.scope.region='ap-northeast-1' if case=='same_region' else 'us-east-1'
    # Test fixtures use 111111111111 by default; synchronize the ARN to actual scope.
    if case=='wrong_account':primary.scope.account='222222222222'
    a=target('alias','AWS::KMS::Alias',TargetKeyId='replica')
    d=linked_design(r,[replica,primary,a]);link(d,r,'VolumeEncryptionKey',a if alias else replica)
    if alias:link(d,a,'TargetKeyId',replica)
    if case!='external':link(d,replica,'PrimaryKeyArn',primary)
    if case=='conditional':d.relations[-1].condition='maybe'
    expected='PASS' if case=='symmetric' else 'FAIL' if case in ('hmac','asymmetric') else 'NEEDS_REVIEW'
    assert key_type(_Context(d,r),r,'/properties/VolumeEncryptionKey',allow_alias=True)==expected


def test_vector_alias_is_not_accepted_as_key_arn():
    r=target('main','AWS::S3Vectors::VectorBucket',EncryptionConfiguration={'KmsKeyArn':'alias'})
    a=target('alias','AWS::KMS::Alias',TargetKeyId='key');k=target('key','AWS::KMS::Key')
    d=linked_design(r,[a,k],[('EncryptionConfiguration/KmsKeyArn','alias')]);link(d,a,'TargetKeyId',k)
    assert key_type(_Context(d,r),r,'/properties/EncryptionConfiguration/KmsKeyArn')=='NEEDS_REVIEW'
