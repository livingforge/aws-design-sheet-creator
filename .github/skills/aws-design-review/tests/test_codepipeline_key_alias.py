import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.codepipeline.key_alias import evaluate_codepipeline_key_alias
from test_autoscaling_group_and_scaling_policy import target,linked_design

KEY='12345678-1234-1234-1234-123456789abc'


@pytest.mark.parametrize('key,expected',[
 ('alias/example','FAIL'),('arn:aws:kms:ap-northeast-1:111111111111:alias/example','FAIL'),
 (KEY,'PASS'),('arn:aws:kms:ap-northeast-1:111111111111:key/'+KEY,'PASS'),
 ('mrk-'+'a'*32,'PASS'),('arbitrary-key','NEEDS_REVIEW'),({'$state':'UNRESOLVED'},'NEEDS_REVIEW')])
@pytest.mark.parametrize('mode',['cross','same','unknown','source_template','mapped'])
def test_alias_restriction(key,expected,mode):
    account='111111111111' if mode=='same' else '222222222222'
    role={'$state':'UNRESOLVED'} if mode=='unknown' else 'arn:aws:iam::'+account+':role/path/worker'
    props={'Stages':[{'Actions':[{'RoleArn':role}]}]}
    store={'EncryptionKey':{'Id':key,'Type':'KMS'}}
    if mode=='mapped':props['ArtifactStores']=[{'Region':'ap-northeast-1','ArtifactStore':store}]
    else:props['ArtifactStore']=store
    r=target('main','AWS::CodePipeline::Pipeline',**props)
    if mode=='source_template':r.template=TemplateContext(state='UNRESOLVED')
    want='NOT_APPLICABLE' if mode=='same' else 'NEEDS_REVIEW' if mode in ('unknown','source_template') else expected
    assert evaluate_codepipeline_key_alias(linked_design(r),r)[0]['verdict']==want


@pytest.mark.parametrize('stages',[{'$state':'UNRESOLVED'},'bad',[{'Actions':{'$state':'UNRESOLVED'}}],[{'Actions':[{'RoleArn':'arn:aws:iam::222222222222:role/worker','Region':{'$state':'UNRESOLVED'}}]}]])
def test_unknown_actions(stages):
    r=target('main','AWS::CodePipeline::Pipeline',Stages=stages,ArtifactStore={'EncryptionKey':{'Id':'alias/example'}})
    assert evaluate_codepipeline_key_alias(linked_design(r),r)[0]['verdict']=='NEEDS_REVIEW'


def test_only_matching_region_is_checked():
    r=target('main','AWS::CodePipeline::Pipeline',Stages=[{'Actions':[{'Region':'us-east-1','RoleArn':'arn:aws:iam::222222222222:role/worker'}]}],ArtifactStores=[{'Region':'ap-northeast-1','ArtifactStore':{'EncryptionKey':{'Id':'alias/local'}}},{'Region':'us-east-1','ArtifactStore':{'EncryptionKey':{'Id':'alias/cross'}}}])
    assert [f['verdict'] for f in evaluate_codepipeline_key_alias(linked_design(r),r)]==['NEEDS_REVIEW','FAIL']


def test_missing_action_role_uses_pipeline_role():
    r=target('main','AWS::CodePipeline::Pipeline',RoleArn='arn:aws:iam::111111111111:role/pipeline',Stages=[{'Actions':[{}]}],ArtifactStore={'EncryptionKey':{'Id':'alias/local'}})
    assert evaluate_codepipeline_key_alias(linked_design(r),r)[0]['verdict']=='NOT_APPLICABLE'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    r=target('main','AWS::CodePipeline::Pipeline',Stages=[{'Actions':[{'RoleArn':'arn:aws:iam::222222222222:role/action'}]}],ArtifactStore={'EncryptionKey':{'Id':'alias/example'}})
    root=Path(__file__).resolve().parents[1]
    assert any(f['rule_id']=='PIPELINE_CROSS_ACCOUNT_KEY_ALIAS' and f['verdict']=='FAIL' for f in Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results'])
