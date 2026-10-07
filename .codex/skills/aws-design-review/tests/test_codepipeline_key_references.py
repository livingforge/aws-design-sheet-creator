import pytest
from aws_design_sheet.checks.common.context_values import _Context
from aws_design_sheet.checks.codepipeline.key_references import referenced_role_account, referenced_key_kind
from aws_design_sheet.models import TemplateContext
from test_autoscaling_group_and_scaling_policy import target,linked_design


@pytest.mark.parametrize('kind',['AWS::IAM::Role','AWS::KMS::Key','AWS::KMS::ReplicaKey','AWS::KMS::Alias'])
@pytest.mark.parametrize('mode',['known','conditional','template','source_template','environment','unresolved','duplicate'])
def test_resource_reference(kind,mode):
    raw={'$state':'UNRESOLVED'} if mode=='unresolved' else 'reference'
    r=target('main','AWS::CodePipeline::Pipeline',RoleArn=raw)
    other=target('other',kind);other.scope.account='222222222222'
    d=linked_design(r,[other],[('RoleArn','other')])
    if mode=='conditional':d.relations[0].condition='maybe'
    if mode=='template':other.template=TemplateContext(state='UNRESOLVED')
    if mode=='source_template':r.template=TemplateContext(state='UNRESOLVED')
    if mode=='environment':other.scope.environment='different'
    if mode=='duplicate':d.relations.append(d.relations[0].model_copy(update={'id':'duplicate'}))
    fn=referenced_role_account if kind=='AWS::IAM::Role' else referenced_key_kind
    expected='222222222222' if kind=='AWS::IAM::Role' else 'alias' if kind=='AWS::KMS::Alias' else 'key'
    assert fn(_Context(d,r),r,'/properties/RoleArn')==(expected if mode=='known' else None)


@pytest.mark.parametrize('arn,kind,expected',[
 ('arn:aws:iam::222222222222:role/worker','AWS::IAM::Role','222222222222'),
 ('arn:aws:iam::111111111111:role/worker','AWS::IAM::Role',None),
 ('arn:aws:kms:ap-northeast-1:222222222222:alias/example','AWS::KMS::Key',None),
 ('arn:aws:kms:ap-northeast-1:222222222222:key/123','AWS::KMS::Alias',None),
 ('arn:aws:kms:us-east-1:222222222222:alias/example','AWS::KMS::Alias',None),
])
def test_contradictory_arn(arn,kind,expected):
    r=target('main','AWS::CodePipeline::Pipeline',RoleArn=arn);other=target('other',kind);other.scope.account='222222222222'
    d=linked_design(r,[other],[('RoleArn','other')])
    fn=referenced_role_account if kind=='AWS::IAM::Role' else referenced_key_kind
    assert fn(_Context(d,r),r,'/properties/RoleArn')==expected


@pytest.mark.parametrize('kind,expected',[('AWS::KMS::Key','PASS'),('AWS::KMS::ReplicaKey','PASS'),('AWS::KMS::Alias','FAIL')])
@pytest.mark.parametrize('mode',['known','role_conditional','key_conditional','key_template','source_template','encryption_unknown'])
def test_pipeline_linked_inputs(kind,expected,mode):
    from aws_design_sheet.checks.codepipeline.key_alias import evaluate_codepipeline_key_alias
    r=target('main','AWS::CodePipeline::Pipeline',Stages=[{'Actions':[{'RoleArn':'role'}]}],ArtifactStore={'EncryptionKey':{'Id':'key','Type':{'$state':'UNRESOLVED'} if mode=='encryption_unknown' else 'KMS'}})
    role=target('role','AWS::IAM::Role');role.scope.account='222222222222'
    key=target('key',kind)
    d=linked_design(r,[role,key],[('Stages/0/Actions/0/RoleArn','role'),('ArtifactStore/EncryptionKey/Id','key')])
    if mode=='role_conditional':d.relations[0].condition='maybe'
    if mode=='key_conditional':d.relations[1].condition='maybe'
    if mode=='key_template':key.template=TemplateContext(state='UNRESOLVED')
    if mode=='source_template':r.template=TemplateContext(state='UNRESOLVED')
    assert evaluate_codepipeline_key_alias(d,r)[0]['verdict']==(expected if mode=='known' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('raw,kind',[('alias/example','AWS::KMS::Key'),('12345678-1234-1234-1234-123456789abc','AWS::KMS::Alias')])
def test_bare_literal_kind_contradiction(raw,kind):
    r=target('main','AWS::CodePipeline::Pipeline',RoleArn=raw);other=target('other',kind)
    d=linked_design(r,[other],[('RoleArn','other')])
    assert referenced_key_kind(_Context(d,r),r,'/properties/RoleArn') is None


@pytest.mark.parametrize('action',['malformed',{'$state':'UNRESOLVED'},None])
def test_unknown_action_does_not_inherit_a_default_role(action):
    from aws_design_sheet.checks.codepipeline.key_alias import evaluate_codepipeline_key_alias
    r=target('main','AWS::CodePipeline::Pipeline',RoleArn='arn:aws:iam::111111111111:role/pipeline',Stages=[{'Actions':[action]}],ArtifactStore={'EncryptionKey':{'Id':'alias/example','Type':'KMS'}})
    assert evaluate_codepipeline_key_alias(linked_design(r),r)[0]['verdict']=='NEEDS_REVIEW'
