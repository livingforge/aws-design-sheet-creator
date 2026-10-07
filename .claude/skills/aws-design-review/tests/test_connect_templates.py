from pathlib import Path
import pytest
from aws_design_sheet.checks.common.json_verdict import json_verdict
from aws_design_sheet.checks.connect.templates import evaluate_connect_templates
from aws_design_sheet.checks.codepipeline.template_config_reference import evaluate_codepipeline_template_config_reference
from aws_design_sheet.checks.registry import combine
connect_templates_checks = combine(evaluate_connect_templates, evaluate_codepipeline_template_config_reference)
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def linked_case(r, other, path, mode):
    d=linked_design(r,[other],[] if mode=='literal' else [(path,other.id)])
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='scope':other.scope.account='222222222222'
    return d


@pytest.mark.parametrize('branch',['S3Config','KinesisVideoStreamConfig'])
@pytest.mark.parametrize('spec,expected',[('SYMMETRIC_DEFAULT','PASS'),('RSA_2048','FAIL'),(UNKNOWN,'NEEDS_REVIEW'),(None,'NEEDS_REVIEW')])
@pytest.mark.parametrize('mode',['linked','literal','conditional','scope'])
def test_key(branch,spec,expected,mode):
    r=target('main','AWS::Connect::InstanceStorageConfig',**{branch:{'EncryptionConfig':{'KeyId':'key'}}})
    key=target('key','AWS::KMS::Key',**({} if spec is None else {'KeySpec':spec}))
    d=linked_case(r,key,branch+'/EncryptionConfig/KeyId',mode)
    assert connect_templates_checks(d,r)[0]['verdict']==(expected if mode=='linked' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('branch,wanted',[('QueueConfig','QUEUE_TRANSFER'),('UserConfig','AGENT_TRANSFER')])
@pytest.mark.parametrize('kind',['QUEUE_TRANSFER','AGENT_TRANSFER','CONTACT_FLOW',UNKNOWN])
@pytest.mark.parametrize('mode',['linked','literal','conditional','scope'])
def test_flow(branch,wanted,kind,mode):
    r=target('main','AWS::Connect::QuickConnect',QuickConnectConfig={branch:{'ContactFlowArn':'flow'}})
    flow=target('flow','AWS::Connect::ContactFlow',Type=kind)
    verdict='NEEDS_REVIEW' if mode!='linked' or kind==UNKNOWN else 'PASS' if kind==wanted else 'FAIL'
    assert connect_templates_checks(linked_case(r,flow,'QuickConnectConfig/'+branch+'/ContactFlowArn',mode),r)[0]['verdict']==verdict


@pytest.mark.parametrize('kind',['SAML','CONNECT_MANAGED','EXISTING_DIRECTORY',UNKNOWN])
@pytest.mark.parametrize('info,expected', [({},('FAIL','FAIL','PASS')),({'FirstName':'A','LastName':'B'},('PASS','PASS','PASS')),({'FirstName':UNKNOWN,'LastName':'B','Email':'a@example.com'},('NEEDS_REVIEW','PASS','FAIL'))])
def test_user(kind,info,expected):
    r=target('main','AWS::Connect::User',InstanceArn='instance',IdentityInfo=info)
    instance=target('instance','AWS::Connect::Instance',IdentityManagementType=kind)
    findings=connect_templates_checks(linked_case(r,instance,'InstanceArn','linked'),r)
    values=tuple(f['verdict'] for f in findings)
    assert values==(expected if kind=='SAML' else expected[:2] if kind=='CONNECT_MANAGED' else () if kind=='EXISTING_DIRECTORY' else ('NEEDS_REVIEW',)*3)


@pytest.mark.parametrize('raw,expected',[('{}','PASS'),('[]','PASS'),('null','PASS'),('1e9999','PASS'),('{"a":1,"a":2}','PASS'),('', 'FAIL'),('{', 'FAIL'),('NaN','FAIL'),('Infinity','FAIL'),('{"a":1,}','FAIL'),('${Json}','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW'),('['*1100+']'*1100,'NEEDS_REVIEW')],ids=['object','array','null','big_float','duplicate','empty','incomplete','nan','infinity','comma','substitution','unknown','deep'])
def test_json(raw,expected):
    assert json_verdict(raw)==expected


@pytest.mark.parametrize('required,secret,expected',[(True,False,'PASS'),(False,False,'FAIL'),(True,True,'FAIL'),(UNKNOWN,False,'NEEDS_REVIEW'),(True,UNKNOWN,'NEEDS_REVIEW')])
@pytest.mark.parametrize('field',['EntityUrlTemplate','ExecutionUrlTemplate'])
def test_template_flags(required,secret,expected,field):
    r=target('main','AWS::CodePipeline::CustomActionType',Settings={field:'https://example.com/{Config:Project}/{ExternalExecutionId}'},ConfigurationProperties=[{'Name':'Project','Required':required,'Secret':secret}])
    assert connect_templates_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('props',[[],[{'Name':'Project'},{'Name':'Project'}],[{'Name':UNKNOWN}],UNKNOWN])
def test_template_ambiguous(props):
    r=target('main','AWS::CodePipeline::CustomActionType',Settings={'EntityUrlTemplate':'https://example.com/{Config:Project}'},ConfigurationProperties=props)
    assert connect_templates_checks(linked_design(r),r)[0]['verdict']==('FAIL' if props==[] else 'NEEDS_REVIEW')


@pytest.mark.parametrize('url,expected',[('https://example.com/static','PASS'),('https://example.com/{Config:','NEEDS_REVIEW'),('${URL}','NEEDS_REVIEW')])
def test_template_grammar(url,expected):
    r=target('main','AWS::CodePipeline::CustomActionType',Settings={'ExecutionUrlTemplate':url})
    assert connect_templates_checks(linked_design(r),r)[0]['verdict']==expected


def test_checker_initialization():
    r=target('main','AWS::Connect::TestCase',InitializationData='{bad}')
    root=Path(__file__).resolve().parents[1]
    findings=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='CONNECT_TEST_INITIALIZATION_JSON' and f['verdict']=='FAIL' for f in findings)
