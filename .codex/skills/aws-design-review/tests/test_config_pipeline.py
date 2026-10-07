from pathlib import Path
import pytest
from aws_design_sheet.checks.config.pipeline import CONFIG_ENUMS, evaluate_config_pipeline
from aws_design_sheet.checks.cognito.idp_provider import evaluate_cognito_idp_provider
from aws_design_sheet.checks.codepipeline.webhook_first_stage import evaluate_codepipeline_webhook_first_stage
from aws_design_sheet.checks.registry import combine
config_pipeline_checks = combine(evaluate_cognito_idp_provider, evaluate_config_pipeline, evaluate_codepipeline_webhook_first_stage)
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def nested(path, raw):
    if not path:
        return raw
    head, *tail = path
    return [nested(tail, raw)] if head == '*' else {head:nested(tail, raw)}


@pytest.mark.parametrize('suffix,allowed', CONFIG_ENUMS, ids=['owner','source','message','detail_frequency','frequency','mode'])
@pytest.mark.parametrize('mode',['valid','invalid','unknown','intrinsic'])
def test_config_values(suffix,allowed,mode):
    raw=allowed[0] if mode=='valid' else 'Invalid' if mode=='invalid' else UNKNOWN if mode=='unknown' else '${Value}'
    r=target('main','AWS::Config::ConfigRule',**nested(suffix.split('/'),raw))
    f=config_pipeline_checks(linked_design(r),r)
    assert len(f)==1
    assert f[0]['verdict']==('PASS' if mode=='valid' else 'FAIL' if mode=='invalid' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('kind',['SAML','Facebook','Google','LoginWithAmazon','SignInWithApple','OIDC','Invalid',UNKNOWN])
def test_idp(kind):
    r=target('main','AWS::Cognito::UserPoolIdentityProvider',ProviderType=kind)
    assert config_pipeline_checks(linked_design(r),r)[0]['verdict']==('NEEDS_REVIEW' if kind==UNKNOWN else 'FAIL' if kind=='Invalid' else 'PASS')


@pytest.mark.parametrize('first,name,expected', [(['Source'],'Source','PASS'),(['Other'],'Source','FAIL'),(['Other'],'Other','PASS'),(['Source','Source'],'Source','NEEDS_REVIEW'),(['Source',UNKNOWN],'Source','NEEDS_REVIEW'),([], 'Source','FAIL'),(['Source'],UNKNOWN,'NEEDS_REVIEW')])
@pytest.mark.parametrize('mode',['linked','literal','conditional','scope'])
def test_webhook(first,name,expected,mode):
    r=target('main','AWS::CodePipeline::Webhook',TargetPipeline='pipeline',TargetAction=name)
    p=target('pipeline','AWS::CodePipeline::Pipeline',Name='pipeline',Stages=[{'Actions':[{'Name':n} for n in first]},{'Actions':[{'Name':'Source'}]}])
    d=linked_design(r,[p],[] if mode=='literal' else [('TargetPipeline','pipeline')])
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='scope':p.scope.account='222222222222'
    assert config_pipeline_checks(d,r)[0]['verdict']==(expected if mode=='linked' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('stages',[UNKNOWN,[],[UNKNOWN],[{'Actions':UNKNOWN}]])
def test_unknown_pipeline_structure(stages):
    r=target('main','AWS::CodePipeline::Webhook',TargetPipeline='p',TargetAction='Source')
    p=target('p','AWS::CodePipeline::Pipeline',Name='pipeline',Stages=stages)
    assert config_pipeline_checks(linked_design(r,[p],[('TargetPipeline','p')]),r)[0]['verdict']=='NEEDS_REVIEW'


def test_checker_integration():
    r=target('main','AWS::Config::ConfigRule',Source={'Owner':'Invalid'})
    root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='CONFIG_RULE_VALUES' and f['verdict']=='FAIL' for f in results)
