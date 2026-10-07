import pytest
from aws_design_sheet.checks.amplifyuibuilder.navigation_type import evaluate_amplifyuibuilder_navigation_type
from aws_design_sheet.checks.appstream.associations import evaluate_appstream_associations
from aws_design_sheet.checks.apprunner.security_group_vpc import evaluate_apprunner_security_group_vpc
from aws_design_sheet.checks.registry import combine
app_associations_checks = combine(evaluate_amplifyuibuilder_navigation_type, evaluate_appstream_associations, evaluate_apprunner_security_group_vpc)
from aws_design_sheet.checks.cognito.idp_provider import evaluate_cognito_idp_provider
from aws_design_sheet.checks.config.pipeline import evaluate_config_pipeline
from aws_design_sheet.checks.codepipeline.webhook_first_stage import evaluate_codepipeline_webhook_first_stage
from aws_design_sheet.checks.registry import combine
config_pipeline_checks = combine(evaluate_cognito_idp_provider, evaluate_config_pipeline, evaluate_codepipeline_webhook_first_stage)
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN
from test_template_dependencies import link


@pytest.mark.parametrize('raw,want', [('fleet','PASS'),('other','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW'),(None,'PASS')])
@pytest.mark.parametrize('block', [False,True])
def test_appstream_fleet_identity(raw,want,block):
    b=target('block','AWS::AppStream::AppBlock')
    app=target('app','AWS::AppStream::Application')
    a=target('association','AWS::AppStream::ApplicationFleetAssociation',**({} if raw is None else {'FleetName':raw}))
    fleet=target('fleet','AWS::AppStream::Fleet',Name='fleet',FleetType='ELASTIC')
    d=linked_design(b,[app,a,fleet]);link(d,app,'AppBlockArn',b);link(d,a,'ApplicationArn',app);link(d,a,'FleetName',fleet)
    r=b if block else app
    assert app_associations_checks(d,r)[0]['verdict']==want


@pytest.mark.parametrize('kind', ['ALWAYS_ON','ON_DEMAND'])
def test_multiple_consumers_one_incompatible(kind):
    r=target('app','AWS::AppStream::Application')
    good=target('good','AWS::AppStream::Fleet',FleetType='ELASTIC')
    bad=target('bad','AWS::AppStream::Fleet',FleetType=kind)
    first=target('first','AWS::AppStream::ApplicationFleetAssociation')
    second=target('second','AWS::AppStream::ApplicationFleetAssociation')
    d=linked_design(r,[good,bad,first,second])
    for a,f in ((first,good),(second,bad)):
        link(d,a,'ApplicationArn',r);link(d,a,'FleetName',f)
    assert app_associations_checks(d,r)[0]['verdict']=='FAIL'


@pytest.mark.parametrize('raw,want', [('stack','FAIL'),('other','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW'),(None,'FAIL')])
def test_userpool_stack_identity(raw,want):
    r=target('user','AWS::AppStream::StackUserAssociation',AuthenticationType='USERPOOL',**({} if raw is None else {'StackName':raw}))
    s=target('stack','AWS::AppStream::Stack',Name='stack')
    a=target('association','AWS::AppStream::StackFleetAssociation')
    f=target('fleet','AWS::AppStream::Fleet',DomainJoinInfo={'DirectoryName':'example.test'})
    d=linked_design(r,[s,a,f]);link(d,r,'StackName',s);link(d,a,'StackName',s);link(d,a,'FleetName',f)
    assert app_associations_checks(d,r)[0]['verdict']==want


@pytest.mark.parametrize('raw,want', [('pipeline','PASS'),('other','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW'),(None,'PASS')])
def test_webhook_pipeline_identity(raw,want):
    r=target('hook','AWS::CodePipeline::Webhook',TargetAction='Source',**({} if raw is None else {'TargetPipeline':raw}))
    p=target('pipeline','AWS::CodePipeline::Pipeline',Name='pipeline',Stages=[{'Actions':[{'Name':'Source'}]}])
    d=linked_design(r,[p]);link(d,r,'TargetPipeline',p)
    assert config_pipeline_checks(d,r)[0]['verdict']==want


def test_literal_arn_does_not_override_relation():
    r=target('app','AWS::AppStream::Application')
    a=target('association','AWS::AppStream::ApplicationFleetAssociation',ApplicationArn='arn:aws:appstream:ap-northeast-1:111111111111:application/different')
    f=target('fleet','AWS::AppStream::Fleet',FleetType='ON_DEMAND')
    d=linked_design(r,[a,f]);link(d,a,'ApplicationArn',r);link(d,a,'FleetName',f)
    assert app_associations_checks(d,r)[0]['verdict']=='NEEDS_REVIEW'
