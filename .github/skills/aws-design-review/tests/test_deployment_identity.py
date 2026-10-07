from pathlib import Path
import pytest
from aws_design_sheet.checks.codedeploy.deployment_group import evaluate_codedeploy_deployment_group
from aws_design_sheet.checks.codeguruprofiler.principal_wildcards import evaluate_codeguruprofiler_principal_wildcards
from aws_design_sheet.checks.codestarconnections.connection_provider import evaluate_codestarconnections_connection_provider
from aws_design_sheet.checks.codestarnotifications.notification_target_type import evaluate_codestarnotifications_notification_target_type
from aws_design_sheet.checks.cognito.deployment_identity import evaluate_cognito_deployment_identity
from aws_design_sheet.checks.registry import combine
deployment_identity_checks = combine(evaluate_codedeploy_deployment_group, evaluate_codeguruprofiler_principal_wildcards, evaluate_codestarconnections_connection_provider, evaluate_codestarnotifications_notification_target_type, evaluate_cognito_deployment_identity)
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def relation_design(main, other, path, mode):
    design = linked_design(main, [other], [] if mode == 'literal' else [(path, other.id)])
    if mode == 'conditional':
        design.relations[0].condition = 'Maybe'
    if mode == 'scope':
        other.scope.account = '222222222222'
    if mode == 'wrong_type':
        other.type = 'AWS::S3::Bucket'
    return design


@pytest.mark.parametrize('rule,props,expected', [
    ('CODEDEPLOY_ECS_PLATFORM', {'ECSServices':[{'ServiceName':'svc','ClusterName':'cluster'}]}, 'ECS'),
    ('CODEDEPLOY_BLUE_GREEN_PLATFORM', {'DeploymentStyle':{'DeploymentType':'BLUE_GREEN'}}, 'Lambda'),
    ('CODEDEPLOY_REVISION_PLATFORM', {'Deployment':{'Revision':{'RevisionType':'GitHub'}}}, 'Server'),
    ('CODEDEPLOY_REVISION_PLATFORM', {'Deployment':{'Revision':{'RevisionType':'String'}}}, 'Lambda'),
])
@pytest.mark.parametrize('platform', ['Server','Lambda','ECS',None,'Future'])
@pytest.mark.parametrize('mode', ['linked','literal','conditional','scope','wrong_type'])
def test_platform(rule, props, expected, platform, mode):
    r=target('main','AWS::CodeDeploy::DeploymentGroup',ApplicationName='app',**props)
    app=target('app','AWS::CodeDeploy::Application',**({} if platform is None else {'ComputePlatform':platform}))
    findings=deployment_identity_checks(relation_design(r,app,'ApplicationName',mode),r)
    verdict='NEEDS_REVIEW' if mode!='linked' or platform not in ('Server','Lambda','ECS') else 'PASS' if platform==expected else 'FAIL'
    assert next(f for f in findings if f['rule_id']==rule)['verdict']==verdict


@pytest.mark.parametrize('kind,props,rule', [
    ('LogDeliveryConfiguration',{'LogConfigurations':[{'EventSource':'userAuthEvents'}]},'COGNITO_AUTH_LOG_TIER'),
    ('UserPoolClient',{'ExplicitAuthFlows':['ALLOW_USER_AUTH']},'COGNITO_USER_AUTH_TIER'),
])
@pytest.mark.parametrize('tier', ['LITE','ESSENTIALS','PLUS',None,'Future'])
@pytest.mark.parametrize('mode', ['linked','literal','conditional','scope'])
def test_tiers(kind,props,rule,tier,mode):
    r=target('main','AWS::Cognito::'+kind,UserPoolId='pool',**props)
    pool=target('pool','AWS::Cognito::UserPool',**({} if tier is None else {'UserPoolTier':tier}))
    findings=deployment_identity_checks(relation_design(r,pool,'UserPoolId',mode),r)
    verdict='NEEDS_REVIEW' if mode!='linked' or tier not in ('LITE','ESSENTIALS','PLUS') else 'PASS' if tier=='PLUS' or kind=='UserPoolClient' and tier=='ESSENTIALS' else 'FAIL'
    assert next(f for f in findings if f['rule_id']==rule)['verdict']==verdict


@pytest.mark.parametrize('raw,expected', [('arn:aws:iam::111111111111:role/agent','PASS'),('*','FAIL'),('arn:aws:iam::*:role/a','FAIL'),('arn:aws:iam::111111111111:role/a?','FAIL'),(UNKNOWN,'NEEDS_REVIEW'),('${Arn}','NEEDS_REVIEW')])
def test_principal(raw,expected):
    r=target('main','AWS::CodeGuruProfiler::ProfilingGroup',AgentPermissions={'Principals':[raw]})
    assert deployment_identity_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('raw,expected', [('target','PASS'),('targetgroup/mygroup/0123456789abcdef','FAIL'),('arn:aws:elasticloadbalancing:us-east-1:111111111111:targetgroup/g/1','FAIL'),(UNKNOWN,'NEEDS_REVIEW'),({'Fn::GetAtt':['Group','TargetGroupFullName']},'NEEDS_REVIEW')])
@pytest.mark.parametrize('pair',[False,True])
def test_target_name(raw,expected,pair):
    info={'TargetGroupPairInfoList':[{'TargetGroups':[{'Name':raw}]}]} if pair else {'TargetGroupInfoList':[{'Name':raw}]}
    r=target('main','AWS::CodeDeploy::DeploymentGroup',LoadBalancerInfo=info)
    assert deployment_identity_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('provider', ['Bitbucket','GitHub','GitHubEnterpriseServer','GitLab','GitLabSelfManaged','AzureDevOps',UNKNOWN])
def test_provider(provider):
    r=target('main','AWS::CodeStarConnections::Connection',ProviderType=provider)
    assert deployment_identity_checks(linked_design(r),r)[0]['verdict']==('NEEDS_REVIEW' if provider==UNKNOWN else 'FAIL' if provider=='AzureDevOps' else 'PASS')


@pytest.mark.parametrize('kind', ['SNS','AWSChatbotSlack','AWSChatbotMicrosoftTeams','Email',UNKNOWN])
def test_notification(kind):
    r=target('main','AWS::CodeStarNotifications::NotificationRule',Targets=[{'TargetType':kind}])
    assert deployment_identity_checks(linked_design(r),r)[0]['verdict']==('NEEDS_REVIEW' if kind==UNKNOWN else 'FAIL' if kind=='Email' else 'PASS')


def test_checker_linked_platform():
    r=target('main','AWS::CodeDeploy::DeploymentGroup',ApplicationName='app',ECSServices=[{'ServiceName':'svc','ClusterName':'cluster'}])
    app=target('app','AWS::CodeDeploy::Application',ComputePlatform='Lambda')
    root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(relation_design(r,app,'ApplicationName','linked'))['results']
    assert any(f['rule_id']=='CODEDEPLOY_ECS_PLATFORM' and f['verdict']=='FAIL' for f in results)
