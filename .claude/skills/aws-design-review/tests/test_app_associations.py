from pathlib import Path
import pytest
from aws_design_sheet.checks.amplifyuibuilder.navigation_type import evaluate_amplifyuibuilder_navigation_type
from aws_design_sheet.checks.appstream.associations import evaluate_appstream_associations
from aws_design_sheet.checks.apprunner.security_group_vpc import evaluate_apprunner_security_group_vpc
from aws_design_sheet.checks.registry import combine
app_associations_checks = combine(evaluate_amplifyuibuilder_navigation_type, evaluate_appstream_associations, evaluate_apprunner_security_group_vpc)
from aws_design_sheet.checks.autoscalingplans.enums import evaluate_autoscalingplans_enums, ENUMS
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN
from test_template_dependencies import template, link
from test_config_pipeline import nested


def verdict(d,r,rule):
    return next(f['verdict'] for f in app_associations_checks(d,r) if f['rule_id']==rule)


@pytest.mark.parametrize('depth',[0,1,3])
@pytest.mark.parametrize('params,expected', [({},'FAIL'),({'Type':{}},'PASS'),({'Type':UNKNOWN},'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW'),(None,'NEEDS_REVIEW')])
def test_navigation(depth,params,expected):
    props={'Events':{'onClick':{'Action':'Amplify.Navigation','Parameters':params}}}
    for _ in range(depth):props={'Children':[props]}
    r=target('main','AWS::AmplifyUIBuilder::Component',**props)
    assert verdict(linked_design(r),r,'AMPLIFYUI_NAVIGATION_TYPE')==expected


@pytest.mark.parametrize('case',['escaped','unknown_events','unknown_children','deep'])
def test_navigation_limits(case):
    props={'Events':{'bad/key':{'Action':'Amplify.Navigation'}}} if case=='escaped' else {'Events':UNKNOWN} if case=='unknown_events' else {'Children':UNKNOWN}
    if case=='deep':
        props={}
        for _ in range(35):props={'Children':[props]}
    r=target('main','AWS::AmplifyUIBuilder::Component',**props)
    assert verdict(linked_design(r),r,'AMPLIFYUI_NAVIGATION_TYPE')=='NEEDS_REVIEW'


@pytest.mark.parametrize('block',[False,True])
@pytest.mark.parametrize('case',['elastic','always','demand','unknown','external','conditional','scope','no_association'])
def test_application_fleet(block,case):
    b=target('block','AWS::AppStream::AppBlock',Name='block')
    app=target('app','AWS::AppStream::Application')
    a=target('association','AWS::AppStream::ApplicationFleetAssociation',FleetName='fleet')
    fleet=target('fleet','AWS::AppStream::Fleet',Name='fleet',FleetType={'elastic':'ELASTIC','always':'ALWAYS_ON','demand':'ON_DEMAND'}.get(case,UNKNOWN))
    d=linked_design(b,[app,a,fleet])
    link(d,app,'AppBlockArn',b);link(d,a,'ApplicationArn',app)
    if case!='external':link(d,a,'FleetName',fleet)
    if case=='conditional':d.relations[-1].condition='maybe'
    if case=='scope':fleet.scope.account='222222222222'
    if case=='no_association':d.resources.remove(a)
    r=b if block else app
    rule='APPSTREAM_APPBLOCK_ELASTIC_FLEET' if block else 'APPSTREAM_APPLICATION_ELASTIC_FLEET'
    assert verdict(d,r,rule)==('PASS' if case=='elastic' else 'FAIL' if case in ('always','demand') else 'NEEDS_REVIEW')


@pytest.mark.parametrize('case',['absent','domain','unknown','empty','external','conditional','no_association','saml'])
def test_userpool(case):
    r=target('main','AWS::AppStream::StackUserAssociation',AuthenticationType='SAML' if case=='saml' else 'USERPOOL',StackName='stack')
    stack=target('stack','AWS::AppStream::Stack',Name='stack')
    a=target('association','AWS::AppStream::StackFleetAssociation',StackName='stack',FleetName='fleet')
    props={} if case=='absent' else {'DomainJoinInfo':UNKNOWN if case=='unknown' else {} if case=='empty' else {'DirectoryName':'example.test'}}
    fleet=target('fleet','AWS::AppStream::Fleet',Name='fleet',**props)
    d=linked_design(r,[stack,a,fleet],[('StackName','stack')]);link(d,a,'StackName',stack)
    if case!='external':link(d,a,'FleetName',fleet)
    if case=='conditional':d.relations[-1].condition='maybe'
    if case=='no_association':d.resources.remove(a)
    assert verdict(d,r,'APPSTREAM_USERPOOL_DOMAIN_FLEET')==('PASS' if case=='absent' else 'FAIL' if case=='domain' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('case',['same','different','external','conditional','scope','empty'])
def test_runner(case):
    r=target('main','AWS::AppRunner::VpcConnector',Subnets=['s'],SecurityGroups=[] if case=='empty' else ['sg'])
    s=target('s','AWS::EC2::Subnet',VpcId='v1');sg=target('sg','AWS::EC2::SecurityGroup',VpcId='v2' if case=='different' else 'v1')
    v1=target('v1','AWS::EC2::VPC');v2=target('v2','AWS::EC2::VPC')
    d=linked_design(r,[s,sg,v1,v2],[('Subnets/0','s'),('SecurityGroups/0','sg')]);link(d,s,'VpcId',v1)
    if case!='external':link(d,sg,'VpcId',v2 if case=='different' else v1)
    if case=='conditional':d.relations[-1].condition='maybe'
    if case=='scope':sg.scope.account='222222222222'
    assert verdict(d,r,'APPRUNNER_SECURITY_GROUP_VPC')==('PASS' if case=='same' else 'FAIL' if case=='different' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('case',['explicit','implicit','missing','unknown','external','different_template','duplicate','conditional'])
def test_ordering(case):
    r=template(target('main','AWS::AppStream::StackFleetAssociation',FleetName='fleet',StackName='stack'),['fleet','stack'] if case=='explicit' else None if case=='unknown' else [])
    f=template(target('fleet','AWS::AppStream::Fleet',Name='fleet'));s=template(target('stack','AWS::AppStream::Stack',Name='stack'))
    d=linked_design(r,[f,s])
    if case in ('implicit','conditional'):
        link(d,r,'FleetName',f);link(d,r,'StackName',s)
    if case=='conditional':d.relations[0].condition='maybe'
    if case=='external':d.resources.remove(f)
    if case=='different_template':f.template.id='other'
    if case=='duplicate':d.resources.append(template(target('f2','AWS::AppStream::Fleet',Name='fleet')))
    assert verdict(d,r,'APPSTREAM_STACK_FLEET_ORDER')==('PASS' if case in ('explicit','implicit') else 'FAIL' if case=='missing' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('path,allowed',list(ENUMS.items()))
@pytest.mark.parametrize('case',['valid','invalid','unknown','intrinsic'])
def test_scaling_enums(path,allowed,case):
    raw=allowed[-1] if case=='valid' else 'Invalid' if case=='invalid' else UNKNOWN if case=='unknown' else '${Metric}'
    r=target('main','AWS::AutoScalingPlans::ScalingPlan',ScalingInstructions=[nested(path.split('/'),raw)])
    assert evaluate_autoscalingplans_enums(linked_design(r),r)[0]['verdict']==('PASS' if case=='valid' else 'FAIL' if case=='invalid' else 'NEEDS_REVIEW')


def test_checker_and_appsync_override_regression():
    root=Path(__file__).resolve().parents[1];checker=Checker(root/'schemas',root/'profiles/vpc-subnet.json')
    r=target('main','AWS::AmplifyUIBuilder::Component',Events={'onClick':{'Action':'Amplify.Navigation','Parameters':{}}})
    assert any(f['rule_id']=='AMPLIFYUI_NAVIGATION_TYPE' and f['verdict']=='FAIL' for f in checker.check(linked_design(r))['results'])
    r=target('main','AWS::AppSync::FunctionConfiguration',FunctionVersion='2018-05-29',RequestMappingTemplate='{"version":"2017-02-28","operation":"Invoke"}')
    assert evaluate_autoscalingplans_enums(linked_design(r),r)==[]
    assert not any(f['rule_id']=='APPSYNC_LITERAL_REQUEST_VERSION' for f in checker.check(linked_design(r))['results'])
