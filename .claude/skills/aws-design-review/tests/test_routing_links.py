"""Routing identity, enums, selector ambiguity and cardinality boundaries."""
from pathlib import Path
import pytest
from aws_design_sheet.models import Relation
from aws_design_sheet.checks.stepfunctions.state_machine_alias import evaluate_stepfunctions_state_machine_alias
from aws_design_sheet.checks.ses.receipt_enums import evaluate_ses_receipt_enums
from aws_design_sheet.checks.servicediscovery.health_namespace import evaluate_servicediscovery_health_namespace
from aws_design_sheet.checks.transfer.server_endpoints_and_users import evaluate_transfer_server_endpoints_and_users
from aws_design_sheet.checks.workspaces.autostop_interval import evaluate_workspaces_autostop_interval
from aws_design_sheet.checks.registry import combine
routing_links_checks = combine(evaluate_stepfunctions_state_machine_alias, evaluate_ses_receipt_enums, evaluate_servicediscovery_health_namespace, evaluate_transfer_server_endpoints_and_users, evaluate_workspaces_autostop_interval)
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN

ARN='arn:aws:states:ap-northeast-1:111111111111:stateMachine:'


def check(kind,rule=None,**props):
    r=target('subject','AWS::'+kind,**props)
    return [x for x in routing_links_checks(linked_design(r),r) if rule is None or x['rule_id']==rule]


@pytest.mark.parametrize('weights,expected',[
    ([100],'PASS'),([0,100],'PASS'),([50,50],'PASS'),([99],'FAIL'),([101],'FAIL'),
    ([60,60],'FAIL'),([], 'FAIL'),([50,UNKNOWN],'NEEDS_REVIEW'),([100,UNKNOWN],'NEEDS_REVIEW'),
    ([60,60,UNKNOWN],'FAIL'),([True,99],'NEEDS_REVIEW'),([50.0,50],'NEEDS_REVIEW'),
    ([-1,101],'FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_weight_totals(weights,expected):
    config=[{'Weight':x,'StateMachineVersionArn':ARN+'machine:1'} for x in weights] if isinstance(weights,list) else weights
    assert check('StepFunctions::StateMachineAlias','STEPFUNCTIONS_ALIAS_WEIGHT_TOTAL',RoutingConfiguration=config)[0]['verdict']==expected


@pytest.mark.parametrize('arns,expected',[
    ([ARN+'machine:1',ARN+'machine:2'],'PASS'),([ARN+'machine:1',ARN+'other:1'],'FAIL'),
    ([ARN+'machine:1',ARN+'Machine:2'],'FAIL'),([ARN+'machine:1',UNKNOWN],'NEEDS_REVIEW'),
    ([ARN+'machine:1',ARN+'other:1',UNKNOWN],'FAIL'),([ARN+'machine:prod'],'NEEDS_REVIEW'),
    ([ARN+'machine:01'],'NEEDS_REVIEW'),([ARN+'machine'],'NEEDS_REVIEW'),
    ([ARN+'machine:1','arn:aws:states:us-east-1:111111111111:stateMachine:machine:1'],'FAIL'),
    ([ARN+'machine:1',ARN.replace('111111111111','222222222222')+'machine:1'],'FAIL'),
    ([ARN+'machine:1',ARN+'mächine:1'],'NEEDS_REVIEW'),([], 'NEEDS_REVIEW')])
def test_version_arn_identity(arns,expected):
    config=[{'Weight':50,'StateMachineVersionArn':x} for x in arns]
    assert check('StepFunctions::StateMachineAlias','STEPFUNCTIONS_ALIAS_MACHINE_IDENTITY',RoutingConfiguration=config)[0]['verdict']==expected


@pytest.mark.parametrize('mode,expected',[
    ('same_machine','PASS'),('different_machine','FAIL'),('literal_parents','PASS'),
    ('different_literal_parents','FAIL'),('mixed','NEEDS_REVIEW'),('conditional_version','NEEDS_REVIEW'),
    ('conditional_parent','NEEDS_REVIEW'),('cross_scope','NEEDS_REVIEW'),('wrong_type','NEEDS_REVIEW')])
def test_linked_version_identity(mode,expected):
    r=target('alias','AWS::StepFunctions::StateMachineAlias',RoutingConfiguration=[{'Weight':50},{'Weight':50}])
    a=target('version-a','AWS::StepFunctions::StateMachineVersion',StateMachineArn=ARN+'machine')
    b=target('version-b','AWS::StepFunctions::StateMachineVersion',StateMachineArn=ARN+('other' if mode=='different_literal_parents' else 'machine'))
    m=target('machine','AWS::StepFunctions::StateMachine');m2=target('other','AWS::StepFunctions::StateMachine')
    d=linked_design(r,[a,b,m,m2],[('RoutingConfiguration/0/StateMachineVersionArn','version-a'),('RoutingConfiguration/1/StateMachineVersionArn','version-b')])
    if mode not in ('literal_parents','different_literal_parents'):
        d.relations.append(Relation(id='parent-a',source_resource_id=a.id,source_path='/properties/StateMachineArn',target_resource_id=m.id,evidence_ids=['e1']))
        if mode!='mixed':d.relations.append(Relation(id='parent-b',source_resource_id=b.id,source_path='/properties/StateMachineArn',target_resource_id=m2.id if mode=='different_machine' else m.id,evidence_ids=['e1']))
    if mode=='conditional_version':d.relations[0].condition='Maybe'
    if mode=='conditional_parent':d.relations[2].condition='Maybe'
    if mode=='cross_scope':b.scope.region='us-east-1'
    if mode=='wrong_type':b.type='AWS::S3::Bucket'
    assert next(x for x in routing_links_checks(d,r) if x['rule_id']=='STEPFUNCTIONS_ALIAS_MACHINE_IDENTITY')['verdict']==expected


@pytest.mark.parametrize('key,good,bad',[
    ('TlsPolicy','Require','require'),('LambdaAction/InvocationType','Event','DryRun'),
    ('SNSAction/Encoding','Base64','base64')])
@pytest.mark.parametrize('mode',['good','bad','unknown'])
def test_receipt_enums(key,good,bad,mode):
    v={'good':good,'bad':bad,'unknown':UNKNOWN}[mode]
    rule={key:v} if '/' not in key else {'Actions':[{key.split('/')[0]:{key.split('/')[1]:v}}]}
    assert check('SES::ReceiptRule',Rule=rule)[0]['verdict']=={'good':'PASS','bad':'FAIL','unknown':'NEEDS_REVIEW'}[mode]


def test_encoding_conflict_and_unknown_actions():
    assert check('SES::ReceiptRule',Rule={'Actions':[{'SNSAction':{'Encoding':'BASE64'}}]})[0]['verdict']=='NEEDS_REVIEW'
    rows=check('SES::ReceiptRule',Rule={'Actions':UNKNOWN})
    assert len(rows)==1 and rows[0]['verdict']=='NEEDS_REVIEW'
    assert check('SES::ReceiptRule',Rule={'Actions':[{'SNSAction':{}}]})==[]


@pytest.mark.parametrize('namespace,expected',[
    ('PublicDnsNamespace','PASS'),('HttpNamespace','PASS'),('PrivateDnsNamespace','FAIL')])
@pytest.mark.parametrize('selector',['NamespaceId','DnsConfig/NamespaceId','both'])
def test_health_namespace(namespace,expected,selector):
    r=target('service','AWS::ServiceDiscovery::Service',HealthCheckConfig={'Type':'HTTPS'})
    n=target('namespace','AWS::ServiceDiscovery::'+namespace)
    paths=['NamespaceId','DnsConfig/NamespaceId'] if selector=='both' else [selector]
    d=linked_design(r,[n],[(p,n.id) for p in paths])
    assert routing_links_checks(d,r)[0]['verdict']==expected


@pytest.mark.parametrize('mode',['missing','literal','conditional','cross_scope','conflicting','unknown_health','mixed'])
def test_health_namespace_holds(mode):
    r=target('service','AWS::ServiceDiscovery::Service',HealthCheckConfig=UNKNOWN if mode=='unknown_health' else {'Type':'HTTPS'})
    n=target('namespace','AWS::ServiceDiscovery::PrivateDnsNamespace');other=target('other','AWS::ServiceDiscovery::PublicDnsNamespace')
    if mode in ('literal','mixed'):r=target('service','AWS::ServiceDiscovery::Service',HealthCheckConfig={'Type':'HTTPS'},NamespaceId='ns-existing')
    links=[] if mode in ('missing','literal') else [('DnsConfig/NamespaceId' if mode=='mixed' else 'NamespaceId','namespace')]
    if mode=='conflicting':links.append(('DnsConfig/NamespaceId','other'))
    d=linked_design(r,[n,other],links)
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='cross_scope':n.scope.region='us-east-1'
    assert routing_links_checks(d,r)[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('addresses,subnets,expected',[
    (['a'],['s'],'PASS'),(['a','b'],['s'],'FAIL'),(['a'],['s','t'],'FAIL'),
    (['a','b'],['s','t'],'PASS'),([UNKNOWN],['s'],'NEEDS_REVIEW'),
    (UNKNOWN,['s'],'NEEDS_REVIEW'),(['a'],UNKNOWN,'NEEDS_REVIEW'),
    ([],['s'],'NEEDS_REVIEW'),(['a'],[],'NEEDS_REVIEW')])
def test_transfer_array_length(addresses,subnets,expected):
    assert check('Transfer::Server',EndpointDetails={'AddressAllocationIds':addresses,'SubnetIds':subnets})[0]['verdict']==expected


@pytest.mark.parametrize('provider,expected',[
    ('SERVICE_MANAGED','PASS'),('API_GATEWAY','FAIL'),('AWS_DIRECTORY_SERVICE','FAIL'),
    ('AWS_LAMBDA','FAIL'),(UNKNOWN,'NEEDS_REVIEW'),('future','NEEDS_REVIEW'),(None,'NEEDS_REVIEW')])
def test_transfer_user_provider(provider,expected):
    r=target('user','AWS::Transfer::User')
    s=target('server','AWS::Transfer::Server',**({} if provider is None else {'IdentityProviderType':provider}))
    assert routing_links_checks(linked_design(r,[s],[('ServerId','server')]),r)[0]['verdict']==expected


@pytest.mark.parametrize('mode',['unlinked','conditional','cross_scope','unknown_scope'])
def test_transfer_user_relation_holds(mode):
    r=target('user','AWS::Transfer::User',ServerId='s-existing');s=target('server','AWS::Transfer::Server',IdentityProviderType='API_GATEWAY')
    d=linked_design(r,[s],[] if mode=='unlinked' else [('ServerId','server')])
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='cross_scope':s.scope.region='us-east-1'
    if mode=='unknown_scope':s.scope.region=r.scope.region='unknown'
    assert routing_links_checks(d,r)[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('mode,timeout,expected',[
    ('AUTO_STOP',60,'PASS'),('AUTO_STOP',120,'PASS'),('AUTO_STOP',61,'FAIL'),
    ('AUTO_STOP',0,'NEEDS_REVIEW'),('AUTO_STOP',-60,'NEEDS_REVIEW'),
    ('AUTO_STOP',60.0,'NEEDS_REVIEW'),('AUTO_STOP',True,'NEEDS_REVIEW'),
    ('AUTO_STOP',UNKNOWN,'NEEDS_REVIEW'),('ALWAYS_ON',61,'NEEDS_REVIEW'),(UNKNOWN,60,'NEEDS_REVIEW')])
def test_autostop_interval(mode,timeout,expected):
    assert check('WorkSpaces::Workspace',WorkspaceProperties={'RunningMode':mode,'RunningModeAutoStopTimeoutInMinutes':timeout})[0]['verdict']==expected


def test_checker_integration():
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('subject','AWS::StepFunctions::StateMachineAlias',RoutingConfiguration=[{'Weight':90,'StateMachineVersionArn':ARN+'machine:1'}])
    row=next(x for x in Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results'] if x['rule_id']=='STEPFUNCTIONS_ALIAS_WEIGHT_TOTAL')
    assert row['verdict']=='FAIL' and row['source_urls'] and row['evidence_ids']
