"""Design boundaries, uncertainty and explicit cross-resource relations."""
from pathlib import Path
import pytest
from aws_design_sheet.checks.sagemaker.deployment_ratios import evaluate_sagemaker_deployment_ratios
from aws_design_sheet.checks.servicediscovery.instance import evaluate_servicediscovery_instance
from aws_design_sheet.checks.ses.runtime_bounds import evaluate_ses_runtime_bounds
from aws_design_sheet.checks.shield.proactive_phone import evaluate_shield_proactive_phone
from aws_design_sheet.checks.registry import combine
runtime_bounds_checks = combine(evaluate_sagemaker_deployment_ratios, evaluate_servicediscovery_instance, evaluate_ses_runtime_bounds, evaluate_shield_proactive_phone)
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def check(kind,rule=None,**props):
    r=target('subject','AWS::'+kind,**props)
    rows=runtime_bounds_checks(linked_design(r),r)
    return [x for x in rows if rule is None or x['rule_id']==rule]


@pytest.mark.parametrize('kind,size,copies,expected',[
    ('CAPACITY_PERCENT',5,UNKNOWN,'PASS'),('CAPACITY_PERCENT',50,UNKNOWN,'PASS'),
    ('CAPACITY_PERCENT',4,100,'FAIL'),('CAPACITY_PERCENT',51,100,'FAIL'),
    ('COPY_COUNT',1,20,'PASS'),('COPY_COUNT',10,20,'PASS'),('COPY_COUNT',11,20,'FAIL'),
    ('COPY_COUNT',1,21,'FAIL'),('COPY_COUNT',1,19,'PASS'),('COPY_COUNT',1,1,'FAIL'),
    ('COPY_COUNT',1,0,'NEEDS_REVIEW'),('COPY_COUNT',1,UNKNOWN,'NEEDS_REVIEW'),
    ('COPY_COUNT',1,True,'NEEDS_REVIEW'),('COPY_COUNT',True,20,'NEEDS_REVIEW'),
    ('COPY_COUNT',1.0,20,'NEEDS_REVIEW'),('COPY_COUNT',UNKNOWN,20,'NEEDS_REVIEW'),
    (UNKNOWN,5,20,'NEEDS_REVIEW'),('INSTANCE_COUNT',5,20,'NEEDS_REVIEW')])
def test_component_ratio(kind,size,copies,expected):
    assert check('SageMaker::InferenceComponent',RuntimeConfig={'CopyCount':copies},DeploymentConfig={'RollingUpdatePolicy':{'MaximumBatchSize':{'Type':kind,'Value':size}}})[0]['verdict']==expected


@pytest.mark.parametrize('extra,expected',[
    ({'CurrentCopyCount':20,'DesiredCopyCount':20},'PASS'),
    ({'CurrentCopyCount':40},'NEEDS_REVIEW'),({'DesiredCopyCount':UNKNOWN},'NEEDS_REVIEW'),
    ({'CurrentCopyCount':True},'NEEDS_REVIEW')])
def test_component_observed_counts(extra,expected):
    assert check('SageMaker::InferenceComponent',RuntimeConfig={'CopyCount':20,**extra},DeploymentConfig={'RollingUpdatePolicy':{'MaximumBatchSize':{'Type':'COPY_COUNT','Value':1}}})[0]['verdict']==expected


@pytest.mark.parametrize('start,end,expected',[
    ('-PT25H','-PT1H','PASS'),('-PT25H','PT0H','FAIL'),('-P1D','PT0S','PASS'),
    ('-PT24H1S','PT0H','FAIL'),('-PT23H59M59S','PT0H','PASS'),
    ('-PT30M','PT30M','PASS'),('PT0H','P1DT1S','FAIL'),
    ('-PT1H','-PT1H','NEEDS_REVIEW'),('PT1H','PT0H','NEEDS_REVIEW'),
    ('-P1M','PT0H','NEEDS_REVIEW'),('-P1Y','PT0H','NEEDS_REVIEW'),
    ('-PT1.5H','PT0H','NEEDS_REVIEW'),('-P1W','PT0H','NEEDS_REVIEW'),
    ('-PT1H',UNKNOWN,'NEEDS_REVIEW'),(UNKNOWN,'PT0H','NEEDS_REVIEW'),
    ('P','PT0H','NEEDS_REVIEW'),('PT','PT0H','NEEDS_REVIEW'),
    ('P1DT','PT0H','NEEDS_REVIEW'),('-PT999999999999H','PT0H','NEEDS_REVIEW')])
@pytest.mark.parametrize('expression',['NOW','cron(0 * ? * * *)'])
def test_monitoring_window(start,end,expected,expression):
    assert check('SageMaker::MonitoringSchedule',MonitoringScheduleConfig={'ScheduleConfig':{'ScheduleExpression':expression,'DataAnalysisStartTime':start,'DataAnalysisEndTime':end}})[0]['verdict']==expected


@pytest.mark.parametrize('records,policy,expected',[
    ([{'Type':'A'}],'WEIGHTED','PASS'),([{'Type':'AAAA'}],'WEIGHTED','PASS'),
    ([{'Type':'A'},UNKNOWN],'WEIGHTED','PASS'),([{'Type':'A'}],'MULTIVALUE','FAIL'),
    ([{'Type':'CNAME'}],'WEIGHTED','FAIL'),([],'WEIGHTED','FAIL'),
    ([UNKNOWN],'WEIGHTED','NEEDS_REVIEW'),(UNKNOWN,'WEIGHTED','NEEDS_REVIEW'),
    ([{'Type':'A'}],UNKNOWN,'NEEDS_REVIEW'),(UNKNOWN,'MULTIVALUE','FAIL')])
def test_alias_service(records,policy,expected):
    r=target('instance','AWS::ServiceDiscovery::Instance',InstanceAttributes={'AWS_ALIAS_DNS_NAME':'elb.example.com'})
    service=target('service','AWS::ServiceDiscovery::Service',DnsConfig={'DnsRecords':records,'RoutingPolicy':policy})
    rows=runtime_bounds_checks(linked_design(r,[service],[('ServiceId','service')]),r)
    assert next(x for x in rows if x['rule_id']=='SERVICEDISCOVERY_ALIAS_SERVICE')['verdict']==expected


@pytest.mark.parametrize('mode',['no_link','conditional','cross_scope','unknown_alias','unknown_scope','missing_policy','missing_dns'])
def test_alias_relation_holds(mode):
    r=target('instance','AWS::ServiceDiscovery::Instance',InstanceAttributes={'AWS_ALIAS_DNS_NAME':UNKNOWN if mode=='unknown_alias' else 'elb.example.com'})
    service=target('service','AWS::ServiceDiscovery::Service',DnsConfig={'DnsRecords':[{'Type':'A'}],'RoutingPolicy':'WEIGHTED'})
    if mode=='missing_policy':service=target('service','AWS::ServiceDiscovery::Service',DnsConfig={'DnsRecords':[{'Type':'A'}]})
    if mode=='missing_dns':service=target('service','AWS::ServiceDiscovery::Service')
    if mode=='cross_scope':service.scope.region='us-east-1'
    if mode=='unknown_scope':r.scope.region=service.scope.region='unknown'
    d=linked_design(r,[service],[] if mode=='no_link' else [('ServiceId','service')])
    if mode=='conditional':d.relations[0].condition='Maybe'
    row=next(x for x in runtime_bounds_checks(d,r) if x['rule_id']=='SERVICEDISCOVERY_ALIAS_SERVICE')
    assert row['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('attrs,expected',[
    ({'AWS_INSTANCE_IPV4':'192.0.2.1'},'FAIL'),({'AWS_INSTANCE_IPV6':'2001:db8::1'},'FAIL'),
    ({'AWS_INSTANCE_PORT':'443'},'FAIL'),({'AWS_INSTANCE_CNAME':'example.com'},'FAIL'),
    ({'AWS_INSTANCE_FUTURE':'x'},'NEEDS_REVIEW'),({'AWS_INSTANCE_IPV4':UNKNOWN},'NEEDS_REVIEW'),
    ({'custom':'value'},'PASS'),({'AWS_INSTANCE_PORT':'443','AWS_INSTANCE_IPV4':UNKNOWN},'FAIL')])
def test_alias_attributes(attrs,expected):
    assert check('ServiceDiscovery::Instance','SERVICEDISCOVERY_ALIAS_ATTRIBUTES',InstanceAttributes={'AWS_ALIAS_DNS_NAME':'elb.example.com',**attrs})[0]['verdict']==expected


@pytest.mark.parametrize('identity,domain,expected',[
    ('example.com','bounce.example.com','PASS'),('example.com','a.b.example.com','PASS'),
    ('example.com','example.com','FAIL'),('example.com','notexample.com','FAIL'),
    ('example.com','example.com.evil.test','FAIL'),('user@example.com','bounce.example.com','NEEDS_REVIEW'),
    ('Example.com','bounce.example.com','NEEDS_REVIEW'),('example.com','xn--bcher-kva.example.com','NEEDS_REVIEW'),
    (UNKNOWN,'bounce.example.com','NEEDS_REVIEW'),('example.com',UNKNOWN,'NEEDS_REVIEW')])
def test_mail_from(identity,domain,expected):
    assert check('SES::EmailIdentity',EmailIdentity=identity,MailFromAttributes={'MailFromDomain':domain})[0]['verdict']==expected


@pytest.mark.parametrize('identity,address,expected',[
    ('example.com','alice@example.com','PASS'),('example.com','alice@child.example.com','PASS'),
    ('example.com','alice@notexample.com','FAIL'),('alice@example.com','alice@example.com','PASS'),
    ('alice@example.com','Alice@example.com','FAIL'),('alice@example.com','bob@example.com','FAIL'),
    ('example.com','Name <alice@example.com>','NEEDS_REVIEW'),('example.com','"alice"@example.com','NEEDS_REVIEW'),
    ('Example.com','alice@example.com','NEEDS_REVIEW'),('example.com',UNKNOWN,'NEEDS_REVIEW'),
    (UNKNOWN,'alice@example.com','NEEDS_REVIEW')])
def test_certificate_address(identity,address,expected):
    assert check('SES::EmailIdentityCertificate',EmailIdentity=identity,FromAddress=address)[0]['verdict']==expected


@pytest.mark.parametrize('cidr,policy,expected',[
    ('10.0.0.1','Allow','PASS'),('10.0.0.1/24','Block','PASS'),('0.0.0.0/0','Allow','PASS'),
    ('2001:db8::1/64','Allow','PASS'),('2001:db8::1','Block','PASS'),
    ('999.0.0.1','Allow','FAIL'),('10.0.0.1/33','Allow','FAIL'),('example.com','Allow','FAIL'),
    ('10.0.0.1','allow','FAIL'),('10.0.0.1/255.255.255.0','Allow','NEEDS_REVIEW'),
    ('fe80::1%eth0','Allow','NEEDS_REVIEW'),(UNKNOWN,'Allow','NEEDS_REVIEW'),
    ('10.0.0.1',UNKNOWN,'NEEDS_REVIEW'),(UNKNOWN,'bad','FAIL')])
def test_receipt_filter(cidr,policy,expected):
    assert check('SES::ReceiptFilter',Filter={'IpFilter':{'Cidr':cidr,'Policy':policy}})[0]['verdict']==expected


@pytest.mark.parametrize('contacts,status,expected',[
    ([{'PhoneNumber':'+10000000001'}],'ENABLED','PASS'),
    ([{'PhoneNumber':'+10000000001'},UNKNOWN],'ENABLED','PASS'),
    ([{'EmailAddress':'ops@example.com'}],'ENABLED','FAIL'),([], 'ENABLED','FAIL'),
    ([UNKNOWN],'ENABLED','NEEDS_REVIEW'),(UNKNOWN,'ENABLED','NEEDS_REVIEW'),
    ([{'PhoneNumber':UNKNOWN}],'ENABLED','NEEDS_REVIEW'),
    ([{'PhoneNumber':'+10000000001'}],UNKNOWN,'NEEDS_REVIEW')])
def test_shield_phone(contacts,status,expected):
    assert check('Shield::ProactiveEngagement',ProactiveEngagementStatus=status,EmergencyContactList=contacts)[0]['verdict']==expected


def test_omitted_fields():
    assert check('SageMaker::InferenceComponent',DeploymentConfig={'RollingUpdatePolicy':{'RollbackMaximumBatchSize':{'Type':'CAPACITY_PERCENT','Value':100}}})==[]
    assert check('SageMaker::MonitoringSchedule',MonitoringScheduleConfig={'ScheduleConfig':{'ScheduleExpression':'NOW'}})==[]
    assert check('SageMaker::MonitoringSchedule',MonitoringScheduleConfig={'ScheduleConfig':{'DataAnalysisStartTime':'-PT1H'}})[0]['verdict']=='NEEDS_REVIEW'
    assert check('ServiceDiscovery::Instance',InstanceAttributes={'AWS_INSTANCE_IPV4':'192.0.2.1'})==[]
    assert check('Shield::ProactiveEngagement',ProactiveEngagementStatus='DISABLED')==[]
    assert check('Shield::ProactiveEngagement',ProactiveEngagementStatus='ENABLED')[0]['verdict']=='FAIL'


def test_checker_integration():
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('subject','AWS::SES::EmailIdentity',EmailIdentity='example.com',MailFromAttributes={'MailFromDomain':'other.com'})
    row=next(x for x in Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results'] if x['rule_id']=='SES_MAIL_FROM_SUBDOMAIN')
    assert row['verdict']=='FAIL' and row['source_urls'] and row['evidence_ids']
