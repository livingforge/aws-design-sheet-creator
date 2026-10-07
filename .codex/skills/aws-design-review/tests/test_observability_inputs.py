from pathlib import Path
import pytest
from aws_design_sheet.checks.observabilityadmin.log_key_scope import evaluate_observabilityadmin_log_key_scope
from aws_design_sheet.checks.opensearchserverless.security_policy_json import evaluate_opensearchserverless_security_policy_json
from aws_design_sheet.checks.msk.client_subnet_distinct_azs import evaluate_msk_client_subnet_distinct_azs
from aws_design_sheet.checks.registry import combine
observability_inputs_checks = combine(evaluate_observabilityadmin_log_key_scope, evaluate_opensearchserverless_security_policy_json, evaluate_msk_client_subnet_distinct_azs)
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('strategy',['AWS_OWNED',UNKNOWN])
def test_primary_strategy_held(strategy):
    r=target('main','AWS::ObservabilityAdmin::OrganizationCentralizationRule',Rule={'Destination':{'Account':'111111111111','Region':'ap-northeast-1','DestinationLogsConfiguration':{'LogsEncryptionConfiguration':{'EncryptionStrategy':strategy,'KmsKeyArn':'arn:aws:kms:us-east-1:222222222222:key/example'}}}})
    assert observability_inputs_checks(linked_design(r),r)[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('backup',[False,True])
@pytest.mark.parametrize('mode',['same','account','region','unknown_account','omitted_account','unknown_region','unknown_key','alias','template'])
def test_key_scope(backup,mode):
    key=UNKNOWN if mode=='unknown_key' else 'arn:aws:kms:'+('us-east-1' if mode=='region' else 'ap-northeast-1')+':'+('222222222222' if mode=='account' else '111111111111')+(':'+ 'alias/example' if mode=='alias' else ':key/12345678-1234-1234-1234-123456789012')
    region=UNKNOWN if mode=='unknown_region' else 'ap-northeast-1'
    destination={'Region':'us-east-1' if backup else region,'DestinationLogsConfiguration':{'BackupConfiguration' if backup else 'LogsEncryptionConfiguration':dict(KmsKeyArn=key,**({'Region':region} if backup else {'EncryptionStrategy':'CUSTOMER_MANAGED'}))}}
    if mode!='omitted_account':destination['Account']=UNKNOWN if mode=='unknown_account' else '111111111111'
    r=target('main','AWS::ObservabilityAdmin::OrganizationCentralizationRule',Rule={'Destination':destination})
    if mode=='template':r.template=TemplateContext(state='UNRESOLVED')
    assert observability_inputs_checks(linked_design(r),r)[0]['verdict']==('PASS' if mode=='same' else 'FAIL' if mode in ('account','region') else 'NEEDS_REVIEW')


@pytest.mark.parametrize('raw,verdict',[('{}','PASS'),('[{}]','PASS'),('{ "Rules": [] }','PASS'),('{','FAIL'),('NaN','FAIL'),(UNKNOWN,'NEEDS_REVIEW'),('${policy}','NEEDS_REVIEW')])
def test_policy(raw,verdict):
    r=target('main','AWS::OpenSearchServerless::SecurityPolicy',Policy=raw)
    assert observability_inputs_checks(linked_design(r),r)[0]['verdict']==verdict


@pytest.mark.parametrize('mode',['distinct','duplicate','unknown_az','missing','conditional','ambiguous','scope','template','subnet_template','unknown_list'])
def test_zones(mode):
    r=target('main','AWS::MSK::Cluster',BrokerNodeGroupInfo={'ClientSubnets':UNKNOWN if mode=='unknown_list' else ['one','two']})
    one=target('one','AWS::EC2::Subnet',AvailabilityZone='ap-northeast-1a')
    two=target('two','AWS::EC2::Subnet',AvailabilityZone=UNKNOWN if mode=='unknown_az' else 'ap-northeast-1a' if mode=='duplicate' else 'ap-northeast-1b')
    d=linked_design(r,[one,two],[('BrokerNodeGroupInfo/ClientSubnets/0','one')]+([] if mode=='missing' else [('BrokerNodeGroupInfo/ClientSubnets/1','two')]))
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='ambiguous':d.relations.append(d.relations[0].model_copy(update={'id':'duplicate'}))
    if mode=='scope':two.scope.account='222222222222'
    if mode=='template':r.template=TemplateContext(state='UNRESOLVED')
    if mode=='subnet_template':two.template=TemplateContext(state='UNRESOLVED')
    assert observability_inputs_checks(d,r)[0]['verdict']==('PASS' if mode=='distinct' else 'FAIL' if mode=='duplicate' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('kind',['AWS::ObservabilityAdmin::OrganizationCentralizationRule','AWS::OpenSearchServerless::SecurityPolicy','AWS::MSK::Cluster'])
def test_absent(kind):
    r=target('main',kind)
    assert not observability_inputs_checks(linked_design(r),r)


def test_checker_json():
    r=target('main','AWS::OpenSearchServerless::SecurityPolicy',Policy='{')
    root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='OPENSEARCHSERVERLESS_SECURITY_POLICY_JSON' and f['verdict']=='FAIL' for f in results)
