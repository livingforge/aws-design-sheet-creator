from pathlib import Path
import pytest
from aws_design_sheet.checks.budgets.subscriber_counts import evaluate_budgets_subscriber_counts
from aws_design_sheet.checks.codepipeline.queryable_count import evaluate_codepipeline_queryable_count
from aws_design_sheet.checks.cognito.pretoken_equal import evaluate_cognito_pretoken_equal
from aws_design_sheet.checks.dax.cluster_az_and_parameter_keys import evaluate_dax_cluster_az_and_parameter_keys
from aws_design_sheet.checks.networkmanager.peer_family import evaluate_networkmanager_peer_family
from aws_design_sheet.checks.odb.scan_port_exclusions import evaluate_odb_scan_port_exclusions
from aws_design_sheet.checks.registry import combine
finite_values_checks = combine(evaluate_budgets_subscriber_counts, evaluate_codepipeline_queryable_count, evaluate_cognito_pretoken_equal, evaluate_dax_cluster_az_and_parameter_keys, evaluate_networkmanager_peer_family, evaluate_odb_scan_port_exclusions)
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN

def check(kind,**props):
 r=target('subject','AWS::'+kind,**props)
 return finite_values_checks(linked_design(r),r)[0]['verdict']

@pytest.mark.parametrize('kinds,expected',[(['SNS'],'PASS'),(['SNS']*2,'FAIL'),(['EMAIL']*10,'PASS'),(['EMAIL']*11,'FAIL'),(['SNS']+['EMAIL']*10,'PASS'),([UNKNOWN],'NEEDS_REVIEW'),(['SNS','SNS',UNKNOWN],'FAIL')])
def test_budget(kinds,expected):
 assert check('Budgets::Budget',NotificationsWithSubscribers=[{'Subscribers':[{'SubscriptionType':x} for x in kinds]}])==expected

@pytest.mark.parametrize('flags,expected',[([True,False],'PASS'),([True,True],'FAIL'),([True,UNKNOWN],'NEEDS_REVIEW'),([True,True,UNKNOWN],'FAIL'),([1],'NEEDS_REVIEW'),([None],'NEEDS_REVIEW')])
def test_queryable(flags,expected):
 assert check('CodePipeline::CustomActionType',ConfigurationProperties=[{} if f is None else {'Queryable':f} for f in flags])==expected

@pytest.mark.parametrize('a,b,expected',[('arn:a','arn:a','PASS'),('arn:a','arn:b','FAIL'),(UNKNOWN,'arn:b','NEEDS_REVIEW'),('arn:a',None,'NOT_APPLICABLE')])
def test_pretoken(a,b,expected):
 config={'PreTokenGeneration':a}
 if b is not None:config['PreTokenGenerationConfig']={'LambdaArn':b}
 assert check('Cognito::UserPool',LambdaConfig=config)==expected

@pytest.mark.parametrize('zones,count,expected',[(['a','b'],2,'PASS'),(['a'],2,'FAIL'),([UNKNOWN],1,'PASS'),(UNKNOWN,1,'NEEDS_REVIEW'),(['a'],True,'NEEDS_REVIEW'),(['a'],UNKNOWN,'NEEDS_REVIEW')])
def test_dax_count(zones,count,expected):
 assert check('DAX::Cluster',AvailabilityZones=zones,ReplicationFactor=count)==expected

@pytest.mark.parametrize('values,expected',[({'record-ttl-millis':'5'},'PASS'),({'query-ttl-millis':UNKNOWN},'PASS'),({'bad':'5'},'FAIL'),(UNKNOWN,'NEEDS_REVIEW'),({'${key}':'5'},'NEEDS_REVIEW'),([],'NEEDS_REVIEW')])
def test_dax_keys(values,expected):
 assert check('DAX::ParameterGroup',ParameterNameValues=values)==expected

@pytest.mark.parametrize('a,b,expected',[('10.0.0.1','10.0.0.2','PASS'),('2001:db8::1','2001:db8::2','PASS'),('10.0.0.1','2001:db8::2','FAIL'),('bad','10.0.0.2','NEEDS_REVIEW'),(UNKNOWN,'10.0.0.2','NEEDS_REVIEW'),('fe80::1%eth0','fe80::2','NEEDS_REVIEW')])
def test_family(a,b,expected):
 assert check('NetworkManager::ConnectPeer',PeerAddress=a,CoreNetworkAddress=b)==expected

@pytest.mark.parametrize('port,expected',[(1023,'FAIL'),(1024,'PASS'),(8999,'PASS'),(9000,'FAIL'),(True,'NEEDS_REVIEW'),(1521.0,'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')]+[(n,'FAIL') for n in (2484,6100,6200,7060,7070,7085,7879)])
def test_ports(port,expected):
 assert check('ODB::CloudVmCluster',ScanListenerPortTcp=port)==expected

def test_checker():
 from aws_design_sheet.checker import Checker
 root=Path(__file__).resolve().parents[1]
 r=target('subject','AWS::DAX::Cluster',AvailabilityZones=['a'],ReplicationFactor=3)
 row=next(x for x in Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results'] if x['rule_id']=='DAX_AZ_COUNT')
 assert row['verdict']=='FAIL' and row['source_urls'] and row['evidence_ids']
