import base64
from pathlib import Path
import pytest
from aws_design_sheet.checks.amazonmq.queue_connections import mq_xml, evaluate_amazonmq_queue_connections
from aws_design_sheet.checks.amplify.access_token_provider import amplify_provider, evaluate_amplify_access_token_provider
from aws_design_sheet.checks.aiops.notification_sns_type import evaluate_aiops_notification_sns_type
from aws_design_sheet.checks.aps.scraper_vpc_alignment import evaluate_aps_scraper_vpc_alignment
from aws_design_sheet.checks.registry import combine
queue_connections_checks = combine(evaluate_aiops_notification_sns_type, evaluate_amazonmq_queue_connections, evaluate_amplify_access_token_provider, evaluate_aps_scraper_vpc_alignment)
from aws_design_sheet.models import Relation
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('engine,mode,public,count,expected',[
 ('ACTIVEMQ','SINGLE_INSTANCE',True,1,'PASS'),('ACTIVEMQ','SINGLE_INSTANCE',False,2,'FAIL'),
 ('ACTIVEMQ','ACTIVE_STANDBY_MULTI_AZ',False,2,'PASS'),('ACTIVEMQ','ACTIVE_STANDBY_MULTI_AZ',False,1,'FAIL'),
 ('RABBITMQ','CLUSTER_MULTI_AZ',False,1,'PASS'),('RABBITMQ','CLUSTER_MULTI_AZ',False,0,'FAIL'),
 ('RABBITMQ','CLUSTER_MULTI_AZ',True,0,'NOT_APPLICABLE'),('RABBITMQ','CLUSTER_MULTI_AZ',UNKNOWN,0,'NEEDS_REVIEW'),
 ('RABBITMQ','ACTIVE_STANDBY_MULTI_AZ',False,2,'NEEDS_REVIEW'),('FUTURE','SINGLE_INSTANCE',False,1,'NEEDS_REVIEW')])
def test_mq_count(engine,mode,public,count,expected):
 r=target('main','AWS::AmazonMQ::Broker',EngineType=engine,DeploymentMode=mode,PubliclyAccessible=public,SubnetIds=['s']*count)
 assert queue_connections_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('case',['distinct','same','unknown','external','conditional','az_id'])
def test_mq_az(case):
 r=target('main','AWS::AmazonMQ::Broker',SubnetIds=['a','b'])
 a=target('a','AWS::EC2::Subnet',AvailabilityZone='ap-northeast-1a')
 b=target('b','AWS::EC2::Subnet',AvailabilityZone=UNKNOWN if case=='unknown' else 'apne1-az1' if case=='az_id' else 'ap-northeast-1a' if case=='same' else 'ap-northeast-1c')
 d=linked_design(r,[a,b],[('SubnetIds/0','a')]+([] if case=='external' else [('SubnetIds/1','b')]))
 if case=='conditional':d.relations[-1].condition='condition'
 assert queue_connections_checks(d,r)[-1]['verdict']==('PASS' if case=='distinct' else 'FAIL' if case=='same' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('case,expected',[('valid','PASS'),('broken','FAIL'),('dtd','NEEDS_REVIEW'),('entity','NEEDS_REVIEW'),('deep','NEEDS_REVIEW'),('non_xml','FAIL')])
def test_xml(case,expected):
 text={'valid':'<broker><x/></broker>','broken':'<broker>','dtd':'<!DOCTYPE broker><broker/>','entity':'<!DOCTYPE broker [<!ENTITY x "value">]><broker>&x;</broker>','deep':'<x>'*66+'</x>'*66,'non_xml':'hello'}[case]
 assert mq_xml(base64.b64encode(text.encode()).decode())==expected


@pytest.mark.parametrize('url,expected',[('https://github.com/a/b','PASS'),('https://bitbucket.org/a/b','FAIL'),('https://gitlab.com/a/b','FAIL'),('https://git-codecommit.ap-northeast-1.amazonaws.com/v1/repos/a','FAIL'),('https://github.com.evil.test/a/b','NEEDS_REVIEW'),('https://github.com@bitbucket.org/a/b','NEEDS_REVIEW'),('git@github.com:a/b','NEEDS_REVIEW'),('https://example.test/a','NEEDS_REVIEW'),('https://github.com:bad/a','NEEDS_REVIEW'),('${repository}','NEEDS_REVIEW')])
def test_provider(url,expected):
 assert amplify_provider(url)==expected


@pytest.mark.parametrize('case',['same','different','unknown','external','conditional','cluster_unknown'])
def test_scraper_vpc(case):
 r=target('main','AWS::APS::Scraper',Source={'EksConfiguration':{'ClusterArn':'cluster','SubnetIds':['sub'],'SecurityGroupIds':['sg']}})
 cluster=target('cluster','AWS::EKS::Cluster',ResourcesVpcConfig={'SubnetIds':['sub']})
 sub=target('sub','AWS::EC2::Subnet',VpcId='vpc-one')
 sg=target('sg','AWS::EC2::SecurityGroup',VpcId='vpc-two' if case=='different' else UNKNOWN if case=='unknown' else 'vpc-one')
 links=[('Source/EksConfiguration/ClusterArn','cluster'),('Source/EksConfiguration/SubnetIds/0','sub')]
 if case!='external':links.append(('Source/EksConfiguration/SecurityGroupIds/0','sg'))
 d=linked_design(r,[cluster,sub,sg],links)
 d.relations.append(Relation(id='cluster-subnet',source_resource_id='cluster',source_path='/properties/ResourcesVpcConfig/SubnetIds/0',target_resource_id='sub'))
 if case=='conditional':d.relations[-1].condition='condition'
 if case=='cluster_unknown':cluster.scope.account='unknown'
 assert queue_connections_checks(d,r)[0]['verdict']==('PASS' if case=='same' else 'FAIL' if case=='different' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('service,expected',[('sns','PASS'),('sqs','FAIL'),('lambda','FAIL')])
def test_sns(service,expected):
 r=target('main','AWS::AIOps::InvestigationGroup',ChatbotNotificationChannels=[{'SNSTopicArn':f'arn:aws:{service}:ap-northeast-1:111111111111:topic'}])
 assert queue_connections_checks(linked_design(r),r)[0]['verdict']==expected


def test_checker_secret_not_emitted():
 r=target('main','AWS::Amplify::App',Repository='https://bitbucket.org/a/b',AccessToken='private-token-test')
 root=Path(__file__).resolve().parents[1]
 found=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
 item=next(f for f in found if f['rule_id']=='AMPLIFY_ACCESS_TOKEN_PROVIDER')
 assert item['verdict']=='FAIL' and 'private-token-test' not in str(item)
