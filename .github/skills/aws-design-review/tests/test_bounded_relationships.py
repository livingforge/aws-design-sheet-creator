from pathlib import Path
import pytest
from aws_design_sheet.checks.cognito.user_pool_client_and_user import evaluate_cognito_user_pool_client_and_user
from aws_design_sheet.checks.datasync.task_rate_interval import evaluate_datasync_task_rate_interval
from aws_design_sheet.checks.fsx.capacity_and_retention import evaluate_fsx_capacity_and_retention
from aws_design_sheet.checks.internetmonitor.resource_family import evaluate_internetmonitor_resource_family
from aws_design_sheet.checks.mediapackagev2.dvb_profile import evaluate_mediapackagev2_dvb_profile
from aws_design_sheet.checks.mediatailor.reserved_headers import evaluate_mediatailor_reserved_headers
from aws_design_sheet.checks.oam.filter_operands import evaluate_oam_filter_operands
from aws_design_sheet.checks.registry import combine
triage_relations_checks = combine(evaluate_cognito_user_pool_client_and_user, evaluate_datasync_task_rate_interval, evaluate_fsx_capacity_and_retention, evaluate_internetmonitor_resource_family, evaluate_mediapackagev2_dvb_profile, evaluate_mediatailor_reserved_headers, evaluate_oam_filter_operands)
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN

def check(kind,rule,**props):
 r=target('subject','AWS::'+kind,**props)
 return [x for x in triage_relations_checks(linked_design(r),r) if x['rule_id']==rule]

@pytest.mark.parametrize('attrs,mediums,expected',[([],['EMAIL'],'FAIL'),([{'Name':'email','Value':'x'}],['EMAIL'],'PASS'),([UNKNOWN],['EMAIL'],'NEEDS_REVIEW'),([{'Name':'email_verified','Value':'true'}],[],'FAIL'),([{'Name':'email','Value':UNKNOWN}],['EMAIL'],'NEEDS_REVIEW')])
def test_contact(attrs,mediums,expected):
 assert check('Cognito::UserPoolUser','COGNITO_USER_CONTACT_REQUIRED',UserAttributes=attrs,DesiredDeliveryMediums=mediums)[0]['verdict']==expected

def test_suppressed_delivery_is_held():
 rows=check('Cognito::UserPoolUser','COGNITO_USER_CONTACT_REQUIRED',MessageAction='SUPPRESS')
 assert rows[1]['verdict']=='NEEDS_REVIEW'

@pytest.mark.parametrize('kind,field',[('MetricConfiguration','Namespace'),('LogGroupConfiguration','LogGroupName')])
@pytest.mark.parametrize('count,expected',[(5,'PASS'),(6,'FAIL')])
def test_oam_operand_boundary(kind,field,count,expected):
 expression=' OR '.join([field+" = 'AND OR'"]*(count+1))
 assert check('Oam::Link','OAM_FILTER_OPERANDS',LinkConfiguration={kind:{'Filter':expression}})[0]['verdict']==expected

@pytest.mark.parametrize('raw,expected',[("Namespace IN ('AND', 'OR') AND Namespace NOT LIKE 'AWS/%'",'PASS'),("(Namespace = 'x')",'NEEDS_REVIEW'),("Namespace = 'unterminated",'NEEDS_REVIEW'),('*','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_oam_quoted_and_unsupported(raw,expected):
 assert check('Oam::Link','OAM_FILTER_OPERANDS',LinkConfiguration={'MetricConfiguration':{'Filter':raw}})[0]['verdict']==expected

@pytest.mark.parametrize('uri,expected',[('https://example.com','PASS'),('http://localhost:3000/cb','PASS'),('http://127.0.0.1/cb','PASS'),('http://[::1]/cb','PASS'),('http://example.com','FAIL'),('/relative','FAIL'),('https://example.com/#','FAIL'),('myapp://example','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_callbacks(uri,expected):
 assert check('Cognito::UserPoolClient','COGNITO_CALLBACK_URI',CallbackURLs=[uri])[0]['verdict']==expected

@pytest.mark.parametrize('expression,expected',[('rate(59 minutes)','FAIL'),('rate(60 minutes)','PASS'),('rate(1 hour)','PASS'),('rate(2 days)','PASS'),('cron(0 * * * ? *)','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_rate(expression,expected):
 assert check('DataSync::Task','DATASYNC_RATE_INTERVAL',Schedule={'ScheduleExpression':expression})[0]['verdict']==expected

@pytest.mark.parametrize('deployment,storage,throughput,size,expected',[
 ('SCRATCH_1','SSD',None,1200,'PASS'),('SCRATCH_1','SSD',None,2400,'PASS'),('SCRATCH_1','SSD',None,3600,'PASS'),('SCRATCH_1','SSD',None,4800,'FAIL'),
 ('SCRATCH_2','SSD',None,4800,'PASS'),('PERSISTENT_2','SSD',None,3600,'FAIL'),
 ('PERSISTENT_1','HDD',12,6000,'PASS'),('PERSISTENT_1','HDD',40,1800,'PASS'),('PERSISTENT_1','HDD',12,1800,'FAIL'),('PERSISTENT_1',UNKNOWN,12,6000,'NEEDS_REVIEW'),('PERSISTENT_1','HDD',UNKNOWN,6000,'NEEDS_REVIEW')])
def test_capacity(deployment,storage,throughput,size,expected):
 assert check('FSx::FileSystem','FSX_LUSTRE_CAPACITY_INCREMENT',FileSystemType='LUSTRE',StorageType=storage,StorageCapacity=size,LustreConfiguration={'DeploymentType':deployment,'PerUnitStorageThroughput':throughput})[0]['verdict']==expected

@pytest.mark.parametrize('values,units,expected',[([1,2,3],['DAYS']*3,'PASS'),([1,4,3],['DAYS']*3,'FAIL'),([1,1,1],['MONTHS']*3,'PASS'),([1,2,3],['DAYS','MONTHS','YEARS'],'NEEDS_REVIEW'),([1,UNKNOWN,3],['DAYS']*3,'NEEDS_REVIEW')])
def test_retention(values,units,expected):
 retention={k:{'Value':v,'Type':u} for k,v,u in zip(('MinimumRetention','DefaultRetention','MaximumRetention'),values,units)}
 assert check('FSx::Volume','FSX_RETENTION_SAME_UNIT',OntapConfiguration={'SnaplockConfiguration':{'RetentionPeriod':retention}})[0]['verdict']==expected

VPC='arn:aws:ec2:us-east-1:111111111111:vpc/vpc-abc'
CF='arn:aws:cloudfront::111111111111:distribution/ABC'
NLB='arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/net/name/abc'
WS='arn:aws:workspaces:us-east-1:111111111111:directory/d-abc'
@pytest.mark.parametrize('arns,expected',[([VPC,CF],'PASS'),([NLB,NLB],'PASS'),([WS,WS],'PASS'),([VPC,NLB],'FAIL'),([NLB,WS],'FAIL'),([WS,UNKNOWN],'NEEDS_REVIEW'),([VPC,NLB,UNKNOWN],'FAIL')])
def test_monitor(arns,expected):
 assert check('InternetMonitor::Monitor','INTERNETMONITOR_RESOURCE_FAMILY',ResourcesToAdd=arns)[0]['verdict']==expected

@pytest.mark.parametrize('profiles,expected',[(['DVB_DASH'],'PASS'),([],'FAIL'),([UNKNOWN],'NEEDS_REVIEW'),(['FUTURE'],'NEEDS_REVIEW')])
def test_profiles(profiles,expected):
 rows=check('MediaPackageV2::OriginEndpoint','MEDIAPACKAGE_DVB_PROFILE',DashManifests=[{'Profiles':profiles,'BaseUrls':[{'DvbPriority':1,'DvbWeight':2}]}])
 assert len(rows)==2 and all(x['verdict']==expected for x in rows)

@pytest.mark.parametrize('key,expected',[('X-Amz-Test','FAIL'),('x-amz-test','FAIL'),('Accept','PASS'),('${header}','NEEDS_REVIEW')])
def test_headers(key,expected):
 assert check('MediaTailor::Function','MEDIATAILOR_RESERVED_HEADERS',VastRequestConfiguration={'Headers':{key:'value'}})[0]['verdict']==expected

def test_checker():
 from aws_design_sheet.checker import Checker
 root=Path(__file__).resolve().parents[1]
 r=target('subject','AWS::DataSync::Task',Schedule={'ScheduleExpression':'rate(5 minutes)'})
 row=next(x for x in Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results'] if x['rule_id']=='DATASYNC_RATE_INTERVAL')
 assert row['verdict']=='FAIL' and row['source_urls'] and row['evidence_ids']
