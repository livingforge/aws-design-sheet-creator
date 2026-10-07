from pathlib import Path
import pytest
from aws_design_sheet.checks.datasync.task import evaluate_datasync_task
from aws_design_sheet.checks.datazone.blueprint_domain_version import evaluate_datazone_blueprint_domain_version
from aws_design_sheet.checks.devopsguru.standard_topic import evaluate_devopsguru_standard_topic
from aws_design_sheet.checks.codebuild.project_public_bounds import evaluate_codebuild_project_public_bounds
from aws_design_sheet.checks.registry import combine
transfer_options_checks = combine(evaluate_datasync_task, evaluate_datazone_blueprint_domain_version, evaluate_devopsguru_standard_topic, evaluate_codebuild_project_public_bounds)
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def linked_case(r,other,path,mode):
    d=linked_design(r,[other],[] if mode=='literal' else [(path,other.id)])
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='scope':other.scope.account='222222222222'
    return d


@pytest.mark.parametrize('side',['SourceLocationArn','DestinationLocationArn'])
@pytest.mark.parametrize('mode',['linked','literal','conditional','scope'])
def test_efs(side,mode):
    r=target('main','AWS::DataSync::Task',Options={'PreserveDevices':'PRESERVE'},**{side:'efs'})
    efs=target('efs','AWS::DataSync::LocationEFS')
    assert transfer_options_checks(linked_case(r,efs,side,mode),r)[0]['verdict']==('FAIL' if mode=='linked' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('storage,expected',[('GLACIER','FAIL'),('DEEP_ARCHIVE','FAIL'),('STANDARD','PASS'),('GLACIER_INSTANT_RETRIEVAL','PASS'),(UNKNOWN,'NEEDS_REVIEW'),(None,'NEEDS_REVIEW')])
@pytest.mark.parametrize('mode',['linked','literal','conditional','scope'])
def test_archive(storage,expected,mode):
    r=target('main','AWS::DataSync::Task',Options={'VerifyMode':'POINT_IN_TIME_CONSISTENT'},DestinationLocationArn='s3')
    s3=target('s3','AWS::DataSync::LocationS3',**({} if storage is None else {'S3StorageClass':storage}))
    assert transfer_options_checks(linked_case(r,s3,'DestinationLocationArn',mode),r)[0]['verdict']==(expected if mode=='linked' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('version',['V1','V2',UNKNOWN,None])
@pytest.mark.parametrize('mode',['linked','literal','conditional','scope'])
def test_domain_version(version,mode):
    r=target('main','AWS::DataZone::Environment',EnvironmentBlueprintIdentifier='blueprint',DomainIdentifier='domain')
    domain=target('domain','AWS::DataZone::Domain',**({} if version is None else {'DomainVersion':version}))
    expected='NEEDS_REVIEW' if mode!='linked' or version not in ('V1','V2') else 'PASS' if version=='V1' else 'FAIL'
    assert transfer_options_checks(linked_case(r,domain,'DomainIdentifier',mode),r)[0]['verdict']==expected


@pytest.mark.parametrize('fifo,expected',[(True,'FAIL'),(False,'PASS'),(UNKNOWN,'NEEDS_REVIEW'),(None,'NEEDS_REVIEW')])
@pytest.mark.parametrize('mode',['linked','literal','conditional','scope'])
def test_sns_link(fifo,expected,mode):
    r=target('main','AWS::DevOpsGuru::NotificationChannel',Config={'Sns':{'TopicArn':'topic'}})
    topic=target('topic','AWS::SNS::Topic',**({} if fifo is None else {'FifoTopic':fifo}))
    assert transfer_options_checks(linked_case(r,topic,'Config/Sns/TopicArn',mode),r)[0]['verdict']==(expected if mode=='linked' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('name,expected',[('topic','PASS'),('topic.fifo','FAIL'),('topic.invalid','NEEDS_REVIEW')])
def test_sns_arn(name,expected):
    r=target('main','AWS::DevOpsGuru::NotificationChannel',Config={'Sns':{'TopicArn':f'arn:aws:sns:ap-northeast-1:111111111111:{name}'}})
    assert transfer_options_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('field,maximum',[('TimeoutInMinutes',2160),('QueuedTimeoutInMinutes',480)])
@pytest.mark.parametrize('case',['min','max','below','above','unknown','bool'])
def test_codebuild_time(field,maximum,case):
    value={'min':5,'max':maximum,'below':4,'above':maximum+1,'unknown':UNKNOWN,'bool':True}[case]
    r=target('main','AWS::CodeBuild::Project',**{field:value})
    expected='PASS' if case in ('min','max') else 'FAIL' if case in ('below','above') else 'NEEDS_REVIEW'
    assert transfer_options_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('length,expected',[(0,'PASS'),(255,'PASS'),(256,'FAIL')])
def test_description(length,expected):
    r=target('main','AWS::CodeBuild::Project',Description='a'*length)
    assert transfer_options_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('field,limit',[('SecurityGroupIds',5),('Subnets',16)])
@pytest.mark.parametrize('extra',[0,1])
def test_vpc_count(field,limit,extra):
    r=target('main','AWS::CodeBuild::Project',VpcConfig={field:['id']*(limit+extra)})
    assert transfer_options_checks(linked_design(r),r)[0]['verdict']==('FAIL' if extra else 'PASS')


def test_checker_archive():
    r=target('main','AWS::DataSync::Task',Options={'VerifyMode':'POINT_IN_TIME_CONSISTENT'},DestinationLocationArn='s3')
    s3=target('s3','AWS::DataSync::LocationS3',S3StorageClass='GLACIER')
    root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_case(r,s3,'DestinationLocationArn','linked'))['results']
    assert any(f['rule_id']=='DATASYNC_ARCHIVE_VERIFY_MODE' and f['verdict']=='FAIL' for f in results)
