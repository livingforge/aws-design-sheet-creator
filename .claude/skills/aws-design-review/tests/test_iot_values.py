from pathlib import Path
import pytest
from aws_design_sheet.checks.iot.unit_and_action_values import evaluate_iot_unit_and_action_values
from aws_design_sheet.checks.gamelift.container_log_bucket_region import evaluate_gamelift_container_log_bucket_region
from aws_design_sheet.checks.registry import combine
iot_values_checks = combine(evaluate_iot_unit_and_action_values, evaluate_gamelift_container_log_bucket_region)
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('threshold,factor,expected',[(10.99,1.5,['PASS','PASS']),(10.999,1.55,['FAIL','FAIL']),(UNKNOWN,1.5,['NEEDS_REVIEW','PASS']),(10,UNKNOWN,['PASS','NEEDS_REVIEW'])])
def test_job(threshold,factor,expected):
    r=target('main','AWS::IoT::JobTemplate',AbortConfig={'CriteriaList':[{'ThresholdPercentage':threshold}]},JobExecutionsRolloutConfig={'ExponentialRate':{'IncrementFactor':factor}})
    assert [f['verdict'] for f in iot_values_checks(linked_design(r),r)]==expected


@pytest.mark.parametrize('kind',['quality','format','alarm'])
@pytest.mark.parametrize('error',[False,True])
@pytest.mark.parametrize('mode',['valid','invalid','template','unknown'])
def test_actions(kind,error,mode):
    raw={'quality':'GOOD','format':'UTF8_DATA','alarm':'ALARM'}[kind]
    if mode=='invalid':raw='invalid'
    if mode=='template':raw='${field}'
    if mode=='unknown':raw=UNKNOWN
    action={'IotSiteWise':{'PutAssetPropertyValueEntries':[{'PropertyValues':[{'Quality':raw}]}]}} if kind=='quality' else {'Republish':{'Headers':{'PayloadFormatIndicator':raw}}} if kind=='format' else {'CloudwatchAlarm':{'StateValue':raw}}
    r=target('main','AWS::IoT::TopicRule',TopicRulePayload={'ErrorAction':action} if error else {'Actions':[action]})
    result=iot_values_checks(linked_design(r),r)
    assert len(result)==1 and result[0]['verdict']==('PASS' if mode=='valid' else 'FAIL' if mode=='invalid' else 'NEEDS_REVIEW')


def test_unknown_actions_deduplicated():
    r=target('main','AWS::IoT::TopicRule',TopicRulePayload={'Actions':UNKNOWN})
    result=iot_values_checks(linked_design(r),r)
    assert len(result)==1 and result[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('mode',['same','region','account','name','missing','conditional','unknown','other_destination','omitted_destination'])
def test_logs(mode):
    config={'S3BucketName':UNKNOWN if mode=='unknown' else 'my-bucket'}
    if mode!='omitted_destination':config['LogDestination']='CLOUDWATCH' if mode=='other_destination' else 'S3'
    r=target('main','AWS::GameLift::ContainerFleet',LogConfiguration=config)
    b=target('bucket','AWS::S3::Bucket',BucketName='other-bucket' if mode=='name' else 'my-bucket')
    if mode=='region':b.scope.region='us-east-1'
    if mode=='account':b.scope.account='222222222222'
    d=linked_design(r,[b],[] if mode=='missing' else [('LogConfiguration/S3BucketName','bucket')])
    if mode=='conditional':d.relations[0].condition='Maybe'
    assert iot_values_checks(d,r)[0]['verdict']==('PASS' if mode in ('same','account') else 'FAIL' if mode=='region' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('kind',['AWS::IoT::JobTemplate','AWS::IoT::TopicRule','AWS::GameLift::ContainerFleet'])
def test_omitted(kind):
    r=target('main',kind)
    assert not iot_values_checks(linked_design(r),r)


def test_checker_action_value():
    r=target('main','AWS::IoT::TopicRule',TopicRulePayload={'Actions':[{'CloudwatchAlarm':{'StateValue':'invalid'}}]})
    root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='IOT_TOPIC_ACTION_LITERAL_VALUES' and f['verdict']=='FAIL' for f in results)
