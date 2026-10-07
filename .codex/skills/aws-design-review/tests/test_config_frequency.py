import pytest
from aws_design_sheet.checks.config.frequency import evaluate_config_frequency
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('owner',['AWS','CUSTOM_POLICY','CUSTOM_LAMBDA',UNKNOWN,'future'])
@pytest.mark.parametrize('messages',[None,[],['ConfigurationSnapshotDeliveryCompleted'],['ScheduledNotification'],['ConfigurationItemChangeNotification','OversizedConfigurationItemChangeNotification'],[UNKNOWN],['ConfigurationSnapshotDeliveryCompleted',UNKNOWN],['future']])
def test_frequency(owner,messages):
    source={'Owner':owner}
    if messages is not None:source['SourceDetails']=[{'MessageType':m} for m in messages]
    r=target('main','AWS::Config::ConfigRule',Source=source,MaximumExecutionFrequency='One_Hour')
    expected='NEEDS_REVIEW'
    if owner=='CUSTOM_POLICY':expected='FAIL'
    elif owner=='CUSTOM_LAMBDA' and messages:
        if 'ConfigurationSnapshotDeliveryCompleted' in messages:expected='PASS'
        elif messages[0] in ('ScheduledNotification','ConfigurationItemChangeNotification'):expected='FAIL'
    assert evaluate_config_frequency(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('frequency',[None,UNKNOWN])
def test_absent_unknown_frequency(frequency):
    props={'Source':{'Owner':'CUSTOM_POLICY'}}
    if frequency is not None:props['MaximumExecutionFrequency']=frequency
    r=target('main','AWS::Config::ConfigRule',**props)
    assert evaluate_config_frequency(linked_design(r),r)[0]['verdict']==('NOT_APPLICABLE' if frequency is None else 'NEEDS_REVIEW')
