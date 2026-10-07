import pytest
from aws_design_sheet.checks.batch.job_definition_values import evaluate_batch_job_definition_values
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def check(rule,props):
    r=target('job','AWS::Batch::JobDefinition',**props)
    return [f for f in evaluate_batch_job_definition_values(linked_design(r),r) if f['rule_id']==rule]


@pytest.mark.parametrize('style',['legacy','node','task','node_task'])
@pytest.mark.parametrize('role,expected',[(None,'FAIL'),('arn:aws:iam::123456789012:role/job','PASS'),(UNKNOWN,'NEEDS_REVIEW')])
def test_efs_role(style,role,expected):
    container={'Volumes':[{'EfsVolumeConfiguration':{'AuthorizationConfig':{'Iam':'ENABLED'}}}]}
    if role is not None:container['TaskRoleArn' if 'task' in style else 'JobRoleArn']=role
    if style=='legacy':props={'ContainerProperties':container}
    elif style=='node':props={'NodeProperties':{'NodeRangeProperties':[{'Container':container}]}}
    elif style=='task':props={'EcsProperties':{'TaskProperties':[container]}}
    else:props={'NodeProperties':{'NodeRangeProperties':[{'EcsProperties':{'TaskProperties':[container]}}]}}
    assert check('BATCH_EFS_IAM_ROLE',props)[0]['verdict']==expected


@pytest.mark.parametrize('efs,expected',[
    ({'AuthorizationConfig':{'Iam':'ENABLED'},'TransitEncryption':'ENABLED'},'PASS'),
    ({'AuthorizationConfig':{'Iam':'ENABLED'}},'FAIL'),
    ({'AuthorizationConfig':{'AccessPointId':'fsap-id'},'TransitEncryption':'ENABLED','RootDirectory':'/'},'PASS'),
    ({'AuthorizationConfig':{'AccessPointId':'fsap-id'},'TransitEncryption':'ENABLED','RootDirectory':'/other'},'FAIL'),
    ({'AuthorizationConfig':{'AccessPointId':UNKNOWN}},'NEEDS_REVIEW'),
    ({'AuthorizationConfig':{'Iam':'ENABLED'},'TransitEncryption':UNKNOWN},'NEEDS_REVIEW')])
def test_nested_efs(efs,expected):
    assert check('BATCH_NESTED_EFS_DEPENDENCIES',{'EcsProperties':{'TaskProperties':[
        {'Volumes':[{'EfsVolumeConfiguration':efs}]}]}})[0]['verdict']==expected


@pytest.mark.parametrize('key,raw,expected',[
    ('OnExitCode','123*','PASS'),('OnExitCode','12*3','FAIL'),('OnExitCode','-1','FAIL'),
    ('OnExitCode','1'*512,'PASS'),('OnExitCode','1'*513,'FAIL'),
    ('OnReason','Reason: 12.3\t*','PASS'),('OnReason','Reason/error','FAIL'),
    ('OnStatusReason','Error*','PASS'),('OnStatusReason','*','NEEDS_REVIEW'),
    ('OnReason',UNKNOWN,'NEEDS_REVIEW'),('OnReason','','NEEDS_REVIEW')])
def test_retry_glob(key,raw,expected):
    assert check('BATCH_RETRY_GLOB',{'RetryStrategy':{'EvaluateOnExit':[{key:raw}]}})[0]['verdict']==expected
